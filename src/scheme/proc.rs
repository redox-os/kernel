use crate::{
    arch::paging::{Page, RmmA, RmmArch, VirtualAddress},
    context::{
        self,
        file::FileDescriptor,
        memory::{handle_notify_files, Grant, PageSpan, AddrSpaceWrapper},
        Context, ContextId, Status, context::{HardBlockedReason, Altstack, SignalHandler},
    },
    memory::PAGE_SIZE,
    ptrace,
    scheme::{self, FileHandle, KernelScheme},
    syscall::{
        self,
        data::{GrantDesc, Map, PtraceEvent, SigAction, SetSighandlerData, Stat},
        error::*,
        flag::*,
        usercopy::{UserSliceRo, UserSliceWo},
        EnvRegisters, FloatRegisters, IntRegisters,
    },
};

use alloc::{
    boxed::Box,
    collections::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::{
    mem,
    num::NonZeroUsize,
    slice, str,
    sync::atomic::{AtomicUsize, Ordering},
};
use spin::RwLock;
use spinning_top::RwSpinlock;

use super::{CallerCtx, GlobalSchemes, KernelSchemes, OpenResult};

fn read_from(dst: UserSliceWo, src: &[u8], offset: &mut usize) -> Result<usize> {
    let avail_src = src.get(*offset..).unwrap_or(&[]);
    let bytes_copied = dst.copy_common_bytes_from_slice(avail_src)?;
    *offset = offset
        .checked_add(bytes_copied)
        .ok_or(Error::new(EOVERFLOW))?;
    Ok(bytes_copied)
}

fn with_context<F, T>(pid: ContextId, callback: F) -> Result<T>
where
    F: FnOnce(&Context) -> Result<T>,
{
    let contexts = context::contexts();
    let context = contexts.get(pid).ok_or(Error::new(ESRCH))?;
    let context = context.read();
    if let Status::Exited(_) = context.status {
        return Err(Error::new(ESRCH));
    }
    callback(&context)
}
fn with_context_mut<F, T>(pid: ContextId, callback: F) -> Result<T>
where
    F: FnOnce(&mut Context) -> Result<T>,
{
    let contexts = context::contexts();
    let context = contexts.get(pid).ok_or(Error::new(ESRCH))?;
    let mut context = context.write();
    if let Status::Exited(_) = context.status {
        return Err(Error::new(ESRCH));
    }
    callback(&mut context)
}
fn try_stop_context<F, T>(pid: ContextId, callback: F) -> Result<T>
where
    F: FnOnce(&mut Context) -> Result<T>,
{
    if pid == context::context_id() {
        return Err(Error::new(EBADF));
    }
    // Stop process
    let (was_stopped, mut running) = with_context_mut(pid, |context| {
        let was_stopped = context.ptrace_stop;
        context.ptrace_stop = true;

        Ok((was_stopped, context.running))
    })?;

    // Wait until stopped
    while running {
        context::switch();

        running = with_context(pid, |context| Ok(context.running))?;
    }

    with_context_mut(pid, |context| {
        assert!(
            !context.running,
            "process can't have been restarted, we stopped it!"
        );

        let ret = callback(context);

        context.ptrace_stop = was_stopped;

        ret
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RegsKind {
    Float,
    Int,
    Env,
}
#[derive(Clone)]
enum Operation {
    Regs(RegsKind),
    Trace,
    Static(&'static str),
    Name,
    SessionId,
    Sighandler,
    Start,
    Attr(Attr),
    Filetable {
        filetable: Arc<RwLock<Vec<Option<FileDescriptor>>>>,
    },
    AddrSpace {
        addrspace: Arc<AddrSpaceWrapper>,
    },
    CurrentAddrSpace,

    // "operations CAN change". The reason we split changing the address space into two handle
    // types, is that we would rather want the actual switch to occur when closing, as opposed to
    // when writing. This is so that we can actually guarantee that no file descriptors are leaked.
    AwaitingAddrSpaceChange {
        new: Arc<AddrSpaceWrapper>,
        new_sp: usize,
        new_ip: usize,
    },

    CurrentFiletable,

    AwaitingFiletableChange(Arc<RwLock<Vec<Option<FileDescriptor>>>>),

    // TODO: Remove this once openat is implemented, or allow openat-via-dup via e.g. the top-level
    // directory.
    OpenViaDup,

    SchedAffinity,
    Sigactions(Arc<RwLock<Vec<(SigAction, usize)>>>),
    Sigprocmask,

    // TODO: REMOVE
    Sigignmask,

    CurrentSigactions,
    AwaitingSigactionsChange(Arc<RwLock<Vec<(SigAction, usize)>>>),

    MmapMinAddr(Arc<AddrSpaceWrapper>),
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Attr {
    Uid,
    Gid,
    // TODO: namespace, tid, etc.
}
impl Operation {
    fn needs_child_process(&self) -> bool {
        matches!(
            self,
            Self::Regs(_)
                | Self::Trace
                | Self::SessionId
                | Self::Filetable { .. }
                | Self::AddrSpace { .. }
                | Self::CurrentAddrSpace
                | Self::CurrentFiletable
                | Self::Sigactions(_)
                | Self::CurrentSigactions
                | Self::AwaitingSigactionsChange(_)
                | Self::Sighandler
                | Self::Sigprocmask
                | Self::Sigignmask
        )
    }
    fn needs_root(&self) -> bool {
        matches!(self, Self::Attr(_))
    }
}
#[derive(Default)]
struct TraceData {
    clones: Vec<ContextId>,
}
struct StaticData {
    buf: Box<[u8]>,
    offset: usize,
}
impl StaticData {
    fn new(buf: Box<[u8]>) -> Self {
        Self { buf, offset: 0 }
    }
}
enum OperationData {
    Trace(TraceData),
    Static(StaticData),
    Offset(usize),
    Other,
}
impl OperationData {
    fn trace_data(&mut self) -> Option<&mut TraceData> {
        match self {
            OperationData::Trace(data) => Some(data),
            _ => None,
        }
    }
    fn static_data(&mut self) -> Option<&mut StaticData> {
        match self {
            OperationData::Static(data) => Some(data),
            _ => None,
        }
    }
}

#[derive(Clone)]
struct Info {
    pid: ContextId,
    flags: usize,

    // Important: Operation must never change. Search for:
    //
    // "operations can't change" to see usages.
    operation: Operation,
}
struct Handle {
    info: Info,
    data: OperationData,
}
impl Handle {
    fn continue_ignored_children(&mut self) -> Option<()> {
        let data = self.data.trace_data()?;
        let contexts = context::contexts();

        for pid in data.clones.drain(..) {
            if ptrace::is_traced(pid) {
                continue;
            }
            if let Some(context) = contexts.get(pid) {
                let mut context = context.write();
                context.ptrace_stop = false;
            }
        }
        Some(())
    }
}

pub struct ProcScheme<const FULL: bool>;

static NEXT_ID: AtomicUsize = AtomicUsize::new(1);
// Using BTreeMap as hashbrown doesn't have a const constructor.
static HANDLES: RwLock<BTreeMap<usize, Handle>> = RwLock::new(BTreeMap::new());

fn new_handle(handle: Handle) -> Result<usize> {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let _ = HANDLES.write().insert(id, handle);
    Ok(id)
}

fn get_context(id: ContextId) -> Result<Arc<RwSpinlock<Context>>> {
    context::contexts()
        .get(id)
        .ok_or(Error::new(ENOENT))
        .map(Arc::clone)
}

impl<const FULL: bool> ProcScheme<FULL> {
    fn open_inner(
        &self,
        pid: ContextId,
        operation_str: Option<&str>,
        flags: usize,
        uid: u32,
        gid: u32,
    ) -> Result<usize> {
        let operation = match operation_str {
            Some("addrspace") => Operation::AddrSpace {
                addrspace: Arc::clone(
                    get_context(pid)?
                        .read()
                        .addr_space()
                        .map_err(|_| Error::new(ENOENT))?,
                ),
            },
            Some("filetable") => Operation::Filetable {
                filetable: Arc::clone(&get_context(pid)?.read().files),
            },
            Some("current-addrspace") => Operation::CurrentAddrSpace,
            Some("current-filetable") => Operation::CurrentFiletable,
            Some("regs/float") => Operation::Regs(RegsKind::Float),
            Some("regs/int") => Operation::Regs(RegsKind::Int),
            Some("regs/env") => Operation::Regs(RegsKind::Env),
            Some("trace") => Operation::Trace,
            Some("exe") => Operation::Static("exe"),
            Some("name") => Operation::Name,
            Some("session_id") => Operation::SessionId,
            Some("sighandler") => Operation::Sighandler,
            Some("sigprocmask") => Operation::Sigprocmask,
            Some("sigignmask") => Operation::Sigignmask,
            Some("start") => Operation::Start,
            Some("uid") => Operation::Attr(Attr::Uid),
            Some("gid") => Operation::Attr(Attr::Gid),
            Some("open_via_dup") => Operation::OpenViaDup,
            Some("sigactions") => {
                Operation::Sigactions(Arc::clone(&get_context(pid)?.read().actions))
            }
            Some("current-sigactions") => Operation::CurrentSigactions,
            Some("mmap-min-addr") => Operation::MmapMinAddr(Arc::clone(
                get_context(pid)?
                    .read()
                    .addr_space()
                    .map_err(|_| Error::new(ENOENT))?,
            )),
            Some("sched-affinity") => Operation::SchedAffinity,
            _ => return Err(Error::new(EINVAL)),
        };

        let contexts = context::contexts();
        let target = contexts.get(pid).ok_or(Error::new(ESRCH))?;

        let mut data;

        {
            let target = target.read();

            data = match operation {
                Operation::Trace => OperationData::Trace(TraceData::default()),
                Operation::Static(_) => OperationData::Static(StaticData::new(
                    target.name.clone().into_owned().into_bytes().into(),
                )),
                Operation::AddrSpace { .. } => OperationData::Offset(0),
                _ => OperationData::Other,
            };

            if let Status::Exited(_) = target.status {
                return Err(Error::new(ESRCH));
            }

            // Unless root, check security
            if operation.needs_child_process() && uid != 0 && gid != 0 {
                let current = contexts.current().ok_or(Error::new(ESRCH))?;
                let current = current.read();

                // Are we the process?
                if target.id != current.id {
                    // Do we own the process?
                    if uid != target.euid && gid != target.egid {
                        return Err(Error::new(EPERM));
                    }

                    // Is it a subprocess of us? In the future, a capability could
                    // bypass this check.
                    match contexts
                        .ancestors(target.ppid)
                        .find(|&(id, _context)| id == current.id)
                    {
                        Some((id, context)) => {
                            // Paranoid sanity check, as ptrace security holes
                            // wouldn't be fun
                            assert_eq!(id, current.id);
                            assert_eq!(id, context.read().id);
                        }
                        None => return Err(Error::new(EPERM)),
                    }
                }
            } else if operation.needs_root() && (uid != 0 || gid != 0) {
                return Err(Error::new(EPERM));
            }

            if matches!(operation, Operation::Filetable { .. }) {
                data = OperationData::Static(StaticData::new({
                    use core::fmt::Write;

                    let mut data = String::new();
                    for index in target
                        .files
                        .read()
                        .iter()
                        .enumerate()
                        .filter_map(|(idx, val)| val.as_ref().map(|_| idx))
                    {
                        writeln!(data, "{}", index).unwrap();
                    }
                    data.into_bytes().into_boxed_slice()
                }));
            }
        };

        let id = new_handle(Handle {
            info: Info {
                flags,
                pid,
                operation: operation.clone(),
            },
            data,
        })?;

        if let Operation::Trace = operation {
            if !ptrace::try_new_session(pid, id) {
                // There is no good way to handle id being occupied for nothing
                // here, is there?
                return Err(Error::new(EBUSY));
            }

            if flags & O_TRUNC == O_TRUNC {
                let mut target = target.write();
                target.ptrace_stop = true;
            }
        }

        Ok(id)
    }

    #[cfg(target_arch = "aarch64")]
    fn read_env_regs(&self, info: &Info) -> Result<EnvRegisters> {
        use crate::device::cpu::registers::control_regs;

        let (tpidr_el0, tpidrro_el0) = if info.pid == context::context_id() {
            unsafe {
                (
                    control_regs::tpidr_el0() as usize,
                    control_regs::tpidrro_el0() as usize,
                )
            }
        } else {
            try_stop_context(info.pid, |context| {
                Ok((context.arch.tpidr_el0, context.arch.tpidrro_el0))
            })?
        };
        Ok(EnvRegisters {
            tpidr_el0,
            tpidrro_el0,
        })
    }

    #[cfg(target_arch = "x86")]
    fn read_env_regs(&self, info: &Info) -> Result<EnvRegisters> {
        let (fsbase, gsbase) = if info.pid == context::context_id() {
            unsafe {
                (
                    (&*crate::gdt::pcr()).gdt[crate::gdt::GDT_USER_FS].offset() as u64,
                    (&*crate::gdt::pcr()).gdt[crate::gdt::GDT_USER_GS].offset() as u64,
                )
            }
        } else {
            try_stop_context(info.pid, |context| {
                Ok((context.arch.fsbase as u64, context.arch.gsbase as u64))
            })?
        };
        Ok(EnvRegisters {
            fsbase: fsbase as _,
            gsbase: gsbase as _,
        })
    }

    #[cfg(target_arch = "x86_64")]
    fn read_env_regs(&self, info: &Info) -> Result<EnvRegisters> {
        // TODO: Avoid rdmsr if fsgsbase is not enabled, if this is worth optimizing for.
        let (fsbase, gsbase) = if info.pid == context::context_id() {
            unsafe {
                (
                    x86::msr::rdmsr(x86::msr::IA32_FS_BASE),
                    x86::msr::rdmsr(x86::msr::IA32_KERNEL_GSBASE),
                )
            }
        } else {
            try_stop_context(info.pid, |context| {
                Ok((context.arch.fsbase as u64, context.arch.gsbase as u64))
            })?
        };
        Ok(EnvRegisters {
            fsbase: fsbase as _,
            gsbase: gsbase as _,
        })
    }

    #[cfg(target_arch = "aarch64")]
    fn write_env_regs(&self, info: &Info, regs: EnvRegisters) -> Result<()> {
        use crate::device::cpu::registers::control_regs;

        if info.pid == context::context_id() {
            unsafe {
                control_regs::tpidr_el0_write(regs.tpidr_el0 as u64);
                control_regs::tpidrro_el0_write(regs.tpidrro_el0 as u64);
            }
        } else {
            try_stop_context(info.pid, |context| {
                context.arch.tpidr_el0 = regs.tpidr_el0;
                context.arch.tpidrro_el0 = regs.tpidrro_el0;
                Ok(())
            })?;
        }
        Ok(())
    }

    #[cfg(target_arch = "x86")]
    fn write_env_regs(&self, info: &Info, regs: EnvRegisters) -> Result<()> {
        if !(RmmA::virt_is_valid(VirtualAddress::new(regs.fsbase as usize))
            && RmmA::virt_is_valid(VirtualAddress::new(regs.gsbase as usize)))
        {
            return Err(Error::new(EINVAL));
        }

        if info.pid == context::context_id() {
            unsafe {
                (&mut *crate::gdt::pcr()).gdt[crate::gdt::GDT_USER_FS].set_offset(regs.fsbase);
                (&mut *crate::gdt::pcr()).gdt[crate::gdt::GDT_USER_GS].set_offset(regs.gsbase);

                match context::contexts()
                    .current()
                    .ok_or(Error::new(ESRCH))?
                    .write()
                    .arch
                {
                    ref mut arch => {
                        arch.fsbase = regs.fsbase as usize;
                        arch.gsbase = regs.gsbase as usize;
                    }
                }
            }
        } else {
            try_stop_context(info.pid, |context| {
                context.arch.fsbase = regs.fsbase as usize;
                context.arch.gsbase = regs.gsbase as usize;
                Ok(())
            })?;
        }
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn write_env_regs(&self, info: &Info, regs: EnvRegisters) -> Result<()> {
        if !(RmmA::virt_is_valid(VirtualAddress::new(regs.fsbase as usize))
            && RmmA::virt_is_valid(VirtualAddress::new(regs.gsbase as usize)))
        {
            return Err(Error::new(EINVAL));
        }

        if info.pid == context::context_id() {
            unsafe {
                x86::msr::wrmsr(x86::msr::IA32_FS_BASE, regs.fsbase as u64);
                // We have to write to KERNEL_GSBASE, because when the kernel returns to
                // userspace, it will have executed SWAPGS first.
                x86::msr::wrmsr(x86::msr::IA32_KERNEL_GSBASE, regs.gsbase as u64);

                match context::contexts()
                    .current()
                    .ok_or(Error::new(ESRCH))?
                    .write()
                    .arch
                {
                    ref mut arch => {
                        arch.fsbase = regs.fsbase as usize;
                        arch.gsbase = regs.gsbase as usize;
                    }
                }
            }
        } else {
            try_stop_context(info.pid, |context| {
                context.arch.fsbase = regs.fsbase as usize;
                context.arch.gsbase = regs.gsbase as usize;
                Ok(())
            })?;
        }
        Ok(())
    }
}

impl<const FULL: bool> KernelScheme for ProcScheme<FULL> {
    fn kopen(&self, path: &str, flags: usize, ctx: CallerCtx) -> Result<OpenResult> {
        let mut parts = path.splitn(2, '/');
        let pid_str = parts.next().ok_or(Error::new(ENOENT))?;

        let pid = if pid_str == "current" {
            context::context_id()
        } else if pid_str == "new" {
            inherit_context()?
        } else if !FULL {
            return Err(Error::new(EACCES));
        } else {
            ContextId::new(pid_str.parse().map_err(|_| Error::new(ENOENT))?)
        };

        self.open_inner(pid, parts.next(), flags, ctx.uid, ctx.gid)
            .map(OpenResult::SchemeLocal)
    }

    fn fcntl(&self, id: usize, cmd: usize, arg: usize) -> Result<usize> {
        let mut handles = HANDLES.write();
        let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;

        match cmd {
            F_SETFL => {
                handle.info.flags = arg;
                Ok(0)
            }
            F_GETFL => Ok(handle.info.flags),
            _ => Err(Error::new(EINVAL)),
        }
    }

    fn fevent(&self, id: usize, _flags: EventFlags) -> Result<EventFlags> {
        let handles = HANDLES.read();
        let handle = handles.get(&id).ok_or(Error::new(EBADF))?;

        match handle.info.operation {
            Operation::Trace => ptrace::Session::with_session(handle.info.pid, |session| {
                Ok(session.data.lock().session_fevent_flags())
            }),
            _ => Ok(EventFlags::empty()),
        }
    }

    fn close(&self, id: usize) -> Result<()> {
        let mut handle = HANDLES.write().remove(&id).ok_or(Error::new(EBADF))?;
        handle.continue_ignored_children();

        let stop_context = if handle.info.pid == context::context_id() {
            with_context_mut
        } else {
            try_stop_context
        };

        match handle.info.operation {
            Operation::AwaitingAddrSpaceChange { new, new_sp, new_ip } => {
                let _ = stop_context(handle.info.pid, |context: &mut Context| {
                    let regs = context.regs_mut().ok_or(Error::new(EBADFD))?;
                    regs.set_instr_pointer(new_ip);
                    regs.set_stack_pointer(new_sp);

                    Ok(context.set_addr_space(Some(new)))
                })?;
                let _ = ptrace::send_event(crate::syscall::ptrace_event!(
                    PTRACE_EVENT_ADDRSPACE_SWITCH,
                    0
                ));
            }
            Operation::AddrSpace { addrspace } | Operation::MmapMinAddr(addrspace) => {
                drop(addrspace)
            }

            Operation::AwaitingFiletableChange(new) => {
                with_context_mut(handle.info.pid, |context: &mut Context| {
                    context.files = new;
                    Ok(())
                })?
            }
            Operation::AwaitingSigactionsChange(new) => {
                with_context_mut(handle.info.pid, |context: &mut Context| {
                    context.actions = new;
                    Ok(())
                })?
            }
            Operation::Trace => {
                ptrace::close_session(handle.info.pid);

                if handle.info.flags & O_EXCL == O_EXCL {
                    syscall::kill(handle.info.pid, SIGKILL)?;
                }

                let contexts = context::contexts();
                if let Some(context) = contexts.get(handle.info.pid) {
                    let mut context = context.write();
                    context.ptrace_stop = false;
                }
            }
            _ => (),
        }
        Ok(())
    }
    fn kfmap(
        &self,
        id: usize,
        dst_addr_space: &Arc<AddrSpaceWrapper>,
        map: &crate::syscall::data::Map,
        consume: bool,
    ) -> Result<usize> {
        let info = HANDLES
            .read()
            .get(&id)
            .ok_or(Error::new(EBADF))?
            .info
            .clone();

        match info.operation {
            Operation::AddrSpace { ref addrspace } => {
                if Arc::ptr_eq(addrspace, dst_addr_space) {
                    return Err(Error::new(EBUSY));
                }

                let (requested_dst_page, _) =
                    crate::syscall::validate_region(map.address, map.size)?;
                let src_span =
                    PageSpan::validate_nonempty(VirtualAddress::new(map.offset), map.size)
                        .ok_or(Error::new(EINVAL))?;

                let requested_dst_base = (map.address != 0).then_some(requested_dst_page);

                let mut src_addr_space = addrspace.acquire_write();

                let src_page_count = NonZeroUsize::new(src_span.count).ok_or(Error::new(EINVAL))?;

                let mut notify_files = Vec::new();

                // TODO: Validate flags
                let result_base = if consume {
                    dst_addr_space.r#move(
                        Some((&addrspace, &mut *src_addr_space)),
                        src_span,
                        requested_dst_base,
                        src_page_count.get(),
                        map.flags,
                        &mut notify_files,
                    )?
                } else {
                    let mut dst_addrsp_guard = dst_addr_space.acquire_write();
                    dst_addrsp_guard.mmap(
                        &dst_addr_space,
                        requested_dst_base,
                        src_page_count,
                        map.flags,
                        &mut notify_files,
                        |dst_page, _, dst_mapper, flusher| {
                            Ok(Grant::borrow(
                                Arc::clone(addrspace),
                                &mut *src_addr_space,
                                src_span.base,
                                dst_page,
                                src_span.count,
                                map.flags,
                                dst_mapper,
                                flusher,
                                true,
                                true,
                                false,
                            )?)
                        },
                    )?
                };

                handle_notify_files(notify_files);

                Ok(result_base.start_address().data())
            }
            _ => Err(Error::new(EBADF)),
        }
    }
    fn kread(&self, id: usize, buf: UserSliceWo) -> Result<usize> {
        // Don't hold a global lock during the context switch later on
        let info = {
            let handles = HANDLES.read();
            let handle = handles.get(&id).ok_or(Error::new(EBADF))?;
            handle.info.clone()
        };

        match info.operation {
            Operation::Static(_) => {
                let mut handles = HANDLES.write();
                let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;
                let data = handle.data.static_data().expect("operations can't change");
                let src_buf = data.buf.get(data.offset..).unwrap_or(&[]);

                let len = buf.copy_common_bytes_from_slice(src_buf)?;
                data.offset += len;
                Ok(len)
            }
            Operation::Regs(kind) => {
                union Output {
                    float: FloatRegisters,
                    int: IntRegisters,
                    env: EnvRegisters,
                }

                let (output, size) = match kind {
                    RegsKind::Float => with_context(info.pid, |context| {
                        // NOTE: The kernel will never touch floats

                        Ok((
                            Output {
                                float: context.get_fx_regs(),
                            },
                            mem::size_of::<FloatRegisters>(),
                        ))
                    })?,
                    RegsKind::Int => try_stop_context(info.pid, |context| match context.regs() {
                        None => {
                            assert!(!context.running, "try_stop_context is broken, clearly");
                            println!("{}:{}: Couldn't read registers from stopped process", file!(), line!());
                            Err(Error::new(ENOTRECOVERABLE))
                        },
                        Some(stack) => {
                            let mut regs = IntRegisters::default();
                            stack.save(&mut regs);
                            Ok((Output { int: regs }, mem::size_of::<IntRegisters>()))
                        }
                    })?,
                    RegsKind::Env => (
                        Output {
                            env: self.read_env_regs(&info)?,
                        },
                        mem::size_of::<EnvRegisters>(),
                    ),
                };

                let src_buf =
                    unsafe { slice::from_raw_parts(&output as *const _ as *const u8, size) };

                buf.copy_common_bytes_from_slice(src_buf)
            }
            Operation::Trace => {
                let mut handles = HANDLES.write();
                let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;
                let data = handle.data.trace_data().expect("operations can't change");

                // Wait for event
                if handle.info.flags & O_NONBLOCK != O_NONBLOCK {
                    ptrace::wait(handle.info.pid)?;
                }

                // Check if context exists
                with_context(handle.info.pid, |_| Ok(()))?;

                let mut src_buf = [PtraceEvent::default(); 4];

                // Read events
                let src_len = src_buf.len();
                let slice = &mut src_buf
                    [..core::cmp::min(src_len, buf.len() / mem::size_of::<PtraceEvent>())];

                let (read, reached) = ptrace::Session::with_session(info.pid, |session| {
                    let mut data = session.data.lock();
                    Ok((data.recv_events(slice), data.is_reached()))
                })?;

                // Save child processes in a list of processes to restart
                for event in &slice[..read] {
                    if event.cause == PTRACE_EVENT_CLONE {
                        data.clones.push(ContextId::from(event.a));
                    }
                }

                // If there are no events, and breakpoint isn't reached, we
                // must not have waited.
                if read == 0 && !reached {
                    assert!(
                        handle.info.flags & O_NONBLOCK == O_NONBLOCK,
                        "wait woke up spuriously??"
                    );
                    return Err(Error::new(EAGAIN));
                }

                for (dst, src) in buf
                    .in_exact_chunks(mem::size_of::<PtraceEvent>())
                    .zip(slice.iter())
                {
                    dst.copy_exactly(src)?;
                }

                // Return read events
                Ok(read * mem::size_of::<PtraceEvent>())
            }
            Operation::AddrSpace { ref addrspace } => {
                let OperationData::Offset(orig_offset) =
                    HANDLES.read().get(&id).ok_or(Error::new(EBADF))?.data
                else {
                    return Err(Error::new(EBADFD));
                };

                // Output a list of grant descriptors, sufficient to allow relibc's fork()
                // implementation to fmap MAP_SHARED grants.
                let mut grants_read = 0;

                let mut dst = [GrantDesc::default(); 16];

                for (dst, (grant_base, grant_info)) in dst
                    .iter_mut()
                    .zip(addrspace.acquire_read().grants.iter().skip(orig_offset))
                {
                    *dst = GrantDesc {
                        base: grant_base.start_address().data(),
                        size: grant_info.page_count() * PAGE_SIZE,
                        flags: grant_info.grant_flags(),
                        // The !0 is not a sentinel value; the availability of `offset` is
                        // indicated by the GRANT_SCHEME flag.
                        offset: grant_info.file_ref().map_or(!0, |f| f.base_offset as u64),
                    };
                    grants_read += 1;
                }
                for (src, chunk) in dst
                    .iter()
                    .take(grants_read)
                    .zip(buf.in_exact_chunks(mem::size_of::<GrantDesc>()))
                {
                    chunk.copy_exactly(src)?;
                }

                match HANDLES.write().get_mut(&id).ok_or(Error::new(EBADF))?.data {
                    OperationData::Offset(ref mut offset) => *offset += grants_read,
                    _ => return Err(Error::new(EBADFD)),
                };

                Ok(grants_read * mem::size_of::<GrantDesc>())
            }
            Operation::Name => read_from(
                buf,
                context::contexts()
                    .get(info.pid)
                    .ok_or(Error::new(ESRCH))?
                    .read()
                    .name
                    .as_bytes(),
                &mut 0,
            ),
            Operation::SessionId => read_from(
                buf,
                &context::contexts()
                    .get(info.pid)
                    .ok_or(Error::new(ESRCH))?
                    .read()
                    .session_id
                    .get()
                    .to_ne_bytes(),
                &mut 0,
            ),

            Operation::Sighandler => {
                let handler = context::contexts().get(info.pid).ok_or(Error::new(ESRCH))?.read().sig.handler;
                let altstack = handler.and_then(|h| h.altstack);
                let data = SetSighandlerData {
                    entry: handler.map_or(0, |h| h.handler.get()),
                    altstack_base: altstack.map_or(0, |a| a.base.get()),
                    altstack_len: altstack.map_or(0, |a| a.len.get()),
                };
                buf.copy_exactly(&data)?;

                Ok(mem::size_of::<SetSighandlerData>())
            }
            Operation::Sigprocmask => {
                let procmask = context::contexts().get(info.pid).ok_or(Error::new(ESRCH))?.read().sig.procmask;
                buf.write_u64(procmask)?;
                Ok(8)
            }
            Operation::Sigignmask => {
                let mut ignmask = 0_u64;

                {
                    let contexts = context::contexts();
                    let context = contexts.get(info.pid).ok_or(Error::new(ESRCH))?;
                    let context = context.read();
                    let actions = context.actions.read();
                    for (idx, (action, _)) in actions.iter().enumerate() {
                        if action.sa_handler == unsafe { core::mem::transmute(SIG_IGN) } {
                            ignmask |= 1 << idx;
                        }
                    }
                }
                buf.write_u64(ignmask)?;
                Ok(8)
            }
            Operation::Attr(attr) => {
                let src_buf = match (
                    attr,
                    &*Arc::clone(context::contexts().get(info.pid).ok_or(Error::new(ESRCH))?)
                        .read(),
                ) {
                    (Attr::Uid, context) => context.euid.to_string(),
                    (Attr::Gid, context) => context.egid.to_string(),
                }
                .into_bytes();

                read_from(buf, &src_buf, &mut 0)
            }
            Operation::Filetable { .. } => {
                let mut handles = HANDLES.write();
                let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;
                let data = handle.data.static_data().expect("operations can't change");

                read_from(buf, &data.buf, &mut data.offset)
            }
            Operation::MmapMinAddr(ref addrspace) => {
                buf.write_usize(addrspace.acquire_read().mmap_min)?;
                Ok(mem::size_of::<usize>())
            }
            Operation::SchedAffinity => {
                let mask = context::contexts()
                    .get(info.pid)
                    .ok_or(Error::new(EBADFD))?
                    .read()
                    .sched_affinity
                    .to_raw();

                buf.copy_exactly(crate::cpu_set::mask_as_bytes(&mask))?;
                Ok(mem::size_of_val(&mask))
            }
            // TODO: Replace write() with SYS_DUP_FORWARD.
            // TODO: Find a better way to switch address spaces, since they also require switching
            // the instruction and stack pointer. Maybe remove `<pid>/regs` altogether and replace it
            // with `<pid>/ctx`
            _ => Err(Error::new(EBADF)),
        }
    }
    fn kwrite(&self, id: usize, buf: UserSliceRo) -> Result<usize> {
        // Don't hold a global lock during the context switch later on
        let info = {
            let mut handles = HANDLES.write();
            let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;
            handle.continue_ignored_children();
            handle.info.clone()
        };

        match info.operation {
            Operation::Static(_) => Err(Error::new(EBADF)),
            Operation::AddrSpace { addrspace } => {
                let mut chunks = buf.usizes();
                let mut words_read = 0;
                let mut next = || {
                    words_read += 1;
                    chunks.next().ok_or(Error::new(EINVAL))
                };

                match next()?? {
                    op @ ADDRSPACE_OP_MMAP | op @ ADDRSPACE_OP_TRANSFER => {
                        let fd = next()??;
                        let offset = next()??;
                        let (page, page_count) =
                            crate::syscall::validate_region(next()??, next()??)?;
                        let flags = MapFlags::from_bits(next()??).ok_or(Error::new(EINVAL))?;

                        if !flags.contains(MapFlags::MAP_FIXED) {
                            return Err(Error::new(EOPNOTSUPP));
                        }

                        let (scheme, number) = extract_scheme_number(fd)?;

                        scheme.kfmap(
                            number,
                            &addrspace,
                            &Map {
                                offset,
                                size: page_count * PAGE_SIZE,
                                address: page.start_address().data(),
                                flags,
                            },
                            op == ADDRSPACE_OP_TRANSFER,
                        )?;
                    }
                    ADDRSPACE_OP_MUNMAP => {
                        let (page, page_count) =
                            crate::syscall::validate_region(next()??, next()??)?;

                        let unpin = false;
                        addrspace.munmap(PageSpan::new(page, page_count), unpin)?;
                    }
                    ADDRSPACE_OP_MPROTECT => {
                        let (page, page_count) =
                            crate::syscall::validate_region(next()??, next()??)?;
                        let flags = MapFlags::from_bits(next()??).ok_or(Error::new(EINVAL))?;

                        addrspace.mprotect(PageSpan::new(page, page_count), flags)?;
                    }
                    _ => return Err(Error::new(EINVAL)),
                }
                Ok(words_read * mem::size_of::<usize>())
            }
            Operation::Regs(kind) => match kind {
                RegsKind::Float => {
                    let regs = unsafe { buf.read_exact::<FloatRegisters>()? };

                    with_context_mut(info.pid, |context| {
                        // NOTE: The kernel will never touch floats

                        // Ignore the rare case of floating point
                        // registers being uninitiated
                        let _ = context.set_fx_regs(regs);

                        Ok(mem::size_of::<FloatRegisters>())
                    })
                }
                RegsKind::Int => {
                    let regs = unsafe { buf.read_exact::<IntRegisters>()? };

                    try_stop_context(info.pid, |context| match context.regs_mut() {
                        None => {
                            println!("{}:{}: Couldn't read registers from stopped process", file!(), line!());
                            Err(Error::new(ENOTRECOVERABLE))
                        },
                        Some(stack) => {
                            stack.load(&regs);

                            Ok(mem::size_of::<IntRegisters>())
                        }
                    })
                }
                RegsKind::Env => {
                    let regs = unsafe { buf.read_exact::<EnvRegisters>()? };
                    self.write_env_regs(&info, regs)?;
                    Ok(mem::size_of::<EnvRegisters>())
                }
            },
            Operation::Trace => {
                let op = buf.read_u64()?;
                let op = PtraceFlags::from_bits(op).ok_or(Error::new(EINVAL))?;

                // Set next breakpoint
                ptrace::Session::with_session(info.pid, |session| {
                    session.data.lock().set_breakpoint(
                        Some(op).filter(|op| op.intersects(PTRACE_STOP_MASK | PTRACE_EVENT_MASK)),
                    );
                    Ok(())
                })?;

                if op.contains(PTRACE_STOP_SINGLESTEP) {
                    try_stop_context(info.pid, |context| {
                        match context.regs_mut() {
                            None => {
                                println!(
                                    "{}:{}: Couldn't read registers from stopped process",
                                    file!(),
                                    line!()
                                );
                                Err(Error::new(ENOTRECOVERABLE))
                            }
                            Some(stack) => {
                                stack.set_singlestep(true);
                                Ok(())
                            }
                        }
                    })?;
                }

                // disable the ptrace_stop flag, which is used in some cases
                with_context_mut(info.pid, |context| {
                    context.ptrace_stop = false;
                    Ok(())
                })?;

                // and notify the tracee's WaitCondition, which is used in other cases
                ptrace::Session::with_session(info.pid, |session| {
                    session.tracee.notify();
                    Ok(())
                })?;

                Ok(mem::size_of::<u64>())
            }
            Operation::Name => {
                // TODO: What limit?
                let mut name_buf = [0_u8; 256];
                let bytes_copied = buf.copy_common_bytes_to_slice(&mut name_buf)?;

                let utf8 = alloc::string::String::from_utf8(name_buf[..bytes_copied].to_vec())
                    .map_err(|_| Error::new(EINVAL))?;
                context::contexts()
                    .get(info.pid)
                    .ok_or(Error::new(ESRCH))?
                    .write()
                    .name = utf8.into();
                Ok(buf.len())
            }
            Operation::SessionId => {
                let session_id = ContextId::new(buf.read_usize()?);

                if session_id != info.pid {
                    // Session ID can only be set to this process's ID
                    return Err(Error::new(EPERM));
                }

                for (_id, context_lock) in context::contexts().iter() {
                    if session_id == context_lock.read().pgid {
                        // The session ID cannot match the PGID of any process
                        return Err(Error::new(EPERM));
                    }
                }

                let context_lock =
                    Arc::clone(context::contexts().get(info.pid).ok_or(Error::new(ESRCH))?);
                {
                    let mut context = context_lock.write();
                    context.pgid = session_id;
                    context.session_id = session_id;
                }

                Ok(buf.len())
            }
            Operation::Sighandler => {
                let data = unsafe { buf.read_exact::<SetSighandlerData>()? };

                let new_handler = match NonZeroUsize::new(data.entry) {
                    Some(handler) => Some(SignalHandler {
                        handler,
                        altstack: match (NonZeroUsize::new(data.altstack_base), NonZeroUsize::new(data.altstack_len)) {
                            (Some(base), Some(len)) => Some(Altstack { base, len }),
                            _ => None,
                        }
                    }),
                    None => None,
                };

                context::contexts().get(info.pid).ok_or(Error::new(ESRCH))?.write().sig.handler = new_handler;

                Ok(mem::size_of::<SetSighandlerData>())
            }
            Operation::Sigprocmask => {
                let new_procmask = buf.read_u64()?;
                context::contexts().get(info.pid).ok_or(Error::new(ESRCH))?.write().sig.procmask = new_procmask;
                Ok(8)
            }
            // TODO: Remove!
            Operation::Sigignmask => {
                let new_ignmask = buf.read_u64()?;
                let contexts = context::contexts();
                let context = contexts.get(info.pid).ok_or(Error::new(ESRCH))?;
                let context = context.read();
                let mut actions = context.actions.write();
                for bit in (0..64).filter(|bit| new_ignmask & (1 << bit) != 0) {
                    actions[bit] = (SigAction {
                        sa_flags: SigActionFlags::empty(),
                        sa_mask: 0,
                        sa_handler: unsafe { core::mem::transmute(SIG_IGN) },
                    }, 0);
                }
                Ok(8)
            }
            Operation::Start => match context::contexts().get(info.pid).ok_or(Error::new(ESRCH))?.write().status {
                ref mut status @ Status::HardBlocked { reason: HardBlockedReason::NotYetStarted } => {
                    *status = Status::Runnable;
                    Ok(buf.len())
                }
                _ => return Err(Error::new(EINVAL)),
            }
            Operation::Attr(attr) => {
                // TODO: What limit?
                let mut str_buf = [0_u8; 32];
                let bytes_copied = buf.copy_common_bytes_to_slice(&mut str_buf)?;

                let id = core::str::from_utf8(&str_buf[..bytes_copied])
                    .map_err(|_| Error::new(EINVAL))?
                    .parse::<u32>()
                    .map_err(|_| Error::new(EINVAL))?;
                let context_lock =
                    Arc::clone(context::contexts().get(info.pid).ok_or(Error::new(ESRCH))?);

                match attr {
                    Attr::Uid => context_lock.write().euid = id,
                    Attr::Gid => context_lock.write().egid = id,
                }
                Ok(buf.len())
            }
            Operation::Filetable { .. } => Err(Error::new(EBADF)),

            Operation::CurrentFiletable => {
                let filetable_fd = buf.read_usize()?;
                let (hopefully_this_scheme, number) = extract_scheme_number(filetable_fd)?;
                verify_scheme(hopefully_this_scheme)?;

                let mut handles = HANDLES.write();
                let Operation::Filetable { ref filetable } = handles
                    .get(&number)
                    .ok_or(Error::new(EBADF))?
                    .info
                    .operation
                else {
                    return Err(Error::new(EBADF));
                };

                handles
                    .get_mut(&id)
                    .ok_or(Error::new(EBADF))?
                    .info
                    .operation = Operation::AwaitingFiletableChange(Arc::clone(filetable));

                Ok(mem::size_of::<usize>())
            }
            Operation::CurrentAddrSpace { .. } => {
                let mut iter = buf.usizes();
                let addrspace_fd = iter.next().ok_or(Error::new(EINVAL))??;
                let sp = iter.next().ok_or(Error::new(EINVAL))??;
                let ip = iter.next().ok_or(Error::new(EINVAL))??;

                let (hopefully_this_scheme, number) = extract_scheme_number(addrspace_fd)?;
                verify_scheme(hopefully_this_scheme)?;

                let mut handles = HANDLES.write();
                let Operation::AddrSpace { ref addrspace } = handles
                    .get(&number)
                    .ok_or(Error::new(EBADF))?
                    .info
                    .operation
                else {
                    return Err(Error::new(EBADF));
                };

                handles
                    .get_mut(&id)
                    .ok_or(Error::new(EBADF))?
                    .info
                    .operation = Operation::AwaitingAddrSpaceChange {
                    new: Arc::clone(addrspace),
                    new_sp: sp,
                    new_ip: ip,
                };

                Ok(3 * mem::size_of::<usize>())
            }
            Operation::CurrentSigactions => {
                let sigactions_fd = buf.read_usize()?;
                let (hopefully_this_scheme, number) = extract_scheme_number(sigactions_fd)?;
                verify_scheme(hopefully_this_scheme)?;

                let mut handles = HANDLES.write();
                let Operation::Sigactions(ref sigactions) = handles
                    .get(&number)
                    .ok_or(Error::new(EBADF))?
                    .info
                    .operation
                else {
                    return Err(Error::new(EBADF));
                };

                handles
                    .get_mut(&id)
                    .ok_or(Error::new(EBADF))?
                    .info
                    .operation = Operation::AwaitingSigactionsChange(Arc::clone(sigactions));
                Ok(mem::size_of::<usize>())
            }
            Operation::MmapMinAddr(ref addrspace) => {
                let val = buf.read_usize()?;
                if val % PAGE_SIZE != 0 || val > crate::USER_END_OFFSET {
                    return Err(Error::new(EINVAL));
                }
                addrspace.acquire_write().mmap_min = val;
                Ok(mem::size_of::<usize>())
            }
            Operation::SchedAffinity => {
                let mask = unsafe { buf.read_exact::<crate::cpu_set::RawMask>()? };

                context::contexts()
                    .get(info.pid)
                    .ok_or(Error::new(EBADFD))?
                    .write()
                    .sched_affinity
                    .override_from(&mask);

                Ok(mem::size_of_val(&mask))
            }

            _ => Err(Error::new(EBADF)),
        }
    }
    fn kfpath(&self, id: usize, buf: UserSliceWo) -> Result<usize> {
        let handles = HANDLES.read();
        let handle = handles.get(&id).ok_or(Error::new(EBADF))?;

        let path = format!("proc:{}/{}", handle.info.pid.get(), match handle.info.operation {
            Operation::Regs(RegsKind::Float) => "regs/float",
            Operation::Regs(RegsKind::Int) => "regs/int",
            Operation::Regs(RegsKind::Env) => "regs/env",
            Operation::Trace => "trace",
            Operation::Static(path) => path,
            Operation::Name => "name",
            Operation::Sighandler => "sighandler",
            Operation::Attr(Attr::Uid) => "uid",
            Operation::Attr(Attr::Gid) => "gid",
            Operation::Filetable { .. } => "filetable",
            Operation::AddrSpace { .. } => "addrspace",
            Operation::Sigactions(_) => "sigactions",
            Operation::CurrentAddrSpace => "current-addrspace",
            Operation::CurrentFiletable => "current-filetable",
            Operation::CurrentSigactions => "current-sigactions",
            Operation::OpenViaDup => "open-via-dup",
            Operation::MmapMinAddr(_) => "mmap-min-addr",
            Operation::SchedAffinity => "sched-affinity",

                _ => return Err(Error::new(EOPNOTSUPP)),
            }
        );

        buf.copy_common_bytes_from_slice(path.as_bytes())
    }
    fn kfstat(&self, id: usize, buffer: UserSliceWo) -> Result<()> {
        let handles = HANDLES.read();
        let handle = handles.get(&id).ok_or(Error::new(EBADF))?;

        buffer.copy_exactly(&Stat {
            st_mode: MODE_FILE | 0o666,
            st_size: match handle.data {
                OperationData::Static(ref data) => (data.buf.len() - data.offset) as u64,
                _ => 0,
            },

            ..Stat::default()
        })?;

        Ok(())
    }

    /// Dup is currently used to implement clone() and execve().
    fn kdup(&self, old_id: usize, raw_buf: UserSliceRo, _: CallerCtx) -> Result<OpenResult> {
        let info = {
            let handles = HANDLES.read();
            let handle = handles.get(&old_id).ok_or(Error::new(EBADF))?;

            handle.info.clone()
        };

        let handle = |operation, data| Handle {
            info: Info {
                flags: 0,
                pid: info.pid,
                operation,
            },
            data,
        };
        let mut array = [0_u8; 64];
        if raw_buf.len() > array.len() {
            return Err(Error::new(EINVAL));
        }
        raw_buf.copy_to_slice(&mut array[..raw_buf.len()])?;
        let buf = &array[..raw_buf.len()];

        new_handle(match info.operation {
            Operation::OpenViaDup => {
                let (uid, gid) = match &*context::contexts()
                    .current()
                    .ok_or(Error::new(ESRCH))?
                    .read()
                {
                    context => (context.euid, context.egid),
                };
                return self
                    .open_inner(
                        info.pid,
                        Some(core::str::from_utf8(buf).map_err(|_| Error::new(EINVAL))?)
                            .filter(|s| !s.is_empty()),
                        O_RDWR | O_CLOEXEC,
                        uid,
                        gid,
                    )
                    .map(OpenResult::SchemeLocal);
            }

            Operation::Filetable { ref filetable } => {
                // TODO: Maybe allow userspace to either copy or transfer recently dupped file
                // descriptors between file tables.
                if buf != b"copy" {
                    return Err(Error::new(EINVAL));
                }
                let new_filetable = Arc::try_new(RwLock::new(filetable.read().clone()))
                    .map_err(|_| Error::new(ENOMEM))?;

                handle(
                    Operation::Filetable {
                        filetable: new_filetable,
                    },
                    OperationData::Other,
                )
            }
            Operation::AddrSpace { ref addrspace } => {
                const GRANT_FD_PREFIX: &[u8] = b"grant-fd-";

                let operation = match buf {
                    // TODO: Better way to obtain new empty address spaces, perhaps using SYS_OPEN. But
                    // in that case, what scheme?
                    b"empty" => Operation::AddrSpace {
                        addrspace: AddrSpaceWrapper::new()?,
                    },
                    b"exclusive" => Operation::AddrSpace {
                        addrspace: addrspace.try_clone()?,
                    },
                    b"mmap-min-addr" => Operation::MmapMinAddr(Arc::clone(addrspace)),

                    _ if buf.starts_with(GRANT_FD_PREFIX) => {
                        let string = core::str::from_utf8(&buf[GRANT_FD_PREFIX.len()..])
                            .map_err(|_| Error::new(EINVAL))?;
                        let page_addr =
                            usize::from_str_radix(string, 16).map_err(|_| Error::new(EINVAL))?;

                        if page_addr % PAGE_SIZE != 0 {
                            return Err(Error::new(EINVAL));
                        }

                        let page = Page::containing_address(VirtualAddress::new(page_addr));

                        match addrspace
                            .acquire_read()
                            .grants
                            .contains(page)
                            .ok_or(Error::new(EINVAL))?
                        {
                            (_, info) => {
                                return Ok(OpenResult::External(
                                    info.file_ref()
                                        .map(|r| Arc::clone(&r.description))
                                        .ok_or(Error::new(EBADF))?,
                                ))
                            }
                        }
                    }

                    _ => return Err(Error::new(EINVAL)),
                };

                handle(operation, OperationData::Offset(0))
            }
            Operation::Sigactions(ref sigactions) => {
                let new = match buf {
                    b"empty" => Context::empty_actions(),
                    b"copy" => Arc::new(RwLock::new(sigactions.read().clone())),
                    _ => return Err(Error::new(EINVAL)),
                };
                handle(Operation::Sigactions(new), OperationData::Other)
            }
            _ => return Err(Error::new(EINVAL)),
        })
        .map(OpenResult::SchemeLocal)
    }
}
extern "C" fn clone_handler() {
    // This function will return to the syscall return assembly, and subsequently transition to
    // usermode.
}

fn inherit_context() -> Result<ContextId> {
    let new_id = {
        let current_context_lock = Arc::clone(context::contexts().current().ok_or(Error::new(ESRCH))?);
        let new_context_lock = Arc::clone(context::contexts_mut().spawn(true, clone_handler)?);

        // (Starts with "all signals blocked".)

        let current_context = current_context_lock.read();
        let mut new_context = new_context_lock.write();

        new_context.status = Status::HardBlocked { reason: HardBlockedReason::NotYetStarted };

        // TODO: Move all of these IDs into somewhere in userspace, file descriptors as
        // capabilities. A userspace daemon can manage process hierarchies etc. whereas the kernel
        // only needs to manage contexts.
        new_context.euid = current_context.euid;
        new_context.egid = current_context.egid;
        new_context.ruid = current_context.ruid;
        new_context.rgid = current_context.rgid;
        new_context.ens = current_context.ens;
        new_context.rns = current_context.rns;
        new_context.ppid = current_context.id;
        new_context.pgid = current_context.pgid;
        new_context.session_id = current_context.session_id;
        new_context.umask = current_context.umask;

        new_context.id
    };

    if ptrace::send_event(crate::syscall::ptrace_event!(
        PTRACE_EVENT_CLONE,
        new_id.into()
    ))
    .is_some()
    {
        // Freeze the clone, allow ptrace to put breakpoints
        // to it before it starts
        let contexts = context::contexts();
        let context = contexts
            .get(new_id)
            .expect("Newly created context doesn't exist??");
        let mut context = context.write();
        context.ptrace_stop = true;
    }

    Ok(new_id)
}
fn extract_scheme_number(fd: usize) -> Result<(KernelSchemes, usize)> {
    let (scheme_id, number) = match &*context::contexts()
        .current()
        .ok_or(Error::new(ESRCH))?
        .read()
        .get_file(FileHandle::from(fd))
        .ok_or(Error::new(EBADF))?
        .description
        .read()
    {
        desc => (desc.scheme, desc.number),
    };
    let scheme = scheme::schemes()
        .get(scheme_id)
        .ok_or(Error::new(ENODEV))?
        .clone();

    Ok((scheme, number))
}
fn verify_scheme(scheme: KernelSchemes) -> Result<()> {
    if !matches!(
        scheme,
        KernelSchemes::Global(GlobalSchemes::ProcFull | GlobalSchemes::ProcRestricted)
    ) {
        return Err(Error::new(EBADF));
    }
    Ok(())
}
