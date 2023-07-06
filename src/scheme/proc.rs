use crate::{
    arch::paging::{mapper::InactiveFlusher, Page, RmmA, RmmArch, VirtualAddress},
    context::{self, Context, ContextId, Status, file::{FileDescription, FileDescriptor}, memory::{AddrSpace, Grant, new_addrspace, map_flags, Region}, BorrowedHtBuf},
    memory::PAGE_SIZE,
    ptrace,
    scheme::{self, FileHandle, KernelScheme, SchemeId},
    syscall::{
        FloatRegisters,
        IntRegisters,
        EnvRegisters,
        data::{Map, PtraceEvent, SigAction, Stat},
        error::*,
        flag::*,
        scheme::{calc_seek_offset_usize, Scheme},
        self, usercopy::{UserSliceWo, UserSliceRo},
    },
};

use alloc::{
    boxed::Box,
    collections::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use ::syscall::CallerCtx;
use core::{
    mem,
    slice,
    str,
    sync::atomic::{AtomicUsize, Ordering},
};
use spin::{Once, RwLock};

use super::OpenResult;

fn read_from(dst: UserSliceWo, src: &[u8], offset: &mut usize) -> Result<usize> {
    let avail_src = src.get(*offset..).unwrap_or(&[]);
    let bytes_copied = dst.copy_common_bytes_from_slice(avail_src)?;
    *offset = offset.checked_add(bytes_copied).ok_or(Error::new(EOVERFLOW))?;
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
        unsafe { context::switch(); }

        running = with_context(pid, |context| {
            Ok(context.running)
        })?;
    }

    with_context_mut(pid, |context| {
        assert!(!context.running, "process can't have been restarted, we stopped it!");

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
    Memory { addrspace: Arc<RwLock<AddrSpace>> },
    Regs(RegsKind),
    Trace,
    Static(&'static str),
    Name,
    Sigstack,
    Attr(Attr),
    Filetable { filetable: Arc<RwLock<Vec<Option<FileDescriptor>>>> },
    AddrSpace { addrspace: Arc<RwLock<AddrSpace>> },
    CurrentAddrSpace,

    // "operations CAN change". The reason we split changing the address space into two handle
    // types, is that we would rather want the actual switch to occur when closing, as opposed to
    // when writing. This is so that we can actually guarantee that no file descriptors are leaked.
    AwaitingAddrSpaceChange {
        new: Arc<RwLock<AddrSpace>>,
        new_sp: usize,
        new_ip: usize,
    },

    CurrentFiletable,

    AwaitingFiletableChange(Arc<RwLock<Vec<Option<FileDescriptor>>>>),

    // TODO: Remove this once openat is implemented, or allow openat-via-dup via e.g. the top-level
    // directory.
    OpenViaDup,
    // Allows calling fmap directly on a FileDescriptor (as opposed to a FileDescriptor).
    //
    // TODO: Remove this once cross-scheme links are merged. That would allow acquiring a new
    // FD to access the file descriptor behind grants.
    GrantHandle { description: Arc<RwLock<FileDescription>> },

    SchedAffinity,
    Sigactions(Arc<RwLock<Vec<(SigAction, usize)>>>),
    CurrentSigactions,
    AwaitingSigactionsChange(Arc<RwLock<Vec<(SigAction, usize)>>>),

    MmapMinAddr(Arc<RwLock<AddrSpace>>),
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Attr {
    Uid,
    Gid,
    // TODO: namespace, tid, etc.
}
impl Operation {
    fn needs_child_process(&self) -> bool {
        matches!(self, Self::Memory { .. } | Self::Regs(_) | Self::Trace | Self::Filetable { .. } | Self::AddrSpace { .. } | Self::CurrentAddrSpace | Self::CurrentFiletable | Self::Sigactions(_) | Self::CurrentSigactions | Self::AwaitingSigactionsChange(_))
    }
    fn needs_root(&self) -> bool {
        matches!(self, Self::Attr(_))
    }
}
struct MemData {
    offset: VirtualAddress,
}
impl Default for MemData {
    fn default() -> Self {
        Self { offset: VirtualAddress::new(0) }
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
        Self {
            buf,
            offset: 0,
        }
    }
}
enum OperationData {
    Memory(MemData),
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
    fn mem_data(&mut self) -> Option<&mut MemData> {
        match self {
            OperationData::Memory(data) => Some(data),
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

pub static PROC_SCHEME_ID: Once<SchemeId> = Once::new();

pub struct ProcScheme {
    next_id: AtomicUsize,
    handles: RwLock<BTreeMap<usize, Handle>>,
    access: Access,
}
#[derive(PartialEq)]
pub enum Access {
    OtherProcesses,
    Restricted,
}

impl ProcScheme {
    pub fn new(scheme_id: SchemeId) -> Self {
        PROC_SCHEME_ID.call_once(|| scheme_id);

        Self {
            next_id: AtomicUsize::new(0),
            handles: RwLock::new(BTreeMap::new()),
            access: Access::OtherProcesses,
        }
    }
    pub fn restricted() -> Self {
        Self {
            next_id: AtomicUsize::new(0),
            handles: RwLock::new(BTreeMap::new()),
            access: Access::Restricted,
        }
    }
    fn new_handle(&self, handle: Handle) -> Result<usize> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let _ = self.handles.write().insert(id, handle);
        Ok(id)
    }
}

fn get_context(id: ContextId) -> Result<Arc<RwLock<Context>>> {
    context::contexts().get(id).ok_or(Error::new(ENOENT)).map(Arc::clone)
}

impl ProcScheme {
    fn open_inner(&self, pid: ContextId, operation_str: Option<&str>, flags: usize, uid: u32, gid: u32) -> Result<usize> {
        let operation = match operation_str {
            Some("mem") => Operation::Memory { addrspace: Arc::clone(get_context(pid)?.read().addr_space().map_err(|_| Error::new(ENOENT))?) },
            Some("addrspace") => Operation::AddrSpace { addrspace: Arc::clone(get_context(pid)?.read().addr_space().map_err(|_| Error::new(ENOENT))?) },
            Some("filetable") => Operation::Filetable { filetable: Arc::clone(&get_context(pid)?.read().files) },
            Some("current-addrspace") => Operation::CurrentAddrSpace,
            Some("current-filetable") => Operation::CurrentFiletable,
            Some("regs/float") => Operation::Regs(RegsKind::Float),
            Some("regs/int") => Operation::Regs(RegsKind::Int),
            Some("regs/env") => Operation::Regs(RegsKind::Env),
            Some("trace") => Operation::Trace,
            Some("exe") => Operation::Static("exe"),
            Some("name") => Operation::Name,
            Some("sigstack") => Operation::Sigstack,
            Some("uid") => Operation::Attr(Attr::Uid),
            Some("gid") => Operation::Attr(Attr::Gid),
            Some("open_via_dup") => Operation::OpenViaDup,
            Some("sigactions") => Operation::Sigactions(Arc::clone(&get_context(pid)?.read().actions)),
            Some("current-sigactions") => Operation::CurrentSigactions,
            Some("mmap-min-addr") => Operation::MmapMinAddr(Arc::clone(get_context(pid)?.read().addr_space().map_err(|_| Error::new(ENOENT))?)),
            Some("sched-affinity") => Operation::SchedAffinity,
            _ => return Err(Error::new(EINVAL))
        };

        let contexts = context::contexts();
        let target = contexts.get(pid).ok_or(Error::new(ESRCH))?;

        let mut data;

        {
            let target = target.read();

            data = match operation {
                Operation::Memory { .. } => OperationData::Memory(MemData::default()),
                Operation::Trace => OperationData::Trace(TraceData::default()),
                Operation::Static(_) => OperationData::Static(StaticData::new(
                    target.name.clone().into_owned().into_bytes().into()
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
                    match contexts.ancestors(target.ppid).find(|&(id, _context)| id == current.id) {
                        Some((id, context)) => {
                            // Paranoid sanity check, as ptrace security holes
                            // wouldn't be fun
                            assert_eq!(id, current.id);
                            assert_eq!(id, context.read().id);
                        },
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
                    for index in target.files.read().iter().enumerate().filter_map(|(idx, val)| val.as_ref().map(|_| idx)) {
                        writeln!(data, "{}", index).unwrap();
                    }
                    data.into_bytes().into_boxed_slice()
                }));
            }
        };

        let id = self.new_handle(Handle {
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
                Ok((
                    context.arch.tpidr_el0,
                    context.arch.tpidrro_el0,
                ))
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
                    crate::gdt::GDT[crate::gdt::GDT_USER_FS].offset() as u64,
                    crate::gdt::GDT[crate::gdt::GDT_USER_GS].offset() as u64
                )
            }
        } else {
            try_stop_context(info.pid, |context| {
                Ok((context.arch.fsbase as u64, context.arch.gsbase as u64))
            })?
        };
        Ok(EnvRegisters { fsbase: fsbase as _, gsbase: gsbase as _ })
    }

    #[cfg(target_arch = "x86_64")]
    fn read_env_regs(&self, info: &Info) -> Result<EnvRegisters> {
        let (fsbase, gsbase) = if info.pid == context::context_id() {
            #[cfg(not(feature = "x86_fsgsbase"))]
            unsafe {
                (
                    x86::msr::rdmsr(x86::msr::IA32_FS_BASE),
                    x86::msr::rdmsr(x86::msr::IA32_KERNEL_GSBASE),
                )
            }
            #[cfg(feature = "x86_fsgsbase")]
            unsafe {
                use x86::bits64::segmentation::*;

                (
                    rdfsbase(),
                    {
                        swapgs();
                        let gsbase = rdgsbase();
                        swapgs();
                        gsbase
                    }
                )
            }
        } else {
            try_stop_context(info.pid, |context| {
                Ok((context.arch.fsbase as u64, context.arch.gsbase as u64))
            })?
        };
        Ok(EnvRegisters { fsbase: fsbase as _, gsbase: gsbase as _ })
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
        if !(RmmA::virt_is_valid(VirtualAddress::new(regs.fsbase as usize)) && RmmA::virt_is_valid(VirtualAddress::new(regs.gsbase as usize))) {
            return Err(Error::new(EINVAL));
        }

        if info.pid == context::context_id() {
            unsafe {
                crate::gdt::GDT[crate::gdt::GDT_USER_FS].set_offset(regs.fsbase);
                crate::gdt::GDT[crate::gdt::GDT_USER_GS].set_offset(regs.gsbase);

                match context::contexts().current().ok_or(Error::new(ESRCH))?.write().arch {
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
        if !(RmmA::virt_is_valid(VirtualAddress::new(regs.fsbase as usize)) && RmmA::virt_is_valid(VirtualAddress::new(regs.gsbase as usize))) {
            return Err(Error::new(EINVAL));
        }

        if info.pid == context::context_id() {
            #[cfg(not(feature = "x86_fsgsbase"))]
            unsafe {
                x86::msr::wrmsr(x86::msr::IA32_FS_BASE, regs.fsbase as u64);
                // We have to write to KERNEL_GSBASE, because when the kernel returns to
                // userspace, it will have executed SWAPGS first.
                x86::msr::wrmsr(x86::msr::IA32_KERNEL_GSBASE, regs.gsbase as u64);

                match context::contexts().current().ok_or(Error::new(ESRCH))?.write().arch {
                    ref mut arch => {
                        arch.fsbase = regs.fsbase as usize;
                        arch.gsbase = regs.gsbase as usize;
                    }
                }
            }
            #[cfg(feature = "x86_fsgsbase")]
            unsafe {
                use x86::bits64::segmentation::*;

                wrfsbase(regs.fsbase);
                swapgs();
                wrgsbase(regs.gsbase);
                swapgs();

                // No need to update the current context; with fsgsbase enabled, these
                // registers are automatically saved and restored.
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

impl Scheme for ProcScheme {
    fn open(&self, path: &str, flags: usize, uid: u32, gid: u32) -> Result<usize> {
        let mut parts = path.splitn(2, '/');
        let pid_str = parts.next()
            .ok_or(Error::new(ENOENT))?;

        let pid = if pid_str == "current" {
            context::context_id()
        } else if pid_str == "new" {
            inherit_context()?
        } else if self.access == Access::Restricted {
            return Err(Error::new(EACCES));
        } else {
            ContextId::from(pid_str.parse().map_err(|_| Error::new(ENOENT))?)
        };

        self.open_inner(pid, parts.next(), flags, uid, gid)
    }


    fn seek(&self, id: usize, pos: isize, whence: usize) -> Result<isize> {
        let mut handles = self.handles.write();
        let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;
        let mut memory = handle.data.mem_data().ok_or(Error::new(EBADF))?;

        let value = calc_seek_offset_usize(memory.offset.data(), pos, whence, isize::max_value() as usize)?;
        memory.offset = VirtualAddress::new(value as usize);
        Ok(value)
    }

    fn fcntl(&self, id: usize, cmd: usize, arg: usize) -> Result<usize> {
        let mut handles = self.handles.write();
        let mut handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;

        match cmd {
            F_SETFL => { handle.info.flags = arg; Ok(0) },
            F_GETFL => Ok(handle.info.flags),
            _ => Err(Error::new(EINVAL))
        }
    }

    fn fevent(&self, id: usize, _flags: EventFlags) -> Result<EventFlags> {
        let handles = self.handles.read();
        let handle = handles.get(&id).ok_or(Error::new(EBADF))?;

        match handle.info.operation {
            Operation::Trace => ptrace::Session::with_session(handle.info.pid, |session| {
                Ok(session.data.lock().session_fevent_flags())
            }),
            _ => Ok(EventFlags::empty()),
        }
    }


    fn close(&self, id: usize) -> Result<usize> {
        let mut handle = self.handles.write().remove(&id).ok_or(Error::new(EBADF))?;
        handle.continue_ignored_children();

        let stop_context = if handle.info.pid == context::context_id() { with_context_mut } else { try_stop_context };

        match handle.info.operation {
            Operation::AwaitingAddrSpaceChange { new, new_sp, new_ip } => {
                stop_context(handle.info.pid, |context: &mut Context| unsafe {
                    if let Some(saved_regs) = ptrace::regs_for_mut(context) {
                        #[cfg(target_arch = "aarch64")]
                        {
                            saved_regs.iret.elr_el1 = new_ip;
                            saved_regs.iret.sp_el0 = new_sp;
                        }

                        #[cfg(target_arch = "x86")]
                        {
                            saved_regs.iret.eip = new_ip;
                            saved_regs.iret.esp = new_sp;
                        }

                        #[cfg(target_arch = "x86_64")]
                        {
                            saved_regs.iret.rip = new_ip;
                            saved_regs.iret.rsp = new_sp;
                        }
                    } else {
                        context.clone_entry = Some([new_ip, new_sp]);
                    }

                    let prev_addr_space = context.set_addr_space(new);

                    if let Some(prev_addr_space) = prev_addr_space {
                        maybe_cleanup_addr_space(prev_addr_space);
                    }

                    Ok(())
                })?;
                let _ = ptrace::send_event(crate::syscall::ptrace_event!(PTRACE_EVENT_ADDRSPACE_SWITCH, 0));
            }
            Operation::AddrSpace { addrspace } | Operation::Memory { addrspace } | Operation::MmapMinAddr(addrspace) => maybe_cleanup_addr_space(addrspace),

            Operation::AwaitingFiletableChange(new) => with_context_mut(handle.info.pid, |context: &mut Context| {
                context.files = new;
                Ok(())
            })?,
            Operation::AwaitingSigactionsChange(new) => with_context_mut(handle.info.pid, |context: &mut Context| {
                context.actions = new;
                Ok(())
            })?,
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
        Ok(0)
    }
    fn fmap(&self, id: usize, map: &Map) -> Result<usize> {
        self.kfmap(id, &AddrSpace::current()?, map, false)
    }
}
impl KernelScheme for ProcScheme {
    fn as_addrspace(&self, number: usize) -> Result<Arc<RwLock<AddrSpace>>> {
        if let Operation::AddrSpace { ref addrspace } | Operation::Memory { ref addrspace } = self.handles.read().get(&number).ok_or(Error::new(EBADF))?.info.operation {
            Ok(Arc::clone(addrspace))
        } else {
            Err(Error::new(EBADF))
        }
    }
    fn as_filetable(&self, number: usize) -> Result<Arc<RwLock<Vec<Option<FileDescriptor>>>>> {
        if let Operation::Filetable { ref filetable } = self.handles.read().get(&number).ok_or(Error::new(EBADF))?.info.operation {
            Ok(Arc::clone(filetable))
        } else {
            Err(Error::new(EBADF))
        }
    }
    fn as_sigactions(&self, number: usize) -> Result<Arc<RwLock<Vec<(crate::syscall::data::SigAction, usize)>>>> {
        if let Operation::Sigactions(ref sigactions) = self.handles.read().get(&number).ok_or(Error::new(EBADF))?.info.operation {
            Ok(Arc::clone(sigactions))
        } else {
            Err(Error::new(EBADF))
        }
    }
    fn kfmap(&self, id: usize, dst_addr_space: &Arc<RwLock<AddrSpace>>, map: &crate::syscall::data::Map, consume: bool) -> Result<usize> {
        let info = self.handles.read().get(&id).ok_or(Error::new(EBADF))?.info.clone();

        match info.operation {
            Operation::GrantHandle { ref description } => {
                // The map struct will probably reside in kernel memory, on the stack, and for that
                // it would be very insecure not to use the pinned head/tail buffer.
                let mut buf = BorrowedHtBuf::head()?;
                // TODO: This can be safe
                let map_dst = unsafe { buf.use_for_struct()? };
                *map_dst = *map;

                let (scheme_id, number) = {
                    let description = description.read();

                    (description.scheme, description.number)
                };
                let scheme = Arc::clone(scheme::schemes().get(scheme_id).ok_or(Error::new(EBADFD))?);
                let res = scheme.fmap(number, map_dst);

                res
            }
            Operation::AddrSpace { ref addrspace } => {
                if Arc::ptr_eq(addrspace, dst_addr_space) {
                    return Err(Error::new(EBUSY));
                }
                // Limit to transferring/borrowing at most one grant, or part of a grant (splitting
                // will be mandatory if grants are coalesced).

                let (requested_dst_page, page_count) = crate::syscall::validate_region(map.address, map.size)?;
                let (src_page, _) = crate::syscall::validate_region(map.offset, map.size)?;

                let requested_dst_page = (map.address != 0).then_some(requested_dst_page);

                let mut src_addr_space = addrspace.write();
                let src_addr_space = &mut *src_addr_space;
                let mut dst_addr_space = dst_addr_space.write();

                let src_grant_region = {
                    let src_region = Region::new(src_page.start_address(), page_count * PAGE_SIZE);
                    let mut conflicts = src_addr_space.grants.conflicts(src_region);
                    let first = conflicts.next().ok_or(Error::new(EINVAL))?;
                    if conflicts.next().is_some() {
                        return Err(Error::new(EINVAL));
                    }

                    if !first.can_have_flags(map.flags) {
                        return Err(Error::new(EACCES));
                    }

                    first.region().intersect(src_region)
                };

                let grant_page_count = src_grant_region.size() / PAGE_SIZE;

                let src_mapper = &mut src_addr_space.table.utable;

                let result_page = if consume {
                    let grant = src_addr_space.grants.take(&src_grant_region).expect("grant cannot disappear");
                    let (before, middle, after) = grant.extract(src_grant_region).expect("called intersect(), must succeed");

                    if let Some(before) = before { src_addr_space.grants.insert(before); }
                    if let Some(after) = after { src_addr_space.grants.insert(after); }

                    dst_addr_space.mmap(requested_dst_page, grant_page_count, map.flags, |dst_page, _flags, dst_mapper, dst_flusher| Grant::transfer(middle, dst_page, src_mapper, dst_mapper, InactiveFlusher::new(), dst_flusher))?
                } else {
                    dst_addr_space.mmap(requested_dst_page, grant_page_count, map.flags, |dst_page, flags, dst_mapper, flusher| Ok(Grant::borrow(Page::containing_address(src_grant_region.start_address()), dst_page, grant_page_count, flags, None, src_mapper, dst_mapper, flusher)?))?
                };

                Ok(result_page.start_address().data())
            }
            _ => Err(Error::new(EBADF)),
        }
    }
    fn kread(&self, id: usize, buf: UserSliceWo) -> Result<usize> {
        // Don't hold a global lock during the context switch later on
        let info = {
            let handles = self.handles.read();
            let handle = handles.get(&id).ok_or(Error::new(EBADF))?;
            handle.info.clone()
        };

        match info.operation {
            Operation::Static(_) => {
                let mut handles = self.handles.write();
                let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;
                let data = handle.data.static_data().expect("operations can't change");
                let src_buf = data.buf.get(data.offset..).unwrap_or(&[]);

                let len = buf.copy_common_bytes_from_slice(src_buf)?;
                data.offset += len;
                Ok(len)
            },
            Operation::Memory { addrspace } => {
                // Won't context switch, don't worry about the locks
                let mut handles = self.handles.write();
                let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;
                let data = handle.data.mem_data().expect("operations can't change");

                let mut bytes_read = 0;

                for chunk_opt in ptrace::context_memory(&mut *addrspace.write(), data.offset, buf.len()) {
                    let (chunk, _writable) = chunk_opt.ok_or(Error::new(EFAULT))?;
                    buf.advance(bytes_read).and_then(|buf| buf.limit(chunk.len())).ok_or(Error::new(EINVAL))?.copy_from_slice(unsafe { &*chunk })?;
                    /*
                    let dst_slice = &mut buf[bytes_read..bytes_read + chunk.len()];
                    unsafe {
                        chunk.as_mut_ptr().copy_to_nonoverlapping(dst_slice.as_mut_ptr(), dst_slice.len());
                    }
                    */
                    bytes_read += chunk.len();
                }

                data.offset = VirtualAddress::new(data.offset.data() + bytes_read);
                Ok(bytes_read)
            },
            // TODO: Support reading only a specific address range. Maybe using seek?
            Operation::AddrSpace { addrspace } => {
                let mut handles = self.handles.write();
                let OperationData::Offset(ref mut offset) = handles.get_mut(&id).ok_or(Error::new(EBADF))?.data else {
                    return Err(Error::new(EBADFD));
                };

                // TODO: Define a struct somewhere?
                const RECORD_SIZE: usize = mem::size_of::<usize>() * 4;
                let records = buf.in_exact_chunks(mem::size_of::<usize>()).array_chunks::<4>();

                let addrspace = addrspace.read();
                let mut bytes_read = 0;

                for ([r1, r2, r3, r4], grant) in records.zip(addrspace.grants.iter()).skip(*offset / RECORD_SIZE) {
                    r1.write_usize(grant.start_address().data())?;
                    r2.write_usize(grant.size())?;
                    r3.write_usize(map_flags(grant.flags()).bits() | if grant.desc_opt.is_some() { 0x8000_0000 } else { 0 })?;
                    r4.write_usize(grant.desc_opt.as_ref().map_or(0, |d| d.offset))?;
                    bytes_read += RECORD_SIZE;
                }

                *offset += bytes_read;
                Ok(bytes_read)
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

                        Ok((Output { float: context.get_fx_regs() }, mem::size_of::<FloatRegisters>()))
                    })?,
                    RegsKind::Int => try_stop_context(info.pid, |context| match unsafe { ptrace::regs_for(context) } {
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
                    RegsKind::Env => {
                        (
                            Output { env: self.read_env_regs(&info)? },
                            mem::size_of::<EnvRegisters>()
                        )
                    }
                };

                let src_buf = unsafe {
                    slice::from_raw_parts(&output as *const _ as *const u8, size)
                };

                buf.copy_common_bytes_from_slice(src_buf)
            },
            Operation::Trace => {
                let mut handles = self.handles.write();
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
                let slice = &mut src_buf[..core::cmp::min(src_len, buf.len() / mem::size_of::<PtraceEvent>())];

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
                    assert!(handle.info.flags & O_NONBLOCK == O_NONBLOCK, "wait woke up spuriously??");
                    return Err(Error::new(EAGAIN));
                }

                for (dst, src) in buf.in_exact_chunks(mem::size_of::<PtraceEvent>()).zip(slice.iter()) {
                    dst.copy_exactly(src)?;
                }

                // Return read events
                Ok(read * mem::size_of::<PtraceEvent>())
            }
            Operation::Name => read_from(buf, context::contexts().get(info.pid).ok_or(Error::new(ESRCH))?.read().name.as_bytes(), &mut 0),
            Operation::Sigstack => read_from(buf, &context::contexts().get(info.pid).ok_or(Error::new(ESRCH))?.read().sigstack.unwrap_or(!0).to_ne_bytes(), &mut 0),
            Operation::Attr(attr) => {
                let src_buf = match (attr, &*Arc::clone(context::contexts().get(info.pid).ok_or(Error::new(ESRCH))?).read()) {
                    (Attr::Uid, context) => context.euid.to_string(),
                    (Attr::Gid, context) => context.egid.to_string(),
                }.into_bytes();

                read_from(buf, &src_buf, &mut 0)
            }
            Operation::Filetable { .. } => {
                let mut handles = self.handles.write();
                let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;
                let data = handle.data.static_data().expect("operations can't change");

                read_from(buf, &data.buf, &mut data.offset)
            }
            Operation::MmapMinAddr(ref addrspace) => {
                buf.write_usize(addrspace.read().mmap_min)?;
                Ok(mem::size_of::<usize>())
            }
            Operation::SchedAffinity => {
                buf.write_usize(context::contexts().get(info.pid).ok_or(Error::new(EBADFD))?.read().sched_affinity.map_or(usize::MAX, |a| a % crate::cpu_count()))?;
                Ok(mem::size_of::<usize>())
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
            let mut handles = self.handles.write();
            let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;
            handle.continue_ignored_children();
            handle.info.clone()
        };

        match info.operation {
            Operation::Static(_) => Err(Error::new(EBADF)),
            Operation::Memory { addrspace } => {
                // Won't context switch, don't worry about the locks
                let mut handles = self.handles.write();
                let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;
                let data = handle.data.mem_data().expect("operations can't change");

                let mut bytes_written = 0;

                for chunk_opt in ptrace::context_memory(&mut *addrspace.write(), data.offset, buf.len()) {
                    let (chunk, writable) = chunk_opt.ok_or(Error::new(EFAULT))?;

                    if !writable { return Err(Error::new(EACCES)); }

                    buf.advance(bytes_written).and_then(|buf| buf.limit(chunk.len())).ok_or(Error::new(EINVAL))?
                        .copy_to_slice(unsafe { &mut *chunk })?;

                    bytes_written += chunk.len();
                }

                data.offset = data.offset.add(bytes_written);
                Ok(bytes_written)
            },
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
                        let (page, page_count) = crate::syscall::validate_region(next()??, next()??)?;
                        let flags = MapFlags::from_bits(next()??).ok_or(Error::new(EINVAL))?;

                        if !flags.contains(MapFlags::MAP_FIXED) {
                            return Err(Error::new(EOPNOTSUPP));
                        }

                        let (scheme, number) = extract_scheme_number(fd)?;

                        scheme.kfmap(number, &addrspace, &Map { offset, size: page_count * PAGE_SIZE, address: page.start_address().data(), flags }, op == ADDRSPACE_OP_TRANSFER)?;
                    }
                    ADDRSPACE_OP_MUNMAP => {
                        let (page, page_count) = crate::syscall::validate_region(next()??, next()??)?;

                        addrspace.write().munmap(page, page_count);
                    }
                    ADDRSPACE_OP_MPROTECT => {
                        let (page, page_count) = crate::syscall::validate_region(next()??, next()??)?;
                        let flags = MapFlags::from_bits(next()??).ok_or(Error::new(EINVAL))?;

                        addrspace.write().mprotect(page, page_count, flags)?;
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
                },
                RegsKind::Int => {
                    let regs = unsafe { buf.read_exact::<IntRegisters>()? };

                    try_stop_context(info.pid, |context| match unsafe { ptrace::regs_for_mut(context) } {
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
                        Some(op)
                            .filter(|op| op.intersects(PTRACE_STOP_MASK | PTRACE_EVENT_MASK))
                    );
                    Ok(())
                })?;

                if op.contains(PTRACE_STOP_SINGLESTEP) {
                    try_stop_context(info.pid, |context| {
                        match unsafe { ptrace::regs_for_mut(context) } {
                            None => {
                                println!("{}:{}: Couldn't read registers from stopped process", file!(), line!());
                                Err(Error::new(ENOTRECOVERABLE))
                            },
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
            },
            Operation::Name => {
                // TODO: What limit?
                let mut name_buf = [0_u8; 256];
                let bytes_copied = buf.copy_common_bytes_to_slice(&mut name_buf)?;

                let utf8 = alloc::string::String::from_utf8(name_buf[..bytes_copied].to_vec()).map_err(|_| Error::new(EINVAL))?;
                context::contexts().get(info.pid).ok_or(Error::new(ESRCH))?.write().name = utf8.into();
                Ok(buf.len())
            }
            Operation::Sigstack => {
                let sigstack = buf.read_usize()?;
                context::contexts().get(info.pid).ok_or(Error::new(ESRCH))?.write().sigstack = (sigstack != !0).then(|| sigstack);
                Ok(buf.len())
            }
            Operation::Attr(attr) => {
                // TODO: What limit?
                let mut str_buf = [0_u8; 32];
                let bytes_copied = buf.copy_common_bytes_to_slice(&mut str_buf)?;

                let id = core::str::from_utf8(&str_buf[..bytes_copied]).map_err(|_| Error::new(EINVAL))?.parse::<u32>().map_err(|_| Error::new(EINVAL))?;
                let context_lock = Arc::clone(context::contexts().get(info.pid).ok_or(Error::new(ESRCH))?);

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

                let filetable = hopefully_this_scheme.as_filetable(number)?;

                self.handles.write().get_mut(&id).ok_or(Error::new(EBADF))?.info.operation = Operation::AwaitingFiletableChange(filetable);

                Ok(mem::size_of::<usize>())
            }
            Operation::CurrentAddrSpace { .. } => {
                let mut iter = buf.usizes();
                let addrspace_fd = iter.next().ok_or(Error::new(EINVAL))??;
                let sp = iter.next().ok_or(Error::new(EINVAL))??;
                let ip = iter.next().ok_or(Error::new(EINVAL))??;

                let (hopefully_this_scheme, number) = extract_scheme_number(addrspace_fd)?;
                let space = hopefully_this_scheme.as_addrspace(number)?;

                self.handles.write().get_mut(&id).ok_or(Error::new(EBADF))?.info.operation = Operation::AwaitingAddrSpaceChange { new: space, new_sp: sp, new_ip: ip };

                Ok(3 * mem::size_of::<usize>())
            }
            Operation::CurrentSigactions => {
                let sigactions_fd = buf.read_usize()?;
                let (hopefully_this_scheme, number) = extract_scheme_number(sigactions_fd)?;
                let sigactions = hopefully_this_scheme.as_sigactions(number)?;
                self.handles.write().get_mut(&id).ok_or(Error::new(EBADF))?.info.operation = Operation::AwaitingSigactionsChange(sigactions);
                Ok(mem::size_of::<usize>())
            }
            Operation::MmapMinAddr(ref addrspace) => {
                let val = buf.read_usize()?;
                if val % PAGE_SIZE != 0 || val > crate::USER_END_OFFSET { return Err(Error::new(EINVAL)); }
                addrspace.write().mmap_min = val;
                Ok(mem::size_of::<usize>())
            }
            // TODO: Deduplicate code.
            Operation::SchedAffinity => {
                let val = buf.read_usize()?;
                context::contexts().get(info.pid).ok_or(Error::new(EBADFD))?.write().sched_affinity = if val == usize::MAX { None } else { Some(val % crate::cpu_count()) };
                Ok(mem::size_of::<usize>())
            }

            _ => Err(Error::new(EBADF)),
        }
    }
    fn kfpath(&self, id: usize, buf: UserSliceWo) -> Result<usize> {
        let handles = self.handles.read();
        let handle = handles.get(&id).ok_or(Error::new(EBADF))?;

        let path = format!("proc:{}/{}", handle.info.pid.into(), match handle.info.operation {
            Operation::Memory { .. } => "mem",
            Operation::Regs(RegsKind::Float) => "regs/float",
            Operation::Regs(RegsKind::Int) => "regs/int",
            Operation::Regs(RegsKind::Env) => "regs/env",
            Operation::Trace => "trace",
            Operation::Static(path) => path,
            Operation::Name => "name",
            Operation::Sigstack => "sigstack",
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
        });

        buf.copy_common_bytes_from_slice(path.as_bytes())
    }
    fn kfstat(&self, id: usize, buffer: UserSliceWo) -> Result<usize> {
        let handles = self.handles.read();
        let handle = handles.get(&id).ok_or(Error::new(EBADF))?;

        buffer.copy_exactly(&Stat {
            st_mode: MODE_FILE | 0o666,
            st_size: match handle.data {
                OperationData::Static(ref data) => (data.buf.len() - data.offset) as u64,
                _ => 0,
            },

            ..Stat::default()
        })?;

        Ok(0)
    }

    /// Dup is currently used to implement clone() and execve().
    fn kdup(&self, old_id: usize, raw_buf: UserSliceRo, _: CallerCtx) -> Result<OpenResult> {
        let info = {
            let handles = self.handles.read();
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

        self.new_handle(match info.operation {
            Operation::OpenViaDup => {
                let (uid, gid) = match &*context::contexts().current().ok_or(Error::new(ESRCH))?.read() {
                    context => (context.euid, context.egid),
                };
                return self.open_inner(info.pid, Some(core::str::from_utf8(buf).map_err(|_| Error::new(EINVAL))?).filter(|s| !s.is_empty()), O_RDWR | O_CLOEXEC, uid, gid).map(OpenResult::SchemeLocal);
            },

            Operation::Filetable { ref filetable } => {
                // TODO: Maybe allow userspace to either copy or transfer recently dupped file
                // descriptors between file tables.
                if buf != b"copy" {
                    return Err(Error::new(EINVAL));
                }
                let new_filetable = Arc::try_new(RwLock::new(filetable.read().clone())).map_err(|_| Error::new(ENOMEM))?;

                handle(Operation::Filetable { filetable: new_filetable }, OperationData::Other)
            }
            Operation::AddrSpace { ref addrspace } => {
                let (operation, is_mem) = match buf {
                    // TODO: Better way to obtain new empty address spaces, perhaps using SYS_OPEN. But
                    // in that case, what scheme?
                    b"empty" => (Operation::AddrSpace { addrspace: new_addrspace()? }, false),
                    b"exclusive" => (Operation::AddrSpace { addrspace: addrspace.write().try_clone()? }, false),
                    b"mem" => (Operation::Memory { addrspace: Arc::clone(addrspace) }, true),
                    b"mmap-min-addr" => (Operation::MmapMinAddr(Arc::clone(addrspace)), false),

                    grant_handle if grant_handle.starts_with(b"grant-") => {
                        let start_addr = usize::from_str_radix(core::str::from_utf8(&grant_handle[6..]).map_err(|_| Error::new(EINVAL))?, 16).map_err(|_| Error::new(EINVAL))?;
                        (Operation::GrantHandle {
                            description: Arc::clone(&addrspace.read().grants.contains(VirtualAddress::new(start_addr)).ok_or(Error::new(EINVAL))?.desc_opt.as_ref().ok_or(Error::new(EINVAL))?.desc.description)
                        }, false)
                    }

                    _ => return Err(Error::new(EINVAL)),
                };

                handle(operation, if is_mem { OperationData::Memory(MemData { offset: VirtualAddress::new(0) }) } else { OperationData::Offset(0) })
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
        }).map(OpenResult::SchemeLocal)
    }

}
extern "C" fn clone_handler() {
    let context_lock = Arc::clone(context::contexts().current().expect("expected the current context to be set in a spawn closure"));

    loop {
        unsafe {
            let Some([ip, sp]) = ({ context_lock.read().clone_entry }) else {
                context_lock.write().status = Status::Stopped(SIGSTOP);
                continue;
            };
            let [arg, is_singlestep] = [0; 2];

            crate::start::usermode(ip, sp, arg, is_singlestep);
        }
    }
}

fn inherit_context() -> Result<ContextId> {
    let new_id = {
        let current_context_lock = Arc::clone(context::contexts().current().ok_or(Error::new(ESRCH))?);
        let new_context_lock = Arc::clone(context::contexts_mut().spawn(clone_handler)?);

        let current_context = current_context_lock.read();
        let mut new_context = new_context_lock.write();

        new_context.status = Status::Stopped(SIGSTOP);

        // TODO: Move all of these IDs into somewhere in userspace. Processes as an abstraction
        // needs not be in the kernel; contexts are sufficient.
        new_context.euid = current_context.euid;
        new_context.egid = current_context.egid;
        new_context.ruid = current_context.ruid;
        new_context.rgid = current_context.rgid;
        new_context.ens = current_context.ens;
        new_context.rns = current_context.rns;
        new_context.ppid = current_context.id;
        new_context.pgid = current_context.pgid;
        new_context.umask = current_context.umask;

        // TODO: Force userspace to copy sigmask. Start with "all signals blocked".
        new_context.sigmask = current_context.sigmask;

        new_context.id
    };

    if ptrace::send_event(crate::syscall::ptrace_event!(PTRACE_EVENT_CLONE, new_id.into())).is_some() {
        // Freeze the clone, allow ptrace to put breakpoints
        // to it before it starts
        let contexts = context::contexts();
        let context = contexts.get(new_id).expect("Newly created context doesn't exist??");
        let mut context = context.write();
        context.ptrace_stop = true;
    }

    Ok(new_id)
}
fn extract_scheme_number(fd: usize) -> Result<(Arc<dyn KernelScheme>, usize)> {
    let (scheme_id, number) = match &*context::contexts().current().ok_or(Error::new(ESRCH))?.read().get_file(FileHandle::from(fd)).ok_or(Error::new(EBADF))?.description.read() {
        desc => (desc.scheme, desc.number)
    };
    let scheme = Arc::clone(scheme::schemes().get(scheme_id).ok_or(Error::new(ENODEV))?);

    Ok((scheme, number))
}
fn maybe_cleanup_addr_space(addr_space: Arc<RwLock<AddrSpace>>) {
    if let Ok(mut space) = Arc::try_unwrap(addr_space).map(RwLock::into_inner) {
        // We are the last reference to the address space; therefore it must be
        // unmapped.

        // TODO: Optimize away clearing of page tables? In that case, what about memory
        // deallocation?
        for grant in space.grants.into_iter() {
            grant.unmap(&mut space.table.utable, ());
        }
    }

}
