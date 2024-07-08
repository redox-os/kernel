use crate::{
    arch::paging::{Page, RmmA, RmmArch, VirtualAddress},
    context::{
        self,
        context::{HardBlockedReason, SignalState},
        file::{FileDescriptor, InternalFlags},
        memory::{handle_notify_files, AddrSpaceWrapper, Grant, PageSpan},
        process::{self, Process, ProcessId},
        Context, ContextId, Status,
    },
    memory::PAGE_SIZE,
    ptrace,
    scheme::{self, FileHandle, KernelScheme},
    syscall::{
        self,
        data::{GrantDesc, Map, PtraceEvent, SetSighandlerData, Stat},
        error::*,
        flag::*,
        usercopy::{UserSliceRo, UserSliceWo},
        EnvRegisters, FloatRegisters, IntRegisters,
    },
};

use ::syscall::{SigProcControl, Sigcontrol};
use alloc::{
    boxed::Box,
    collections::{btree_map::Entry, BTreeMap},
    string::{String, ToString},
    sync::{Arc, Weak},
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

fn read_from(dst: UserSliceWo, src: &[u8], offset: u64) -> Result<usize> {
    let avail_src = usize::try_from(offset)
        .ok()
        .and_then(|o| src.get(o..))
        .unwrap_or(&[]);
    dst.copy_common_bytes_from_slice(avail_src)
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
    if pid == context::current_cid() {
        return Err(Error::new(EBADF));
    }
    // Stop process
    let (prev_status, mut running) = with_context_mut(pid, |context| {
        Ok((
            core::mem::replace(
                &mut context.status,
                context::Status::HardBlocked {
                    reason: HardBlockedReason::NotYetStarted,
                },
            ),
            context.running,
        ))
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

        context.status = prev_status;

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
enum ProcHandle {
    Trace {
        pid: ProcessId,
        clones: Vec<ProcessId>,
        excl: bool,
    },
    Static {
        ty: &'static str,
        bytes: Box<[u8]>,
    },
    SessionId,
    Attr {
        attr: Attr,
    },
}
#[derive(Clone)]
enum ContextHandle {
    Regs(RegsKind),
    Name,
    Sighandler,
    Start,
    NewFiletable {
        filetable: Arc<RwLock<Vec<Option<FileDescriptor>>>>,
        data: Box<[u8]>,
    },
    Filetable {
        filetable: Weak<RwLock<Vec<Option<FileDescriptor>>>>,
        data: Box<[u8]>,
    },
    AddrSpace {
        addrspace: Arc<AddrSpaceWrapper>,
    },
    CurrentAddrSpace,

    AwaitingAddrSpaceChange {
        new: Arc<AddrSpaceWrapper>,
        new_sp: usize,
        new_ip: usize,
    },

    CurrentFiletable,

    AwaitingFiletableChange {
        new_ft: Arc<RwLock<Vec<Option<FileDescriptor>>>>,
    },

    // TODO: Remove this once openat is implemented, or allow openat-via-dup via e.g. the top-level
    // directory.
    OpenViaDup,
    SchedAffinity,

    MmapMinAddr(Arc<AddrSpaceWrapper>),
}
#[derive(Clone)]
enum Handle {
    Context {
        context: Arc<RwSpinlock<Context>>,
        kind: ContextHandle,
    },
    Process {
        process: Arc<RwLock<Process>>,
        kind: ProcHandle,
    },
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Attr {
    Uid,
    Gid,
    // TODO: namespace, tid, etc.
}
impl Handle {
    fn needs_child_process(&self) -> bool {
        matches!(
            self,
            Self::Process {
                kind: ProcHandle::Trace { .. } | ProcHandle::SessionId,
                ..
            } | Self::Context {
                kind: ContextHandle::Regs(_)
                    | ContextHandle::Filetable { .. }
                    | ContextHandle::NewFiletable { .. }
                    | ContextHandle::AddrSpace { .. }
                    | ContextHandle::CurrentAddrSpace
                    | ContextHandle::CurrentFiletable
                    | ContextHandle::Sighandler,
                ..
            }
        )
    }
    fn needs_root(&self) -> bool {
        matches!(
            self,
            Self::Process {
                kind: Attr { .. },
                ..
            }
        )
    }
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
                context.status = context::Status::HardBlocked {
                    reason: HardBlockedReason::PtraceStop,
                };
            }
        }
        Some(())
    }
}

pub struct ProcScheme<const FULL: bool>;

static NEXT_ID: AtomicUsize = AtomicUsize::new(1);
// Using BTreeMap as hashbrown doesn't have a const constructor.
static HANDLES: RwLock<BTreeMap<usize, Handle>> = RwLock::new(BTreeMap::new());

fn new_handle((handle, fl): (Handle, InternalFlags)) -> Result<(usize, InternalFlags)> {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let _ = HANDLES.write().insert(id, handle);
    Ok((id, fl))
}

fn get_context(id: ContextId) -> Result<Arc<RwSpinlock<Context>>> {
    context::contexts()
        .get(id)
        .ok_or(Error::new(ENOENT))
        .map(Arc::clone)
}

impl<const FULL: bool> ProcScheme<FULL> {
    fn openat_context(&self, path: &str, context: Arc<RwLock<Context>>) {
        let kind = match path {
            "addrspace" => (
                ContextHandle::AddrSpace {
                    addrspace: Arc::clone(
                        context
                            .read()
                            .addr_space()
                            .map_err(|_| Error::new(ENOENT))?,
                    ),
                },
                true,
            ),
            "filetable" => (
                ContextHandle::Filetable {
                    filetable: Arc::downgrade(&context.read().files),
                    data: Box::new([]),
                },
                true,
            ),
            "current-addrspace" => (ContextHandle::CurrentAddrSpace, false),
            "current-filetable" => (ContextHandle::CurrentFiletable, false),
            "regs/float" => (ContextHandle::Regs(RegsKind::Float), false),
            "regs/int" => (ContextHandle::Regs(RegsKind::Int), false),
            "regs/env" => (ContextHandle::Regs(RegsKind::Env), false),
            "name" => (ContextHandle::Name, true),
            "sighandler" => (ContextHandle::Sighandler, false),
            "start" => (ContextHandle::Start, false),
            "open_via_dup" => (ContextHandle::OpenViaDup, false),
            "mmap-min-addr" => (
                ContextHandle::MmapMinAddr(Arc::clone(
                    context
                        .read()
                        .addr_space()
                        .map_err(|_| Error::new(ENOENT))?,
                )),
                false,
            ),
            "sched-affinity" => (ContextHandle::SchedAffinity, true),
            _ => return Err(Error::new(EINVAL)),
        };
    }
    fn open_inner(
        &self,
        pid: ProcessId,
        operation_str: Option<&str>,
        flags: usize,
        uid: u32,
        gid: u32,
    ) -> Result<(usize, InternalFlags)> {
        let processes = process::PROCESSES.read();
        let target = processes.get(&pid).ok_or(Error::new(ESRCH))?;

        let (handle, positioned) = match operation_str.ok_or(Error::new(EINVAL))? {
            "trace" => (ContextHandle::Trace { clones: Vec::new() }, false),
            "exe" => (
                ContextHandle::Static {
                    ty: "exe",
                    bytes: target.read().name.as_bytes().to_owned(),
                },
                true,
            ),
            "uid" => (ContextHandle::Attr { attr: Attr::Uid }, true),
            "gid" => (ContextHandle::Attr { attr: Attr::Gid }, true),
            "session_id" => (ContextHandle::SessionId, true),

            other => {
                let first_thread = target
                    .read()
                    .threads
                    .first()
                    .ok_or(Error::new(ESRCH))?
                    .upgrade()
                    .ok_or(Error::new(ESRCH))?;
                self.openat_context(other, first_thread)
            }
        };

        let mut data;

        {
            let target = target.read();

            if let Status::Exited(_) = target.status {
                return Err(Error::new(ESRCH));
            }

            // Unless root, check security
            if handle.needs_child_process() && uid != 0 && gid != 0 {
                let current = contexts.current().ok_or(Error::new(ESRCH))?;
                let current = current.read();

                // Are we the process?
                if target.pid != current.pid {
                    // Do we own the process?
                    if uid != target.euid && gid != target.egid {
                        return Err(Error::new(EPERM));
                    }

                    // Is it a subprocess of us? In the future, a capability could
                    // bypass this check.
                    match contexts
                        .ancestors(target.ppid)
                        .find(|&(id, _context)| pid == current.pid)
                    {
                        Some((id, context)) => {
                            // Paranoid sanity check, as ptrace security holes
                            // wouldn't be fun
                            assert_eq!(id, current.pid);
                            assert_eq!(id, context.read().pid);
                        }
                        None => return Err(Error::new(EPERM)),
                    }
                }
            } else if handle.needs_root() && (uid != 0 || gid != 0) {
                return Err(Error::new(EPERM));
            }

            let filetable_opt = match handle {
                ContextHandle::Filetable {
                    ref filetable,
                    ref mut data,
                } => Some((filetable.upgrade().ok_or(Error::new(EOWNERDEAD))?, data)),
                ContextHandle::NewFiletable {
                    ref filetable,
                    ref mut data,
                } => Some((Arc::clone(filetable), data)),
                _ => None,
            };
            if let Some((filetable, data)) = filetable_opt {
                *data = {
                    use core::fmt::Write;

                    let mut data = String::new();
                    for index in filetable
                        .read()
                        .iter()
                        .enumerate()
                        .filter_map(|(idx, val)| val.as_ref().map(|_| idx))
                    {
                        writeln!(data, "{}", index).unwrap();
                    }
                    data.into_bytes().into_boxed_slice()
                };
            }
        };

        let (id, int_fl) = new_handle((
            handle,
            if positioned {
                InternalFlags::POSITIONED
            } else {
                InternalFlags::empty()
            },
        ))?;

        if let ContextHandle::Trace = operation {
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

        Ok((id, int_fl))
    }
}

impl<const FULL: bool> KernelScheme for ProcScheme<FULL> {
    fn kopen(&self, path: &str, flags: usize, ctx: CallerCtx) -> Result<OpenResult> {
        let mut parts = path.splitn(2, '/');
        let pid_str = parts.next().ok_or(Error::new(ENOENT))?;

        let pid = if pid_str == "current" {
            context::current_cid()
        } else if pid_str == "new" {
            new_child()?
        } else if !FULL {
            return Err(Error::new(EACCES));
        } else {
            ContextId::new(pid_str.parse().map_err(|_| Error::new(ENOENT))?)
        };

        self.open_inner(pid, parts.next(), flags, ctx.uid, ctx.gid)
            .map(|(r, fl)| OpenResult::SchemeLocal(r, fl))
    }

    fn fevent(&self, id: usize, _flags: EventFlags) -> Result<EventFlags> {
        let handles = HANDLES.read();
        let handle = handles.get(&id).ok_or(Error::new(EBADF))?;

        match handle {
            ContextHandle::Trace { pid, .. } => ptrace::Session::with_session(pid, |session| {
                Ok(session.data.lock().session_fevent_flags())
            }),
            _ => Ok(EventFlags::empty()),
        }
    }

    fn close(&self, id: usize) -> Result<()> {
        let mut handle = HANDLES.write().remove(&id).ok_or(Error::new(EBADF))?;
        handle.continue_ignored_children();

        let stop_context = if handle.cid == context::current_cid() {
            with_context_mut
        } else {
            try_stop_context
        };

        match handle {
            ContextHandle::AwaitingAddrSpaceChange {
                new,
                new_sp,
                new_ip,
            } => {
                let pid = context.read().pid;

                let _ = stop_context(pid, |context: &mut Context| {
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
            ContextHandle::AddrSpace { addrspace } | ContextHandle::MmapMinAddr(addrspace) => {
                drop(addrspace)
            }

            ContextHandle::AwaitingFiletableChange { new_ft } => {
                context.write().files = new_ft;
            }
            ContextHandle::Trace { pid, excl, .. } => {
                ptrace::close_session(pid);

                if excl {
                    syscall::kill(pid, SIGKILL, false)?;
                }

                let contexts = context::contexts();
                if let Some(context) = contexts.get(pid) {
                    let mut context = context.write();
                    context.status = context::Status::Runnable;
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
        let handle = HANDLES.read().get(&id).ok_or(Error::new(EBADF))?.clone();
        let Handle::Context { context, kind } = handle else {
            return Err(Error::new(EBADF));
        };

        match kind {
            ContextHandle::AddrSpace { ref addrspace } => {
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
    fn kreadoff(
        &self,
        id: usize,
        buf: UserSliceWo,
        offset: u64,
        read_flags: u32,
        _stored_flags: u32,
    ) -> Result<usize> {
        // Don't hold a global lock during the context switch later on
        let handle = {
            let handles = HANDLES.read();
            handles.get(&id).ok_or(Error::new(EBADF))?.clone()
        };

        match info {
            _ => Err(Error::new(EBADF)),
        }
    }
    fn kwriteoff(
        &self,
        id: usize,
        buf: UserSliceRo,
        _offset: u64,
        _fcntl_flags: u32,
        _stored_flags: u32,
    ) -> Result<usize> {
        // TODO: offset

        // Don't hold a global lock during the context switch later on
        let handle = {
            let mut handles = HANDLES.write();
            let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;
            handle.continue_ignored_children();
            handle.clone()
        };

        match handle {
            Handle::Process { process, kind } => kind.kwriteoff(process, buf),
            Handle::Context { context, kind } => kind.kwriteoff(id, context, buf),
        }
    }
    fn kfpath(&self, id: usize, buf: UserSliceWo) -> Result<usize> {
        let handles = HANDLES.read();
        let handle = handles.get(&id).ok_or(Error::new(EBADF))?;

        let Handle::Process { process, kind } = handle else {
            return Err(Error::new(EBADF));
        };
        let path = format!(
            "proc:{}/{}",
            pid,
            match kind {
                ProcHandle::Attr {
                    attr: Attr::Uid, ..
                } => "uid",
                ProcHandle::Attr {
                    attr: Attr::Gid, ..
                } => "gid",
                ProcHandle::Trace { .. } => "trace",
                ProcHandle::Static { ty, .. } => ty,
                ProcHandle::SessionId => "session_id",
            },
        );
        /*let path = format!(
            "proc:{}/{}",
            handle.pid.get(),
            match handle {
                ContextHandle::Regs(RegsKind::Float) => "regs/float",
                ContextHandle::Regs(RegsKind::Int) => "regs/int",
                ContextHandle::Regs(RegsKind::Env) => "regs/env",
                ContextHandle::Name => "name",
                ContextHandle::Sighandler => "sighandler",
                ContextHandle::Filetable { .. } => "filetable",
                ContextHandle::AddrSpace { .. } => "addrspace",
                ContextHandle::CurrentAddrSpace => "current-addrspace",
                ContextHandle::CurrentFiletable => "current-filetable",
                ContextHandle::OpenViaDup => "open-via-dup",
                ContextHandle::MmapMinAddr(_) => "mmap-min-addr",
                ContextHandle::SchedAffinity => "sched-affinity",

                _ => return Err(Error::new(EOPNOTSUPP)),
            }
        );*/

        buf.copy_common_bytes_from_slice(path.as_bytes())
    }
    fn kfstat(&self, id: usize, buffer: UserSliceWo) -> Result<()> {
        let handles = HANDLES.read();
        let handle = handles.get(&id).ok_or(Error::new(EBADF))?;

        buffer.copy_exactly(&Stat {
            st_mode: MODE_FILE | 0o666,
            st_size: handle.fsize()?,

            ..Stat::default()
        })?;

        Ok(())
    }

    fn fsize(&self, id: usize) -> Result<u64> {
        let mut handles = HANDLES.write();
        let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;

        handle.fsize()
    }

    /// Dup is currently used to implement clone() and execve().
    fn kdup(&self, old_id: usize, raw_buf: UserSliceRo, _: CallerCtx) -> Result<OpenResult> {
        let info = {
            let handles = HANDLES.read();
            let handle = handles.get(&old_id).ok_or(Error::new(EBADF))?;

            handle.clone()
        };

        let handle = |h, positioned| {
            (
                h,
                if positioned {
                    InternalFlags::POSITIONED
                } else {
                    InternalFlags::empty()
                },
            )
        };
        let mut array = [0_u8; 64];
        if raw_buf.len() > array.len() {
            return Err(Error::new(EINVAL));
        }
        raw_buf.copy_to_slice(&mut array[..raw_buf.len()])?;
        let buf = &array[..raw_buf.len()];

        new_handle(match info {
            ContextHandle::OpenViaDup => {
                let (uid, gid) = match &*process::current()?.read() {
                    process => (process.euid, process.egid),
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
                    .map(|(r, fl)| OpenResult::SchemeLocal(r, fl));
            }

            ContextHandle::Filetable {
                ref filetable,
                ref data,
            } => {
                // TODO: Maybe allow userspace to either copy or transfer recently dupped file
                // descriptors between file tables.
                if buf != b"copy" {
                    return Err(Error::new(EINVAL));
                }
                let filetable = filetable.upgrade().ok_or(Error::new(EOWNERDEAD))?;

                let new_filetable = Arc::try_new(RwLock::new(filetable.read().clone()))
                    .map_err(|_| Error::new(ENOMEM))?;

                handle(
                    ContextHandle::NewFiletable {
                        filetable: new_filetable,
                        data: data.clone(),
                    },
                    true,
                )
            }
            ContextHandle::AddrSpace { ref addrspace } => {
                const GRANT_FD_PREFIX: &[u8] = b"grant-fd-";

                let kind = match buf {
                    // TODO: Better way to obtain new empty address spaces, perhaps using SYS_OPEN. But
                    // in that case, what scheme?
                    b"empty" => ContextHandle::AddrSpace {
                        addrspace: AddrSpaceWrapper::new()?,
                    },
                    b"exclusive" => ContextHandle::AddrSpace {
                        addrspace: addrspace.try_clone()?,
                    },
                    b"mmap-min-addr" => ContextHandle::MmapMinAddr(Arc::clone(addrspace)),

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

                handle(Handle::Context { context, kind }, true)
            }
            _ => return Err(Error::new(EINVAL)),
        })
        .map(|(r, fl)| OpenResult::SchemeLocal(r, fl))
    }
}
extern "C" fn clone_handler() {
    // This function will return to the syscall return assembly, and subsequently transition to
    // usermode.
}

fn new_child() -> Result<ContextId> {
    let new_id = {
        let current_process = process::current()?;
        let new_context_lock =
            Arc::clone(context::contexts_mut().spawn(true, current_process, clone_handler)?);

        // (Signals are initially disabled.)

        let mut new_context = new_context_lock.write();

        new_context.status = Status::HardBlocked {
            reason: HardBlockedReason::NotYetStarted,
        };

        new_context.cid
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
        context.status = context::Status::HardBlocked {
            reason: HardBlockedReason::PtraceStop,
        };
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
impl Handle {
    fn fsize(&self) -> Result<u64> {
        match self {
            Self::Process {
                kind: ProcHandle::Static { ref bytes, .. },
                ..
            } => Ok(bytes.len() as u64),
            Self::Context {
                kind:
                    ContextHandle::Filetable { ref data, .. }
                    | ContextHandle::NewFiletable { ref data, .. },
                ..
            } => Ok(data.len() as u64),
            _ => Ok(0),
        }
    }
}
impl ProcHandle {
    fn kwriteoff(self, process: Arc<RwLock<Process>>, buf: UserSliceRo) -> Result<usize> {
        match self {
            Self::Static { .. } => Err(Error::new(EBADF)),
            Self::Trace { .. } => {
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
                    try_stop_context(info.pid, |context| match context.regs_mut() {
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
                    })?;
                }

                // disable the ptrace_stop flag, which is used in some cases
                // FIXME
                /*
                with_context_mut(info.pid, |context| {
                    context.ptrace_stop = false;
                    Ok(())
                })?;
                */

                // and notify the tracee's WaitCondition, which is used in other cases
                ptrace::Session::with_session(info.pid, |session| {
                    session.tracee.notify();
                    Ok(())
                })?;

                Ok(mem::size_of::<u64>())
            }
            Self::Attr { attr } => {
                // TODO: What limit?
                let mut str_buf = [0_u8; 32];
                let bytes_copied = buf.copy_common_bytes_to_slice(&mut str_buf)?;

                let id = core::str::from_utf8(&str_buf[..bytes_copied])
                    .map_err(|_| Error::new(EINVAL))?
                    .parse::<u32>()
                    .map_err(|_| Error::new(EINVAL))?;

                match attr {
                    Attr::Uid => process.write().euid = id,
                    Attr::Gid => process.write().egid = id,
                }
                Ok(buf.len())
            }
            Self::SessionId => {
                let session_id = ProcessId::new(buf.read_usize()?);

                if session_id != process.read().pid {
                    // Session ID can only be set to this process's ID
                    return Err(Error::new(EPERM));
                }

                for (_pid, process_lock) in process::PROCESSES.read().iter() {
                    if session_id == process_lock.read().pgid {
                        // The session ID cannot match the PGID of any process
                        return Err(Error::new(EPERM));
                    }
                }

                {
                    let mut process = process.write();
                    process.pgid = session_id;
                    process.session_id = session_id;
                }

                Ok(buf.len())
            }
        }
    }
    fn kreadoff(
        self,
        id: usize,
        process: Arc<RwLock<Process>>,
        buf: UserSliceWo,
        offset: u64,
        read_flags: u32,
    ) -> Result<usize> {
        match self {
            Self::Static { bytes, .. } => {
                let mut handles = HANDLES.write();
                let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;
                read_from(buf, &bytes, offset)
            }
            Self::Trace { pid, clones, .. } => {
                // Wait for event
                if (read_flags as usize) & O_NONBLOCK != O_NONBLOCK {
                    ptrace::wait(pid)?;
                }

                // Check if process exists FIXME
                //with_context(pid, |_| Ok(()))?;

                let mut src_buf = [PtraceEvent::default(); 4];

                // Read events
                let src_len = src_buf.len();
                let slice = &mut src_buf
                    [..core::cmp::min(src_len, buf.len() / mem::size_of::<PtraceEvent>())];

                let (read, reached) = ptrace::Session::with_session(info.pid, |session| {
                    let mut data = session.data.lock();
                    Ok((data.recv_events(slice), data.is_reached()))
                })?;
                let mut handles = HANDLES.write();
                let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;
                let data = handle.data.trace_data().expect("operations can't change");

                // Save child processes in a list of processes to restart
                for event in &slice[..read] {
                    if event.cause == PTRACE_EVENT_CLONE {
                        data.clones.push(ContextId::from(event.a));
                    }
                }

                // If there are no events, and breakpoint isn't reached, we
                // must not have waited.
                if read == 0 && !reached {
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
            Self::SessionId => {
                read_from(buf, &process.read().session_id.get().to_ne_bytes(), offset)
            }
            Self::Attr { attr } => {
                let src_buf = match (attr, process.read()) {
                    (Attr::Uid, process) => process.euid.to_string(),
                    (Attr::Gid, process) => process.egid.to_string(),
                }
                .into_bytes();

                read_from(buf, &src_buf, offset)
            }
        }
    }
}
impl ContextHandle {
    fn kwriteoff(
        self,
        id: usize,
        context: Arc<RwSpinlock<Context>>,
        buf: UserSliceRo,
    ) -> Result<usize> {
        match self {
            Self::AddrSpace { addrspace } => {
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
            ContextHandle::Regs(kind) => match kind {
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
                            println!(
                                "{}:{}: Couldn't read registers from stopped process",
                                file!(),
                                line!()
                            );
                            Err(Error::new(ENOTRECOVERABLE))
                        }
                        Some(stack) => {
                            stack.load(&regs);

                            Ok(mem::size_of::<IntRegisters>())
                        }
                    })
                }
                RegsKind::Env => {
                    let regs = unsafe { buf.read_exact::<EnvRegisters>()? };
                    write_env_regs(context.read().cid, regs)?;
                    Ok(mem::size_of::<EnvRegisters>())
                }
            },
            ContextHandle::Name => {
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
            ContextHandle::Sighandler => {
                let data = unsafe { buf.read_exact::<SetSighandlerData>()? };

                if data.user_handler >= crate::USER_END_OFFSET
                    || data.excp_handler >= crate::USER_END_OFFSET
                {
                    return Err(Error::new(EPERM));
                }
                if data.thread_control_addr >= crate::USER_END_OFFSET
                    || data.proc_control_addr >= crate::USER_END_OFFSET
                {
                    return Err(Error::new(EFAULT));
                }

                let state = if data.thread_control_addr != 0 && data.proc_control_addr != 0 {
                    let validate_off = |addr, sz| {
                        let off = addr % PAGE_SIZE;
                        if off % mem::align_of::<usize>() == 0 && off + sz <= PAGE_SIZE {
                            Ok(off as u16)
                        } else {
                            Err(Error::new(EINVAL))
                        }
                    };

                    let addrsp = Arc::clone(
                        context::contexts()
                            .get(info.pid)
                            .ok_or(Error::new(ESRCH))?
                            .read()
                            .addr_space()?,
                    );

                    Some(SignalState {
                        threadctl_off: validate_off(
                            data.thread_control_addr,
                            mem::size_of::<Sigcontrol>(),
                        )?,
                        procctl_off: validate_off(
                            data.proc_control_addr,
                            mem::size_of::<SigProcControl>(),
                        )?,
                        user_handler: NonZeroUsize::new(data.user_handler)
                            .ok_or(Error::new(EINVAL))?,
                        excp_handler: NonZeroUsize::new(data.excp_handler),
                        thread_control: addrsp.borrow_frame_enforce_rw_allocated(
                            Page::containing_address(VirtualAddress::new(data.thread_control_addr)),
                        )?,
                        proc_control: addrsp.borrow_frame_enforce_rw_allocated(
                            Page::containing_address(VirtualAddress::new(data.proc_control_addr)),
                        )?,
                    })
                } else {
                    None
                };

                context::contexts()
                    .get(info.pid)
                    .ok_or(Error::new(ESRCH))?
                    .write()
                    .sig = state;

                Ok(mem::size_of::<SetSighandlerData>())
            }
            ContextHandle::Start => match context::contexts()
                .get(info.pid)
                .ok_or(Error::new(ESRCH))?
                .write()
                .status
            {
                ref mut status @ Status::HardBlocked {
                    reason: HardBlockedReason::NotYetStarted,
                } => {
                    *status = Status::Runnable;
                    Ok(buf.len())
                }
                _ => return Err(Error::new(EINVAL)),
            },
            ContextHandle::Filetable { .. } | ContextHandle::NewFiletable { .. } => {
                Err(Error::new(EBADF))
            }

            ContextHandle::CurrentFiletable => {
                let filetable_fd = buf.read_usize()?;
                let (hopefully_this_scheme, number) = extract_scheme_number(filetable_fd)?;
                verify_scheme(hopefully_this_scheme)?;

                let mut handles = HANDLES.write();
                let Entry::Occupied(mut entry) = handles.entry(number) else {
                    return Err(Error::new(EBADF));
                };
                let filetable = match *entry.get_mut() {
                    Handle::Process { .. } => return Err(Error::new(EBADF)),
                    Handle::Context {
                        kind: ContextHandle::Filetable { ref filetable, .. },
                        ..
                    } => filetable.upgrade().ok_or(Error::new(EOWNERDEAD))?,
                    Handle::Context {
                        kind:
                            ContextHandle::NewFiletable {
                                ref filetable,
                                ref data,
                            },
                        ..
                    } => {
                        let ft = Arc::clone(&filetable);
                        *entry.get_mut() = Handle::Context {
                            kind: ContextHandle::Filetable {
                                filetable: Arc::downgrade(&filetable),
                                data: data.clone(),
                            },
                            context: Arc::clone(&context),
                        };
                        ft
                    }

                    _ => return Err(Error::new(EBADF)),
                };

                *handles.get_mut(&id).ok_or(Error::new(EBADF))? = Handle::Context {
                    kind: ContextHandle::AwaitingFiletableChange { new_ft: filetable },
                    context,
                };

                Ok(mem::size_of::<usize>())
            }
            ContextHandle::CurrentAddrSpace { .. } => {
                let mut iter = buf.usizes();
                let addrspace_fd = iter.next().ok_or(Error::new(EINVAL))??;
                let sp = iter.next().ok_or(Error::new(EINVAL))??;
                let ip = iter.next().ok_or(Error::new(EINVAL))??;

                let (hopefully_this_scheme, number) = extract_scheme_number(addrspace_fd)?;
                verify_scheme(hopefully_this_scheme)?;

                let mut handles = HANDLES.write();
                let Handle::Context {
                    kind: ContextHandle::AddrSpace { ref addrspace },
                    ..
                } = handles.get(&number).ok_or(Error::new(EBADF))?
                else {
                    return Err(Error::new(EBADF));
                };

                *handles.get_mut(&id).ok_or(Error::new(EBADF))? = Handle::Context {
                    context,
                    kind: Self::AwaitingAddrSpaceChange {
                        new: Arc::clone(addrspace),
                        new_sp: sp,
                        new_ip: ip,
                    },
                };

                Ok(3 * mem::size_of::<usize>())
            }
            Self::MmapMinAddr(ref addrspace) => {
                let val = buf.read_usize()?;
                if val % PAGE_SIZE != 0 || val > crate::USER_END_OFFSET {
                    return Err(Error::new(EINVAL));
                }
                addrspace.acquire_write().mmap_min = val;
                Ok(mem::size_of::<usize>())
            }
            Self::SchedAffinity => {
                let mask = unsafe { buf.read_exact::<crate::cpu_set::RawMask>()? };

                context::contexts()
                    .get(info.pid)
                    .ok_or(Error::new(EBADFD))?
                    .write()
                    .sched_affinity
                    .override_from(&mask);

                Ok(mem::size_of_val(&mask))
            }
            Self::OpenViaDup
            | Self::AwaitingAddrSpaceChange { .. }
            | Self::AwaitingFiletableChange { .. } => Err(Error::new(EBADF)),
        }
    }
    fn kreadoff(
        &self,
        id: usize,
        context: Arc<RwSpinlock<Context>>,
        buf: UserSliceWo,
        offset: u64,
    ) -> Result<usize> {
        match self {
            ContextHandle::Regs(kind) => {
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
                            println!(
                                "{}:{}: Couldn't read registers from stopped process",
                                file!(),
                                line!()
                            );
                            Err(Error::new(ENOTRECOVERABLE))
                        }
                        Some(stack) => {
                            let mut regs = IntRegisters::default();
                            stack.save(&mut regs);
                            Ok((Output { int: regs }, mem::size_of::<IntRegisters>()))
                        }
                    })?,
                    RegsKind::Env => (
                        Output {
                            env: read_env_regs(&info)?,
                        },
                        mem::size_of::<EnvRegisters>(),
                    ),
                };

                let src_buf =
                    unsafe { slice::from_raw_parts(&output as *const _ as *const u8, size) };

                buf.copy_common_bytes_from_slice(src_buf)
            }
            ContextHandle::AddrSpace { ref addrspace } => {
                let Ok(offset) = usize::try_from(offset) else {
                    return Ok(0);
                };
                let grants_to_skip = offset / mem::size_of::<GrantDesc>();

                // Output a list of grant descriptors, sufficient to allow relibc's fork()
                // implementation to fmap MAP_SHARED grants.
                let mut grants_read = 0;

                let mut dst = [GrantDesc::default(); 16];

                for (dst, (grant_base, grant_info)) in dst
                    .iter_mut()
                    .zip(addrspace.acquire_read().grants.iter().skip(grants_to_skip))
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

                Ok(grants_read * mem::size_of::<GrantDesc>())
            }
            ContextHandle::Name => read_from(
                buf,
                context::contexts()
                    .get(info.pid)
                    .ok_or(Error::new(ESRCH))?
                    .read()
                    .name
                    .as_bytes(),
                offset,
            ),

            ContextHandle::Filetable { data, .. } => read_from(buf, &data, offset),
            ContextHandle::MmapMinAddr(ref addrspace) => {
                buf.write_usize(addrspace.acquire_read().mmap_min)?;
                Ok(mem::size_of::<usize>())
            }
            ContextHandle::SchedAffinity => {
                let mask = context::contexts()
                    .get(info.pid)
                    .ok_or(Error::new(EBADFD))?
                    .read()
                    .sched_affinity
                    .to_raw();

                buf.copy_exactly(crate::cpu_set::mask_as_bytes(&mask))?;
                Ok(mem::size_of_val(&mask))
            } // TODO: Replace write() with SYS_DUP_FORWARD.
              // TODO: Find a better way to switch address spaces, since they also require switching
              // the instruction and stack pointer. Maybe remove `<pid>/regs` altogether and replace it
              // with `<pid>/ctx`
        }
    }
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
fn write_env_regs(cid: ContextId, regs: EnvRegisters) -> Result<()> {
    if !(RmmA::virt_is_valid(VirtualAddress::new(regs.fsbase as usize))
        && RmmA::virt_is_valid(VirtualAddress::new(regs.gsbase as usize)))
    {
        return Err(Error::new(EINVAL));
    }

    if cid == context::current_cid() {
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
        try_stop_context(cid, |context| {
            context.arch.fsbase = regs.fsbase as usize;
            context.arch.gsbase = regs.gsbase as usize;
            Ok(())
        })?;
    }
    Ok(())
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
fn read_env_regs(cid: ContextId) -> Result<EnvRegisters> {
    // TODO: Avoid rdmsr if fsgsbase is not enabled, if this is worth optimizing for.
    let (fsbase, gsbase) = if cid == context::current_cid() {
        unsafe {
            (
                x86::msr::rdmsr(x86::msr::IA32_FS_BASE),
                x86::msr::rdmsr(x86::msr::IA32_KERNEL_GSBASE),
            )
        }
    } else {
        try_stop_context(cid, |context| {
            Ok((context.arch.fsbase as u64, context.arch.gsbase as u64))
        })?
    };
    Ok(EnvRegisters {
        fsbase: fsbase as _,
        gsbase: gsbase as _,
    })
}
