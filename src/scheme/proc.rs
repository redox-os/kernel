use crate::{
    arch::paging::{ActivePageTable, Flusher, InactivePageTable, mapper::{InactiveFlusher, Mapper, PageFlushAll}, Page, RmmA, VirtualAddress},
    context::{self, Context, ContextId, Status, file::{FileDescription, FileDescriptor}, memory::{AddrSpace, Grant, new_addrspace, map_flags, page_flags, Region}},
    memory::PAGE_SIZE,
    ptrace,
    scheme::{self, AtomicSchemeId, FileHandle, KernelScheme, SchemeId},
    syscall::{
        FloatRegisters,
        IntRegisters,
        EnvRegisters,
        data::{Map, PtraceEvent, Stat},
        error::*,
        flag::*,
        scheme::{calc_seek_offset_usize, Scheme},
        self,
        validate,
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
    cmp,
    convert::TryFrom,
    mem,
    slice,
    str,
    sync::atomic::{AtomicUsize, Ordering},
};
use spin::{Once, RwLock};

fn read_from(dst: &mut [u8], src: &[u8], offset: &mut usize) -> Result<usize> {
    let byte_count = cmp::min(dst.len(), src.len().saturating_sub(*offset));
    let next_offset = offset.saturating_add(byte_count);
    dst[..byte_count].copy_from_slice(&src[*offset..next_offset]);
    *offset = next_offset;
    Ok(byte_count)
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
fn try_stop_context<F, T>(pid: ContextId, mut callback: F) -> Result<T>
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
    Cwd,
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
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Attr {
    Uid,
    Gid,
    // TODO: namespace, tid, etc.
}
impl Operation {
    fn needs_child_process(&self) -> bool {
        matches!(self, Self::Memory { .. } | Self::Regs(_) | Self::Trace | Self::Filetable { .. } | Self::AddrSpace { .. } | Self::CurrentAddrSpace | Self::CurrentFiletable)
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

fn current_addrspace() -> Result<Arc<RwLock<AddrSpace>>> {
    Ok(Arc::clone(context::contexts().current().ok_or(Error::new(ESRCH))?.read().addr_space()?))
}

impl ProcScheme {
    fn open_inner(&self, pid: ContextId, operation_str: Option<&str>, flags: usize, uid: u32, gid: u32) -> Result<usize> {
        let operation = match operation_str {
            Some("mem") => Operation::Memory { addrspace: current_addrspace()? },
            Some("addrspace") => Operation::AddrSpace { addrspace: current_addrspace()? },
            Some("filetable") => Operation::Filetable { filetable: Arc::clone(&context::contexts().current().ok_or(Error::new(ESRCH))?.read().files) },
            Some("current-addrspace") => Operation::CurrentAddrSpace,
            Some("current-filetable") => Operation::CurrentFiletable,
            Some("regs/float") => Operation::Regs(RegsKind::Float),
            Some("regs/int") => Operation::Regs(RegsKind::Int),
            Some("regs/env") => Operation::Regs(RegsKind::Env),
            Some("trace") => Operation::Trace,
            Some("exe") => Operation::Static("exe"),
            Some("name") => Operation::Name,
            Some("cwd") => Operation::Cwd,
            Some("sigstack") => Operation::Sigstack,
            Some("uid") => Operation::Attr(Attr::Uid),
            Some("gid") => Operation::Attr(Attr::Gid),
            Some("open_via_dup") => Operation::OpenViaDup,
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
                    target.name.read().clone().into()
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
                        write!(data, "{}\n", index).unwrap();
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

    /// Dup is currently used to implement clone() and execve().
    fn dup(&self, old_id: usize, buf: &[u8]) -> Result<usize> {
        let info = {
            let handles = self.handles.read();
            let handle = handles.get(&old_id).ok_or(Error::new(EBADF))?;

            handle.info.clone()
        };

        self.new_handle(match info.operation {
            Operation::OpenViaDup => {
                let (uid, gid) = match &*context::contexts().current().ok_or(Error::new(ESRCH))?.read() {
                    context => (context.euid, context.egid),
                };
                return self.open_inner(info.pid, Some(core::str::from_utf8(buf).map_err(|_| Error::new(EINVAL))?).filter(|s| !s.is_empty()), O_RDWR | O_CLOEXEC, uid, gid);
            },

            Operation::Filetable { filetable } => {
                // TODO: Maybe allow userspace to either copy or transfer recently dupped file
                // descriptors between file tables.
                if buf != b"copy" {
                    return Err(Error::new(EINVAL));
                }
                let new_filetable = Arc::try_new(RwLock::new(filetable.read().clone())).map_err(|_| Error::new(ENOMEM))?;

                Handle {
                    info: Info {
                        flags: 0,
                        pid: info.pid,
                        operation: Operation::Filetable { filetable: new_filetable },
                    },
                    data: OperationData::Other,
                }
            }
            Operation::AddrSpace { addrspace } => {
                let (operation, is_mem) = match buf {
                    // TODO: Better way to obtain new empty address spaces, perhaps using SYS_OPEN. But
                    // in that case, what scheme?
                    b"empty" => (Operation::AddrSpace { addrspace: new_addrspace()? }, false),
                    b"exclusive" => (Operation::AddrSpace { addrspace: addrspace.read().try_clone()? }, false),
                    b"mem" => (Operation::Memory { addrspace: Arc::clone(&addrspace) }, true),

                    grant_handle if grant_handle.starts_with(b"grant-") => {
                        let start_addr = usize::from_str_radix(core::str::from_utf8(&grant_handle[6..]).map_err(|_| Error::new(EINVAL))?, 16).map_err(|_| Error::new(EINVAL))?;
                        (Operation::GrantHandle {
                            description: Arc::clone(&addrspace.read().grants.contains(VirtualAddress::new(start_addr)).ok_or(Error::new(EINVAL))?.desc_opt.as_ref().ok_or(Error::new(EINVAL))?.desc.description)
                        }, false)
                    }

                    _ => return Err(Error::new(EINVAL)),
                };
                Handle {
                    info: Info {
                        flags: 0,
                        pid: info.pid,
                        operation,
                    },
                    data: if is_mem { OperationData::Memory(MemData { offset: VirtualAddress::new(0) }) } else { OperationData::Offset(0) },
                }
            }
            _ => return Err(Error::new(EINVAL)),
        })
    }

    fn seek(&self, id: usize, pos: isize, whence: usize) -> Result<isize> {
        let mut handles = self.handles.write();
        let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;
        let mut memory = handle.data.mem_data().ok_or(Error::new(EBADF))?;

        let value = calc_seek_offset_usize(memory.offset.data(), pos, whence, isize::max_value() as usize)?;
        memory.offset = VirtualAddress::new(value as usize);
        Ok(value)
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn read(&self, id: usize, buf: &mut [u8]) -> Result<usize> {
        //TODO
        Err(Error::new(EINVAL))
    }

    #[cfg(target_arch = "x86_64")]
    fn read(&self, id: usize, buf: &mut [u8]) -> Result<usize> {
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

                let len = cmp::min(data.buf.len() - data.offset, buf.len());
                buf[..len].copy_from_slice(&data.buf[data.offset .. data.offset + len]);
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
                    let chunk = chunk_opt.ok_or(Error::new(EFAULT))?;
                    let dst_slice = &mut buf[bytes_read..bytes_read + chunk.len()];
                    unsafe {
                        chunk.as_mut_ptr().copy_to_nonoverlapping(dst_slice.as_mut_ptr(), dst_slice.len());
                    }
                    bytes_read += chunk.len();
                }

                data.offset = VirtualAddress::new(data.offset.data() + bytes_read);
                Ok(bytes_read)
            },
            // TODO: Support reading only a specific address range. Maybe using seek?
            Operation::AddrSpace { addrspace } => {
                let mut handles = self.handles.write();
                let offset = if let OperationData::Offset(ref mut offset) = handles.get_mut(&id).ok_or(Error::new(EBADF))?.data {
                    offset
                } else {
                    return Err(Error::new(EBADFD));
                };

                // TODO: Define a struct somewhere?
                const RECORD_SIZE: usize = mem::size_of::<usize>() * 4;
                let records = buf.array_chunks_mut::<RECORD_SIZE>();

                let addrspace = addrspace.read();
                let mut bytes_read = 0;

                for (record_bytes, grant) in records.zip(addrspace.grants.iter()).skip(*offset / RECORD_SIZE) {
                    let mut qwords = record_bytes.array_chunks_mut::<{mem::size_of::<usize>()}>();
                    qwords.next().unwrap().copy_from_slice(&usize::to_ne_bytes(grant.start_address().data()));
                    qwords.next().unwrap().copy_from_slice(&usize::to_ne_bytes(grant.size()));
                    qwords.next().unwrap().copy_from_slice(&usize::to_ne_bytes(map_flags(grant.flags()).bits() | if grant.desc_opt.is_some() { 0x8000_0000 } else { 0 }));
                    qwords.next().unwrap().copy_from_slice(&usize::to_ne_bytes(grant.desc_opt.as_ref().map_or(0, |d| d.offset)));
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
                    RegsKind::Int => try_stop_context(info.pid, |context| match unsafe { ptrace::regs_for(&context) } {
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
                        (Output { env: EnvRegisters { fsbase, gsbase }}, mem::size_of::<EnvRegisters>())
                    }
                };

                let bytes = unsafe {
                    slice::from_raw_parts(&output as *const _ as *const u8, mem::size_of::<Output>())
                };
                let len = cmp::min(buf.len(), size);
                buf[..len].copy_from_slice(&bytes[..len]);

                Ok(len)
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

                // Read events
                let slice = unsafe {
                    slice::from_raw_parts_mut(
                        buf.as_mut_ptr() as *mut PtraceEvent,
                        buf.len() / mem::size_of::<PtraceEvent>()
                    )
                };
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

                // Return read events
                Ok(read * mem::size_of::<PtraceEvent>())
            }
            Operation::Name => read_from(buf, context::contexts().get(info.pid).ok_or(Error::new(ESRCH))?.read().name.read().as_bytes(), &mut 0),
            Operation::Cwd => read_from(buf, context::contexts().get(info.pid).ok_or(Error::new(ESRCH))?.read().cwd.read().as_bytes(), &mut 0),
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
            // TODO: Replace write() with SYS_DUP_FORWARD.
            // TODO: Find a better way to switch address spaces, since they also require switching
            // the instruction and stack pointer. Maybe remove `<pid>/regs` altogether and replace it
            // with `<pid>/ctx`
            _ => return Err(Error::new(EBADF)),
        }
    }

    #[cfg(target_arch = "aarch64")]
    fn write(&self, id: usize, buf: &[u8]) -> Result<usize> {
        //TODO
        Err(Error::new(EINVAL))
    }

    #[cfg(target_arch = "x86_64")]
    fn write(&self, id: usize, buf: &[u8]) -> Result<usize> {
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
                    let chunk = chunk_opt.ok_or(Error::new(EFAULT))?;
                    let src_slice = &buf[bytes_written..bytes_written + chunk.len()];
                    unsafe {
                        chunk.as_mut_ptr().copy_from_nonoverlapping(src_slice.as_ptr(), src_slice.len());
                    }
                    bytes_written += chunk.len();
                }

                data.offset = VirtualAddress::new(data.offset.data() + bytes_written);
                Ok(bytes_written)
            },
            Operation::AddrSpace { addrspace } => {
                // FIXME: Forbid upgrading external mappings.

                let mut chunks = buf.array_chunks::<{mem::size_of::<usize>()}>().copied().map(usize::from_ne_bytes);
                // Update grant mappings, like mprotect but allowed to target other contexts.
                let base = chunks.next().ok_or(Error::new(EINVAL))?;
                let size = chunks.next().ok_or(Error::new(EINVAL))?;
                let flags = chunks.next().and_then(|f| MapFlags::from_bits(f)).ok_or(Error::new(EINVAL))?;
                let src_address = chunks.next();

                if base % PAGE_SIZE != 0 || size % PAGE_SIZE != 0 || base.saturating_add(size) > crate::USER_END_OFFSET {
                    return Err(Error::new(EINVAL));
                }

                let mut addrspace = addrspace.write();
                let is_active = addrspace.is_current();

                let (mut inactive, mut active);

                let (mut mapper, mut flusher) = if is_active {
                    active = (unsafe { ActivePageTable::new(rmm::TableKind::User) }, PageFlushAll::new());
                    (active.0.mapper(), &mut active.1 as &mut dyn Flusher<RmmA>)
                } else {
                    inactive = (unsafe { InactivePageTable::from_address(addrspace.frame.utable.start_address().data()) }, InactiveFlusher::new());
                    (inactive.0.mapper(), &mut inactive.1 as &mut dyn Flusher<RmmA>)
                };

                let region = Region::new(VirtualAddress::new(base), size);
                let conflicting = addrspace.grants.conflicts(region).map(|g| *g.region()).collect::<Vec<_>>();
                for conflicting_region in conflicting {
                    let whole_grant = addrspace.grants.take(&conflicting_region).ok_or(Error::new(EBADFD))?;
                    let (before_opt, current, after_opt) = whole_grant.extract(region.intersect(conflicting_region)).ok_or(Error::new(EBADFD))?;

                    if let Some(before) = before_opt {
                        addrspace.grants.insert(before);
                    }
                    if let Some(after) = after_opt {
                        addrspace.grants.insert(after);
                    }

                    let res = current.unmap(&mut mapper, &mut flusher);

                    if res.file_desc.is_some() {
                        // We prefer avoiding file operations from within the kernel. If userspace
                        // updates grants that overlap, it might as well enumerate grants and call
                        // partial funmap on its own.
                        return Err(Error::new(EBUSY));
                    }
                }

                let base_page = Page::containing_address(VirtualAddress::new(base));

                if let Some(src_address) = src_address {
                    // Forbid transferring grants to the same address space!
                    if is_active { return Err(Error::new(EBUSY)); }

                    let src_grant = current_addrspace()?.write().grants.take(&Region::new(VirtualAddress::new(src_address), size)).ok_or(Error::new(EINVAL))?;

                    if src_address % PAGE_SIZE != 0 || src_address.saturating_add(size) > crate::USER_END_OFFSET {
                        return Err(Error::new(EINVAL));
                    }

                    // TODO: Allow downgrading flags?

                    addrspace.grants.insert(Grant::transfer(
                        src_grant,
                        base_page,
                        &mut *unsafe { ActivePageTable::new(rmm::TableKind::User) },
                        &mut mapper,
                        PageFlushAll::new(),
                        flusher,
                    ));
                } else if flags.intersects(MapFlags::PROT_READ | MapFlags::PROT_EXEC | MapFlags::PROT_WRITE) {
                    addrspace.grants.insert(Grant::zeroed(base_page, size / PAGE_SIZE, page_flags(flags), &mut mapper, flusher)?);
                }

                // TODO: Set some "in use" flag every time an address space is switched to? This
                // way, we know what hardware threads are using any given page table, which we need
                // to know while doing TLB shootdown.

                Ok((3 + usize::from(src_address.is_some())) * mem::size_of::<usize>())
            }
            Operation::Regs(kind) => match kind {
                RegsKind::Float => {
                    if buf.len() < mem::size_of::<FloatRegisters>() {
                        return Ok(0);
                    }
                    if (buf.as_ptr() as usize) % mem::align_of::<FloatRegisters>() != 0 {
                        return Err(Error::new(EINVAL));
                    }
                    let regs = unsafe {
                        *(buf as *const _ as *const FloatRegisters)
                    };

                    with_context_mut(info.pid, |context| {
                        // NOTE: The kernel will never touch floats

                        // Ignore the rare case of floating point
                        // registers being uninitiated
                        let _ = context.set_fx_regs(regs);

                        Ok(mem::size_of::<FloatRegisters>())
                    })
                },
                RegsKind::Int => {
                    if buf.len() < mem::size_of::<IntRegisters>() {
                        return Ok(0);
                    }
                    if (buf.as_ptr() as usize) % mem::align_of::<FloatRegisters>() != 0 {
                        return Err(Error::new(EINVAL));
                    }
                    let regs = unsafe {
                        *(buf as *const _ as *const IntRegisters)
                    };

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
                    if buf.len() < mem::size_of::<EnvRegisters>() {
                        return Ok(0);
                    }
                    if (buf.as_ptr() as usize) % mem::align_of::<EnvRegisters>() != 0 {
                        return Err(Error::new(EINVAL));
                    }
                    let regs = unsafe {
                        *(buf as *const _ as *const EnvRegisters)
                    };
                    use rmm::{Arch as _, X8664Arch};
                    if !(X8664Arch::virt_is_valid(VirtualAddress::new(regs.fsbase as usize)) && X8664Arch::virt_is_valid(VirtualAddress::new(regs.gsbase as usize))) {
                        return Err(Error::new(EINVAL));
                    }

                    if info.pid == context::context_id() {
                        #[cfg(not(feature = "x86_fsgsbase"))]
                        unsafe {
                            x86::msr::wrmsr(x86::msr::IA32_FS_BASE, regs.fsbase);
                            // We have to write to KERNEL_GSBASE, because when the kernel returns to
                            // userspace, it will have executed SWAPGS first.
                            x86::msr::wrmsr(x86::msr::IA32_KERNEL_GSBASE, regs.gsbase);

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
                    Ok(mem::size_of::<EnvRegisters>())
                }
            },
            Operation::Trace => {
                if buf.len() < mem::size_of::<u64>() {
                    return Ok(0);
                }

                let mut bytes = [0; mem::size_of::<u64>()];
                let len = bytes.len();
                bytes.copy_from_slice(&buf[0..len]);
                let op = u64::from_ne_bytes(bytes);
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
            // TODO: Deduplicate name and cwd
            Operation::Name => {
                let utf8 = alloc::string::String::from_utf8(buf.to_vec()).map_err(|_| Error::new(EINVAL))?.into_boxed_str();
                *context::contexts().get(info.pid).ok_or(Error::new(ESRCH))?.read().name.write() = utf8;
                Ok(buf.len())
            }
            Operation::Cwd => {
                let utf8 = alloc::string::String::from_utf8(buf.to_vec()).map_err(|_| Error::new(EINVAL))?;
                *context::contexts().get(info.pid).ok_or(Error::new(ESRCH))?.read().cwd.write() = utf8;
                Ok(buf.len())
            }
            Operation::Sigstack => {
                let bytes = <[u8; mem::size_of::<usize>()]>::try_from(buf).map_err(|_| Error::new(EINVAL))?;
                let sigstack = usize::from_ne_bytes(bytes);
                context::contexts().get(info.pid).ok_or(Error::new(ESRCH))?.write().sigstack = (sigstack != !0).then(|| sigstack);
                Ok(buf.len())
            }
            Operation::Attr(attr) => {
                let context_lock = Arc::clone(context::contexts().get(info.pid).ok_or(Error::new(ESRCH))?);
                let id = core::str::from_utf8(buf).map_err(|_| Error::new(EINVAL))?.parse::<u32>().map_err(|_| Error::new(EINVAL))?;

                match attr {
                    Attr::Uid => context_lock.write().euid = id,
                    Attr::Gid => context_lock.write().egid = id,
                }
                Ok(buf.len())
            }
            Operation::Filetable { .. } => return Err(Error::new(EBADF)),
            Operation::CurrentFiletable => {
                let filetable_fd = usize::from_ne_bytes(<[u8; mem::size_of::<usize>()]>::try_from(buf).map_err(|_| Error::new(EINVAL))?);
                let (hopefully_this_scheme, number) = extract_scheme_number(filetable_fd)?;

                let mut filetable = hopefully_this_scheme.as_filetable(number)?;

                self.handles.write().get_mut(&id).ok_or(Error::new(EBADF))?.info.operation = Operation::AwaitingFiletableChange(filetable);

                Ok(mem::size_of::<usize>())
            }
            Operation::CurrentAddrSpace { .. } => {
                let mut iter = buf.array_chunks::<{mem::size_of::<usize>()}>().copied().map(usize::from_ne_bytes);
                let addrspace_fd = iter.next().ok_or(Error::new(EINVAL))?;
                let sp = iter.next().ok_or(Error::new(EINVAL))?;
                let ip = iter.next().ok_or(Error::new(EINVAL))?;

                let (hopefully_this_scheme, number) = extract_scheme_number(addrspace_fd)?;
                let space = hopefully_this_scheme.as_addrspace(number)?;

                self.handles.write().get_mut(&id).ok_or(Error::new(EBADF))?.info.operation = Operation::AwaitingAddrSpaceChange { new: space, new_sp: sp, new_ip: ip };

                Ok(3 * mem::size_of::<usize>())
            }
            _ => return Err(Error::new(EBADF)),
        }
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

    fn fpath(&self, id: usize, buf: &mut [u8]) -> Result<usize> {
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
            Operation::Cwd => "cwd",
            Operation::Sigstack => "sigstack",
            Operation::Attr(Attr::Uid) => "uid",
            Operation::Attr(Attr::Gid) => "gid",
            Operation::Filetable { .. } => "filetable",
            Operation::AddrSpace { .. } => "addrspace",
            Operation::CurrentAddrSpace => "current-addrspace",
            Operation::CurrentFiletable => "current-filetable",
            Operation::OpenViaDup => "open-via-dup",

            _ => return Err(Error::new(EOPNOTSUPP)),
        });

        read_from(buf, &path.as_bytes(), &mut 0)
    }

    fn fstat(&self, id: usize, stat: &mut Stat) -> Result<usize> {
        let handles = self.handles.read();
        let handle = handles.get(&id).ok_or(Error::new(EBADF))?;

        stat.st_size = match handle.data {
            OperationData::Static(ref data) => (data.buf.len() - data.offset) as u64,
            _ => 0,
        };
        *stat = Stat {
            st_mode: MODE_FILE | 0o666,
            st_size: match handle.data {
                OperationData::Static(ref data) => (data.buf.len() - data.offset) as u64,
                _ => 0,
            },

            ..Stat::default()
        };

        Ok(0)
    }

    fn close(&self, id: usize) -> Result<usize> {
        let mut handle = self.handles.write().remove(&id).ok_or(Error::new(EBADF))?;
        handle.continue_ignored_children();

        let stop_context = if handle.info.pid == context::context_id() { with_context_mut } else { try_stop_context };

        match handle.info.operation {
            Operation::AwaitingAddrSpaceChange { new, new_sp, new_ip } => stop_context(handle.info.pid, |context: &mut Context| unsafe {
                if let Some(saved_regs) = ptrace::regs_for_mut(context) {
                    saved_regs.iret.rip = new_ip;
                    saved_regs.iret.rsp = new_sp;
                } else {
                    context.clone_entry = Some([new_ip, new_sp]);
                }

                let prev_addr_space = context.set_addr_space(new);

                if let Some(prev) = prev_addr_space.and_then(|a| Arc::try_unwrap(a).ok()).map(RwLock::into_inner) {
                    // We are the last reference to the address space; therefore it must be
                    // unmapped.

                    let mut table = unsafe { InactivePageTable::from_address(prev.frame.utable.start_address().data()) };

                    // TODO: Optimize away clearing of page tables? In that case, what about memory
                    // deallocation?
                    for grant in prev.grants.into_iter() {
                        grant.unmap(&mut table.mapper(), ());
                    }
                }

                Ok(())
            })?,
            Operation::AwaitingFiletableChange(new) => with_context_mut(handle.info.pid, |context: &mut Context| {
                context.files = new;
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
    // TODO: Support borrowing someone else's memory.
    fn fmap(&self, id: usize, map: &Map) -> Result<usize> {
        let description_lock = match self.handles.read().get(&id) {
            Some(Handle { info: Info { operation: Operation::GrantHandle { ref description }, .. }, .. }) => Arc::clone(description),
            _ => return Err(Error::new(EBADF)),
        };
        let (scheme_id, number) = {
            let description = description_lock.read();

            (description.scheme, description.number)
        };
        let scheme = Arc::clone(scheme::schemes().get(scheme_id).ok_or(Error::new(EBADFD))?);
        scheme.fmap(number, map)
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
}
extern "C" fn clone_handler() {
    let context_lock = Arc::clone(context::contexts().current().expect("expected the current context to be set in a spawn closure"));

    #[cfg(target_arch = "x86_64")]
    unsafe {
        let [ip, sp] = context_lock.read().clone_entry.expect("clone_entry must be set");
        let [arg, is_singlestep] = [0; 2];

        crate::start::usermode(ip, sp, arg, is_singlestep);
    }
}

fn inherit_context() -> Result<ContextId> {
    let current_context_lock = Arc::clone(context::contexts().current().ok_or(Error::new(ESRCH))?);
    let new_context_lock = Arc::clone(context::contexts_mut().spawn(clone_handler)?);

    let current_context = current_context_lock.read();
    let mut new_context = new_context_lock.write();

    new_context.status = Status::Stopped(SIGSTOP);
    new_context.euid = current_context.euid;
    new_context.egid = current_context.egid;
    new_context.ruid = current_context.ruid;
    new_context.rgid = current_context.rgid;
    new_context.ens = current_context.ens;
    new_context.rns = current_context.rns;
    new_context.ppid = current_context.id;
    new_context.pgid = current_context.pgid;
    new_context.umask = current_context.umask;
    new_context.sigmask = current_context.sigmask;

    // TODO: More to copy?

    Ok(new_context.id)
}
fn extract_scheme_number(fd: usize) -> Result<(Arc<dyn KernelScheme>, usize)> {
    let (scheme_id, number) = match &*context::contexts().current().ok_or(Error::new(ESRCH))?.read().get_file(FileHandle::from(fd)).ok_or(Error::new(EBADF))?.description.read() {
        desc => (desc.scheme, desc.number)
    };
    let scheme = Arc::clone(scheme::schemes().get(scheme_id).ok_or(Error::new(ENODEV))?);

    Ok((scheme, number))
}
