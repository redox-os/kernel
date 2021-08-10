use crate::{
    arch::paging::VirtualAddress,
    context::{self, Context, ContextId, Status},
    ptrace,
    scheme::{AtomicSchemeId, SchemeId},
    syscall::{
        FloatRegisters,
        IntRegisters,
        EnvRegisters,
        data::{PtraceEvent, Stat},
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
    vec::Vec,
};
use core::{
    cmp,
    mem,
    slice,
    str,
    sync::atomic::{AtomicUsize, Ordering},
};
use spin::RwLock;

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
    F: FnMut(&mut Context) -> Result<T>,
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
#[derive(Clone, Copy, PartialEq, Eq)]
enum Operation {
    Memory,
    Regs(RegsKind),
    Trace,
    Static(&'static str),
}
impl Operation {
    fn needs_child_process(self) -> bool {
        match self {
            Self::Memory => true,
            Self::Regs(_) => true,
            Self::Trace => true,
            Self::Static(_) => false,
        }
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

#[derive(Clone, Copy)]
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

pub static PROC_SCHEME_ID: AtomicSchemeId = AtomicSchemeId::default();

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
        PROC_SCHEME_ID.store(scheme_id, Ordering::SeqCst);

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
}

impl Scheme for ProcScheme {
    fn open(&self, path: &str, flags: usize, uid: u32, gid: u32) -> Result<usize> {
        let mut parts = path.splitn(2, '/');
        let pid_str = parts.next()
            .ok_or(Error::new(ENOENT))?;

        let pid = if pid_str == "current" {
            context::context_id()
        } else if self.access == Access::Restricted {
            return Err(Error::new(EACCES));
        } else {
            ContextId::from(pid_str.parse().map_err(|_| Error::new(ENOENT))?)
        };

        let operation = match parts.next() {
            Some("mem") => Operation::Memory,
            Some("regs/float") => Operation::Regs(RegsKind::Float),
            Some("regs/int") => Operation::Regs(RegsKind::Int),
            Some("regs/env") => Operation::Regs(RegsKind::Env),
            Some("trace") => Operation::Trace,
            Some("exe") => Operation::Static("exe"),
            _ => return Err(Error::new(EINVAL))
        };

        let contexts = context::contexts();
        let target = contexts.get(pid).ok_or(Error::new(ESRCH))?;

        let data;

        {
            let target = target.read();

            data = match operation {
                Operation::Memory => OperationData::Memory(MemData::default()),
                Operation::Trace => OperationData::Trace(TraceData::default()),
                Operation::Static(_) => OperationData::Static(StaticData::new(
                    target.name.read().clone().into()
                )),
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
            }
        };

        let id = self.next_id.fetch_add(1, Ordering::SeqCst);

        if let Operation::Trace { .. } = operation {
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

        self.handles.write().insert(id, Handle {
            info: Info {
                flags,
                pid,
                operation,
            },
            data,
        });
        Ok(id)
    }

    /// Using dup for `proc:` simply opens another operation on the same PID
    /// ```rust,ignore
    /// let trace = syscall::open("proc:1234/trace")?;
    ///
    /// // let regs = syscall::open("proc:1234/regs/int")?;
    /// let regs = syscall::dup(trace, "regs/int")?;
    /// ```
    fn dup(&self, old_id: usize, buf: &[u8]) -> Result<usize> {
        let info = {
            let handles = self.handles.read();
            let handle = handles.get(&old_id).ok_or(Error::new(EBADF))?;
            handle.info
        };

        let buf_str = str::from_utf8(buf).map_err(|_| Error::new(EINVAL))?;

        let mut path = format!("{}/", info.pid.into());
        path.push_str(buf_str);

        let (uid, gid) = {
            let contexts = context::contexts();
            let context = contexts.current().ok_or(Error::new(ESRCH))?;
            let context = context.read();
            (context.euid, context.egid)
        };

        self.open(&path, info.flags, uid, gid)
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
            handle.info
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
            Operation::Memory => {
                // Won't context switch, don't worry about the locks
                let mut handles = self.handles.write();
                let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;
                let data = handle.data.mem_data().expect("operations can't change");

                let contexts = context::contexts();
                let context = contexts.get(info.pid).ok_or(Error::new(ESRCH))?;
                let mut context = context.write();

                ptrace::with_context_memory(&mut context, data.offset, buf.len(), |ptr| {
                    buf.copy_from_slice(validate::validate_slice(ptr, buf.len())?);
                    Ok(())
                })?;

                data.offset = VirtualAddress::new(data.offset.data() + buf.len());
                Ok(buf.len())
            },
            Operation::Regs(kind) => {
                union Output {
                    float: FloatRegisters,
                    int: IntRegisters,
                    env: EnvRegisters,
                }

                let (output, size) = match kind {
                    RegsKind::Float => with_context(info.pid, |context| {
                        // NOTE: The kernel will never touch floats

                        // In the rare case of not having floating
                        // point registers uninitiated, return
                        // empty everything.
                        let fx = context.arch.get_fx_regs().unwrap_or_default();
                        Ok((Output { float: fx }, mem::size_of::<FloatRegisters>()))
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
            handle.info
        };

        match info.operation {
            Operation::Static(_) => Err(Error::new(EBADF)),
            Operation::Memory => {
                // Won't context switch, don't worry about the locks
                let mut handles = self.handles.write();
                let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;
                let data = handle.data.mem_data().expect("operations can't change");

                let contexts = context::contexts();
                let context = contexts.get(info.pid).ok_or(Error::new(ESRCH))?;
                let mut context = context.write();

                ptrace::with_context_memory(&mut context, data.offset, buf.len(), |ptr| {
                    validate::validate_slice_mut(ptr, buf.len())?.copy_from_slice(buf);
                    Ok(())
                })?;

                data.offset = VirtualAddress::new(data.offset.data() + buf.len());
                Ok(buf.len())
            },
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
                        let _ = context.arch.set_fx_regs(regs);

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
            Operation::Memory => "mem",
            Operation::Regs(RegsKind::Float) => "regs/float",
            Operation::Regs(RegsKind::Int) => "regs/int",
            Operation::Regs(RegsKind::Env) => "regs/env",
            Operation::Trace => "trace",
            Operation::Static(path) => path,
        });

        let len = cmp::min(path.len(), buf.len());
        buf[..len].copy_from_slice(&path.as_bytes()[..len]);

        Ok(len)
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

        if let Operation::Trace = handle.info.operation {
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
        Ok(0)
    }
}
