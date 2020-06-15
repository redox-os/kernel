use crate::{
    arch::paging::VirtualAddress,
    context::{self, Context, ContextId, Status},
    ptrace,
    scheme::{AtomicSchemeId, SchemeId},
    syscall::{
        data::{FloatRegisters, IntRegisters, PtraceEvent},
        error::*,
        flag::*,
        scheme::Scheme,
        self,
        validate,
    },
};

use alloc::{
    collections::BTreeMap,
    vec::Vec
};
use core::{
    cmp,
    mem,
    slice,
    sync::atomic::{AtomicUsize, Ordering},
};
use spin::RwLock;

fn with_context<F, T>(pid: ContextId, callback: F) -> Result<T>
    where F: FnOnce(&Context) -> Result<T>
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
    where F: FnOnce(&mut Context) -> Result<T>
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
    Int
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Operation {
    Memory,
    Regs(RegsKind),
    Trace,
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
enum OperationData {
    Memory(MemData),
    Trace(TraceData),
    Other,
}
impl OperationData {
    fn default_for(op: Operation) -> OperationData {
        match op {
            Operation::Memory => OperationData::Memory(MemData::default()),
            Operation::Trace => OperationData::Trace(TraceData::default()),
            _ => OperationData::Other,
        }
    }
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
}

impl ProcScheme {
    pub fn new(scheme_id: SchemeId) -> Self {
        PROC_SCHEME_ID.store(scheme_id, Ordering::SeqCst);

        Self {
            next_id: AtomicUsize::new(0),
            handles: RwLock::new(BTreeMap::new()),
        }
    }
}

impl Scheme for ProcScheme {
    fn open(&self, path: &[u8], flags: usize, uid: u32, gid: u32) -> Result<usize> {
        let path = core::str::from_utf8(path).map_err(|_| Error::new(EINVAL))?;
        let mut parts = path.splitn(2, '/');
        let pid = parts.next()
            .and_then(|s| s.parse().ok())
            .map(ContextId::from)
            .ok_or(Error::new(EINVAL))?;

        let operation = match parts.next() {
            Some("mem") => Operation::Memory,
            Some("regs/float") => Operation::Regs(RegsKind::Float),
            Some("regs/int") => Operation::Regs(RegsKind::Int),
            Some("trace") => Operation::Trace,
            _ => return Err(Error::new(EINVAL))
        };

        let contexts = context::contexts();
        let target = contexts.get(pid).ok_or(Error::new(ESRCH))?;

        {
            let target = target.read();

            if let Status::Exited(_) = target.status {
                return Err(Error::new(ESRCH));
            }

            // Unless root, check security
            if uid != 0 && gid != 0 {
                let current = contexts.current().ok_or(Error::new(ESRCH))?;
                let current = current.read();

                // Do we own the process?
                if uid != target.euid && gid != target.egid {
                    return Err(Error::new(EPERM));
                }

                // Is it a subprocess of us? In the future, a capability could
                // bypass this check.
                match contexts.anchestors(target.ppid).find(|&(id, _context)| id == current.id) {
                    Some((id, context)) => {
                        // Paranoid sanity check, as ptrace security holes
                        // wouldn't be fun
                        assert_eq!(id, current.id);
                        assert_eq!(id, context.read().id);
                    },
                    None => return Err(Error::new(EPERM))
                }
            }
        }

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
            data: OperationData::default_for(operation),
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

        let mut path = format!("{}/", info.pid.into()).into_bytes();
        path.extend_from_slice(buf);

        let (uid, gid) = {
            let contexts = context::contexts();
            let context = contexts.current().ok_or(Error::new(ESRCH))?;
            let context = context.read();
            (context.euid, context.egid)
        };

        self.open(&path, info.flags, uid, gid)
    }

    fn seek(&self, id: usize, pos: usize, whence: usize) -> Result<usize> {
        let mut handles = self.handles.write();
        let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;
        let mut memory = handle.data.mem_data().ok_or(Error::new(EBADF))?;

        let value = match whence {
            SEEK_SET => pos,
            SEEK_CUR => cmp::max(0, memory.offset.get() as isize + pos as isize) as usize,
            SEEK_END => cmp::max(0, isize::max_value() + pos as isize) as usize,
            _ => return Err(Error::new(EBADF))
        };
        memory.offset = VirtualAddress::new(value);
        Ok(value)
    }

    fn read(&self, id: usize, buf: &mut [u8]) -> Result<usize> {
        // Don't hold a global lock during the context switch later on
        let info = {
            let handles = self.handles.read();
            let handle = handles.get(&id).ok_or(Error::new(EBADF))?;
            handle.info
        };

        match info.operation {
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

                data.offset = VirtualAddress::new(data.offset.get() + buf.len());
                Ok(buf.len())
            },
            Operation::Regs(kind) => {
                union Output {
                    float: FloatRegisters,
                    int: IntRegisters
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
                            println!("{}:{}: Couldn't read registers from stopped process", file!(), line!());
                            Err(Error::new(ENOTRECOVERABLE))
                        },
                        Some(stack) => {
                            let mut regs = IntRegisters::default();
                            stack.save(&mut regs);
                            Ok((Output { int: regs }, mem::size_of::<IntRegisters>()))
                        }
                    })?
                };

                let bytes = unsafe {
                    slice::from_raw_parts(&output as *const _ as *const u8, mem::size_of::<Output>())
                };
                let len = cmp::min(buf.len(), size);
                buf[..len].copy_from_slice(&bytes[..len]);

                Ok(len)
            },
            Operation::Trace => {
                let slice = unsafe {
                    slice::from_raw_parts_mut(
                        buf.as_mut_ptr() as *mut PtraceEvent,
                        buf.len() / mem::size_of::<PtraceEvent>()
                    )
                };
                let read = ptrace::recv_events(info.pid, slice).unwrap_or(0);

                // Won't context switch, don't worry about the locks
                let mut handles = self.handles.write();
                let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;
                let data = handle.data.trace_data().expect("operations can't change");

                for event in &slice[..read] {
                    if event.cause == PTRACE_EVENT_CLONE {
                        data.clones.push(ContextId::from(event.a));
                    }
                }

                Ok(read * mem::size_of::<PtraceEvent>())
            }
        }
    }

    fn write(&self, id: usize, buf: &[u8]) -> Result<usize> {
        // Don't hold a global lock during the context switch later on
        let info = {
            let mut handles = self.handles.write();
            let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;
            handle.continue_ignored_children();
            handle.info
        };

        match info.operation {
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

                data.offset = VirtualAddress::new(data.offset.get() + buf.len());
                Ok(buf.len())
            },
            Operation::Regs(kind) => match kind {
                RegsKind::Float => {
                    if buf.len() < mem::size_of::<FloatRegisters>() {
                        return Ok(0);
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

                let should_continue = !op.contains(PTRACE_FLAG_WAIT) || op.intersects(PTRACE_STOP_MASK);

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

                // Set next breakpoint, and potentially restart tracee
                if op.intersects(PTRACE_STOP_MASK) {
                    ptrace::set_breakpoint(info.pid, op, should_continue);
                } else if should_continue {
                    ptrace::clear_breakpoint(info.pid);
                }

                if should_continue {
                    // disable the ptrace_stop flag, which is used in some cases
                    with_context_mut(info.pid, |context| {
                        context.ptrace_stop = false;
                        Ok(())
                    })?;

                    // and notify the tracee's WaitCondition, which is used in other cases
                    ptrace::notify(info.pid);
                }

                // And await the tracee, if requested to
                if op.contains(PTRACE_FLAG_WAIT) || info.flags & O_NONBLOCK != O_NONBLOCK {
                    ptrace::wait(info.pid)?;
                }

                Ok(mem::size_of::<u64>())
            }
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

        Ok(ptrace::session_fevent_flags(handle.info.pid).expect("proc (fevent): invalid session"))
    }

    fn fpath(&self, id: usize, buf: &mut [u8]) -> Result<usize> {
        let handles = self.handles.read();
        let handle = handles.get(&id).ok_or(Error::new(EBADF))?;

        let path = format!("proc:{}/{}", handle.info.pid.into(), match handle.info.operation {
            Operation::Memory => "mem",
            Operation::Regs(RegsKind::Float) => "regs/float",
            Operation::Regs(RegsKind::Int) => "regs/int",
            Operation::Trace => "trace"
        });

        let len = cmp::min(path.len(), buf.len());
        buf[..len].copy_from_slice(&path.as_bytes()[..len]);

        Ok(len)
    }

    fn close(&self, id: usize) -> Result<usize> {
        let mut handle = self.handles.write().remove(&id).ok_or(Error::new(EBADF))?;
        handle.continue_ignored_children();

        if let Operation::Trace = handle.info.operation {
            ptrace::close_session(handle.info.pid);

            if handle.info.flags & O_EXCL == O_EXCL {
                syscall::kill(handle.info.pid, SIGKILL)?;
            } else {
                let contexts = context::contexts();
                if let Some(context) = contexts.get(handle.info.pid) {
                    let mut context = context.write();
                    context.ptrace_stop = false;
                }
            }
        }
        Ok(0)
    }
}
