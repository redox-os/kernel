use crate::{
    arch::paging::VirtualAddress,
    context::{self, ContextId, Status},
    ptrace,
    scheme::{ATOMIC_SCHEMEID_INIT, AtomicSchemeId, SchemeId},
    syscall::validate
};

use alloc::{
    collections::BTreeMap,
    sync::Arc
};
use core::{
    cmp,
    mem,
    slice,
    sync::atomic::{AtomicUsize, Ordering}
};
use spin::{Mutex, RwLock};
use syscall::{
    data::{FloatRegisters, IntRegisters, PtraceEvent},
    error::*,
    flag::*,
    scheme::Scheme
};

#[derive(Clone, Copy)]
enum RegsKind {
    Float,
    Int
}
#[derive(Clone, Copy)]
enum Operation {
    Memory(VirtualAddress),
    Regs(RegsKind),
    Trace {
        new_child: Option<ContextId>
    }
}

#[derive(Clone, Copy)]
struct Handle {
    flags: usize,
    pid: ContextId,
    operation: Operation
}
impl Handle {
    fn continue_ignored_child(&mut self) -> Option<()> {
        let pid = match self.operation {
            Operation::Trace { ref mut new_child } => new_child.take()?,
            _ => return None
        };
        if ptrace::is_traced(pid) {
            return None;
        }
        let contexts = context::contexts();
        let context = contexts.get(pid)?;
        let mut context = context.write();
        context.ptrace_stop = false;
        Some(())
    }
}

pub static PROC_SCHEME_ID: AtomicSchemeId = ATOMIC_SCHEMEID_INIT;

pub struct ProcScheme {
    next_id: AtomicUsize,
    handles: RwLock<BTreeMap<usize, Arc<Mutex<Handle>>>>
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
            Some("mem") => Operation::Memory(VirtualAddress::new(0)),
            Some("regs/float") => Operation::Regs(RegsKind::Float),
            Some("regs/int") => Operation::Regs(RegsKind::Int),
            Some("trace") => Operation::Trace {
                new_child: None
            },
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

                // Is it a subprocess of us? In the future, a capability
                // could bypass this check.
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
                // There is no good way to handle id being occupied
                // for nothing here, is there?
                return Err(Error::new(EBUSY));
            }

            let mut target = target.write();
            target.ptrace_stop = true;
        }

        self.handles.write().insert(id, Arc::new(Mutex::new(Handle {
            flags,
            pid,
            operation
        })));
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
        let handle = {
            let handles = self.handles.read();
            let handle = handles.get(&old_id).ok_or(Error::new(EBADF))?;
            let handle = handle.lock();
            *handle
        };

        let mut path = format!("{}/", handle.pid.into()).into_bytes();
        path.extend_from_slice(buf);

        let (uid, gid) = {
            let contexts = context::contexts();
            let context = contexts.current().ok_or(Error::new(ESRCH))?;
            let context = context.read();
            (context.euid, context.egid)
        };

        self.open(&path, handle.flags, uid, gid)
    }

    fn seek(&self, id: usize, pos: usize, whence: usize) -> Result<usize> {
        let handles = self.handles.read();
        let handle = handles.get(&id).ok_or(Error::new(EBADF))?;
        let mut handle = handle.lock();

        match handle.operation {
            Operation::Memory(ref mut offset) => Ok({
                *offset = VirtualAddress::new(match whence {
                    SEEK_SET => pos,
                    SEEK_CUR => cmp::max(0, offset.get() as isize + pos as isize) as usize,
                    SEEK_END => cmp::max(0, isize::max_value() + pos as isize) as usize,
                    _ => return Err(Error::new(EBADF))
                });
                offset.get()
            }),
            _ => Err(Error::new(EBADF))
        }
    }

    fn read(&self, id: usize, buf: &mut [u8]) -> Result<usize> {
        // Don't hold a global lock during the context switch later on
        let handle = {
            let handles = self.handles.read();
            Arc::clone(handles.get(&id).ok_or(Error::new(EBADF))?)
        };
        // TODO: Make sure handle can't deadlock
        let mut handle = handle.lock();
        let pid = handle.pid;

        match handle.operation {
            Operation::Memory(ref mut offset) => {
                let contexts = context::contexts();
                let context = contexts.get(pid).ok_or(Error::new(ESRCH))?;
                let context = context.read();

                ptrace::with_context_memory(&context, *offset, buf.len(), |ptr| {
                    buf.copy_from_slice(validate::validate_slice(ptr, buf.len())?);
                    Ok(())
                })?;

                *offset = VirtualAddress::new(offset.get() + buf.len());
                Ok(buf.len())
            },
            Operation::Regs(kind) => {
                union Output {
                    float: FloatRegisters,
                    int: IntRegisters
                }
                let mut first = true;
                let (output, size) = loop {
                    if !first {
                        // We've tried this before, so lets wait before retrying
                        unsafe { context::switch(); }
                    }
                    first = false;

                    let contexts = context::contexts();
                    let context = contexts.get(handle.pid).ok_or(Error::new(ESRCH))?;
                    let context = context.read();

                    break match kind {
                        RegsKind::Float => {
                            // NOTE: The kernel will never touch floats

                            // In the rare case of not having floating
                            // point registers uninitiated, return
                            // empty everything.
                            let fx = context.arch.get_fx_regs().unwrap_or_default();
                            (Output { float: fx }, mem::size_of::<FloatRegisters>())
                        },
                        RegsKind::Int => match unsafe { ptrace::regs_for(&context) } {
                            None => {
                                // Another CPU is running this process, wait until it's stopped.
                                continue;
                            },
                            Some(stack) => {
                                let mut regs = IntRegisters::default();

                                stack.save(&mut regs);

                                (Output { int: regs }, mem::size_of::<IntRegisters>())
                            }
                        }
                    };
                };

                let bytes = unsafe {
                    slice::from_raw_parts(&output as *const _ as *const u8, mem::size_of::<Output>())
                };
                let len = cmp::min(buf.len(), size);
                buf[..len].copy_from_slice(&bytes[..len]);

                Ok(len)
            },
            Operation::Trace { .. } => {
                let read = ptrace::recv_events(handle.pid, unsafe {
                    slice::from_raw_parts_mut(
                        buf.as_mut_ptr() as *mut PtraceEvent,
                        buf.len() / mem::size_of::<PtraceEvent>()
                    )
                }).unwrap_or(0);

                Ok(read * mem::size_of::<PtraceEvent>())
            }
        }
    }

    fn write(&self, id: usize, buf: &[u8]) -> Result<usize> {
        // Don't hold a global lock during the context switch later on
        let handle = {
            let handles = self.handles.read();
            Arc::clone(handles.get(&id).ok_or(Error::new(EBADF))?)
        };
        let mut handle = handle.lock();
        handle.continue_ignored_child();

        // Some operations borrow Operation:: mutably
        let pid = handle.pid;
        let flags = handle.flags;

        let mut first = true;
        match handle.operation {
            Operation::Memory(ref mut offset) => {
                let contexts = context::contexts();
                let context = contexts.get(pid).ok_or(Error::new(ESRCH))?;
                let context = context.read();

                ptrace::with_context_memory(&context, *offset, buf.len(), |ptr| {
                    validate::validate_slice_mut(ptr, buf.len())?.copy_from_slice(buf);
                    Ok(())
                })?;

                *offset = VirtualAddress::new(offset.get() + buf.len());
                Ok(buf.len())
            },
            Operation::Regs(kind) => loop {
                if !first {
                    // We've tried this before, so lets wait before retrying
                    unsafe { context::switch(); }
                }
                first = false;

                let contexts = context::contexts();
                let context = contexts.get(handle.pid).ok_or(Error::new(ESRCH))?;
                let mut context = context.write();

                break match kind {
                    RegsKind::Float => {
                        if buf.len() < mem::size_of::<FloatRegisters>() {
                            return Ok(0);
                        }
                        let regs = unsafe {
                            *(buf as *const _ as *const FloatRegisters)
                        };

                        // NOTE: The kernel will never touch floats

                        // Ignore the rare case of floating point
                        // registers being uninitiated
                        let _ = context.arch.set_fx_regs(regs);

                        Ok(mem::size_of::<FloatRegisters>())
                    },
                    RegsKind::Int => match unsafe { ptrace::regs_for_mut(&mut context) } {
                        None => {
                            // Another CPU is running this process, wait until it's stopped.
                            continue;
                        },
                        Some(stack) => {
                            if buf.len() < mem::size_of::<IntRegisters>() {
                                return Ok(0);
                            }
                            let regs = unsafe {
                                *(buf as *const _ as *const IntRegisters)
                            };

                            stack.load(&regs);

                            Ok(mem::size_of::<IntRegisters>())
                        }
                    }
                };
            },
            Operation::Trace { ref mut new_child } => {
                if buf.len() < 1 {
                    return Ok(0);
                }
                let op = buf[0];

                let mut blocking = flags & O_NONBLOCK != O_NONBLOCK;
                let mut singlestep = false;

                match op & PTRACE_OPERATIONMASK {
                    PTRACE_CONT => { ptrace::cont(pid); },
                    PTRACE_SYSCALL | PTRACE_SINGLESTEP => { // <- not a bitwise OR
                        singlestep = op & PTRACE_OPERATIONMASK == PTRACE_SINGLESTEP;
                        ptrace::set_breakpoint(pid, op);
                    },
                    PTRACE_WAIT => blocking = true,
                    _ => return Err(Error::new(EINVAL))
                }

                let mut first = true;
                loop {
                    if !first {
                        // We've tried this before, so lets wait before retrying
                        unsafe { context::switch(); }
                    }
                    first = false;

                    let contexts = context::contexts();
                    let context = contexts.get(pid).ok_or(Error::new(ESRCH))?;
                    let mut context = context.write();
                    if let Status::Exited(_) = context.status {
                        return Err(Error::new(ESRCH));
                    }

                    if singlestep {
                        match unsafe { ptrace::regs_for_mut(&mut context) } {
                            None => continue,
                            Some(stack) => stack.set_singlestep(true)
                        }
                    }

                    context.ptrace_stop = false;
                    break;
                }

                if blocking {
                    if let Some(event) = ptrace::wait(pid)? {
                        if event.tag == PTRACE_EVENT_CLONE {
                            *new_child = Some(ContextId::from(unsafe { event.data.clone }));
                        }
                        return Ok(0);
                    }
                }

                Ok(1)
            }
        }
    }

    fn fcntl(&self, id: usize, cmd: usize, arg: usize) -> Result<usize> {
        let handles = self.handles.read();
        let handle = handles.get(&id).ok_or(Error::new(EBADF))?;
        let mut handle = handle.lock();

        match cmd {
            F_SETFL => { handle.flags = arg; Ok(0) },
            F_GETFL => return Ok(handle.flags),
            _ => return Err(Error::new(EINVAL))
        }
    }

    fn fevent(&self, id: usize, _flags: usize) -> Result<usize> {
        let handles = self.handles.read();
        let handle = handles.get(&id).ok_or(Error::new(EBADF))?;
        let handle = handle.lock();

        Ok(ptrace::session_fevent_flags(handle.pid).expect("proc (fevent): invalid session"))
    }

    fn fpath(&self, id: usize, buf: &mut [u8]) -> Result<usize> {
        let handles = self.handles.read();
        let handle = handles.get(&id).ok_or(Error::new(EBADF))?;
        let handle = handle.lock();

        let path = format!("proc:{}/{}", handle.pid.into(), match handle.operation {
            Operation::Memory(_) => "mem",
            Operation::Regs(RegsKind::Float) => "regs/float",
            Operation::Regs(RegsKind::Int) => "regs/int",
            Operation::Trace { .. } => "trace"
        });

        let len = cmp::min(path.len(), buf.len());
        buf[..len].copy_from_slice(&path.as_bytes()[..len]);

        Ok(len)
    }

    fn close(&self, id: usize) -> Result<usize> {
        let handle = self.handles.write().remove(&id).ok_or(Error::new(EBADF))?;
        let mut handle = handle.lock();
        handle.continue_ignored_child();

        if let Operation::Trace { .. } = handle.operation {
            ptrace::close_session(handle.pid);
        }

        let contexts = context::contexts();
        if let Some(context) = contexts.get(handle.pid) {
            let mut context = context.write();
            context.ptrace_stop = false;
        }
        Ok(0)
    }
}
