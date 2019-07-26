use crate::{
    arch::paging::VirtualAddress,
    context::{self, Context, ContextId, Status},
    ptrace,
    scheme::{ATOMIC_SCHEMEID_INIT, AtomicSchemeId, SchemeId},
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
    sync::Arc,
    vec::Vec
};
use core::{
    cmp,
    mem,
    slice,
    sync::atomic::{AtomicUsize, Ordering},
};
use spin::{Mutex, RwLock};

#[derive(Clone, Copy)]
enum RegsKind {
    Float,
    Int
}
#[derive(Clone)]
enum Operation {
    Memory(VirtualAddress),
    Regs(RegsKind),
    Trace {
        clones: Vec<ContextId>
    }
}

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
fn try_stop_context<F, T>(pid: ContextId, restart_after: bool, mut callback: F) -> Result<T>
    where F: FnMut(&mut Context) -> Result<T>
{
    let mut first = true;
    let mut was_stopped = false; // will never be read

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

        // Stop the process until we've done our thing
        if first {
            was_stopped = context.ptrace_stop;
        }
        context.ptrace_stop = true;

        if context.running {
            // Process still running, wait until it has stopped
            continue;
        }

        let ret = callback(&mut context);

        context.ptrace_stop = restart_after && was_stopped;

        break ret;
    }
}

#[derive(Clone, Copy)]
struct Info {
    pid: ContextId,
    flags: usize,
}
struct Handle {
    info: Info,
    operation: Operation
}
impl Handle {
    fn continue_ignored_children(&mut self) -> Option<()> {
        let clones = match self.operation {
            Operation::Trace { ref mut clones } => clones,
            _ => return None
        };
        let contexts = context::contexts();
        for pid in clones.drain(..) {
            if ptrace::is_traced(pid) {
                return None;
            }
            if let Some(context) = contexts.get(pid) {
                let mut context = context.write();
                context.ptrace_stop = false;
            }
        }
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
                clones: Vec::new()
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

            if flags & O_TRUNC == O_TRUNC {
                let mut target = target.write();
                target.ptrace_stop = true;
            }
        }

        self.handles.write().insert(id, Arc::new(Mutex::new(Handle {
            info: Info {
                flags,
                pid,
            },
            operation,
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
        let info = {
            let handles = self.handles.read();
            let handle = handles.get(&old_id).ok_or(Error::new(EBADF))?;
            let handle = handle.lock();
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
        let mut handle = handle.lock();
        let info = handle.info;

        match handle.operation {
            Operation::Memory(ref mut offset) => {
                let contexts = context::contexts();
                let context = contexts.get(info.pid).ok_or(Error::new(ESRCH))?;
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

                let (output, size) = match kind {
                    RegsKind::Float => with_context(info.pid, |context| {
                        // NOTE: The kernel will never touch floats

                        // In the rare case of not having floating
                        // point registers uninitiated, return
                        // empty everything.
                        let fx = context.arch.get_fx_regs().unwrap_or_default();
                        Ok((Output { float: fx }, mem::size_of::<FloatRegisters>()))
                    })?,
                    RegsKind::Int => try_stop_context(info.pid, true, |context| match unsafe { ptrace::regs_for(&context) } {
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
            Operation::Trace { .. } => {
                let read = ptrace::recv_events(info.pid, unsafe {
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
        let info = handle.info;
        handle.continue_ignored_children();

        match handle.operation {
            Operation::Memory(ref mut offset) => {
                let contexts = context::contexts();
                let context = contexts.get(info.pid).ok_or(Error::new(ESRCH))?;
                let context = context.read();

                ptrace::with_context_memory(&context, *offset, buf.len(), |ptr| {
                    validate::validate_slice_mut(ptr, buf.len())?.copy_from_slice(buf);
                    Ok(())
                })?;

                *offset = VirtualAddress::new(offset.get() + buf.len());
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

                    try_stop_context(info.pid, true, |context| match unsafe { ptrace::regs_for_mut(context) } {
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
            Operation::Trace { ref mut clones } => {
                if buf.len() < mem::size_of::<u64>() {
                    return Ok(0);
                }

                let mut bytes = [0; mem::size_of::<u64>()];
                let len = bytes.len();
                bytes.copy_from_slice(&buf[0..len]);
                let op = u64::from_ne_bytes(bytes);

                if op & PTRACE_FLAG_WAIT != PTRACE_FLAG_WAIT || op & PTRACE_STOP_MASK != 0 {
                    ptrace::cont(info.pid);
                }
                if op & PTRACE_STOP_MASK != 0 {
                    ptrace::set_breakpoint(info.pid, op);
                }

                if op & PTRACE_STOP_SINGLESTEP == PTRACE_STOP_SINGLESTEP {
                    // try_stop_context with `false` will
                    // automatically disable ptrace_stop
                    try_stop_context(info.pid, false, |context| {
                        match unsafe { ptrace::regs_for_mut(context) } {
                            // If another CPU is running this process,
                            // await for it to be stopped and in such
                            // a way the registers can be read!
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
                } else {
                    // disable ptrace stop
                    with_context_mut(info.pid, |context| {
                        context.ptrace_stop = false;
                        Ok(())
                    })?;
                }

                if op & PTRACE_FLAG_WAIT == PTRACE_FLAG_WAIT || info.flags & O_NONBLOCK != O_NONBLOCK {
                    if let Some(event) = ptrace::wait(info.pid)? {
                        if event.cause == PTRACE_EVENT_CLONE {
                            clones.push(ContextId::from(event.a));
                        }
                    }
                }

                Ok(mem::size_of::<u64>())
            }
        }
    }

    fn fcntl(&self, id: usize, cmd: usize, arg: usize) -> Result<usize> {
        let handles = self.handles.read();
        let handle = handles.get(&id).ok_or(Error::new(EBADF))?;
        let mut handle = handle.lock();

        match cmd {
            F_SETFL => { handle.info.flags = arg; Ok(0) },
            F_GETFL => return Ok(handle.info.flags),
            _ => return Err(Error::new(EINVAL))
        }
    }

    fn fevent(&self, id: usize, _flags: usize) -> Result<usize> {
        let handles = self.handles.read();
        let handle = handles.get(&id).ok_or(Error::new(EBADF))?;
        let handle = handle.lock();

        Ok(ptrace::session_fevent_flags(handle.info.pid).expect("proc (fevent): invalid session"))
    }

    fn fpath(&self, id: usize, buf: &mut [u8]) -> Result<usize> {
        let handles = self.handles.read();
        let handle = handles.get(&id).ok_or(Error::new(EBADF))?;
        let handle = handle.lock();

        let path = format!("proc:{}/{}", handle.info.pid.into(), match handle.operation {
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
        handle.continue_ignored_children();

        if let Operation::Trace { .. } = handle.operation {
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
