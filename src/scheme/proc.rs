use crate::{
    context::{self, ContextId, Status},
    ptrace
};

use alloc::collections::{BTreeMap, BTreeSet};
use core::{
    cmp,
    mem,
    slice,
    sync::atomic::{AtomicUsize, Ordering}
};
use spin::{Mutex, RwLock};
use syscall::{
    data::{IntRegisters, FloatRegisters},
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
    Memory,
    Regs(RegsKind),
    Trace
}

#[derive(Clone, Copy)]
struct Handle {
    flags: usize,
    pid: ContextId,
    operation: Operation
}

pub struct ProcScheme {
    next_id: AtomicUsize,
    handles: RwLock<BTreeMap<usize, Handle>>,
    traced: Mutex<BTreeSet<ContextId>>
}

impl ProcScheme {
    pub fn new() -> Self {
        Self {
            next_id: AtomicUsize::new(0),
            handles: RwLock::new(BTreeMap::new()),
            traced: Mutex::new(BTreeSet::new())
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
        let context = contexts.get(pid).ok_or(Error::new(ESRCH))?;

        {
            // TODO: Put better security here?

            let context = context.read();
            if uid != 0 && gid != 0
            && uid != context.euid && gid != context.egid {
                return Err(Error::new(EPERM));
            }
        }

        if let Operation::Trace = operation {
            let mut traced = self.traced.lock();

            if traced.contains(&pid) {
                return Err(Error::new(EBUSY));
            }
            traced.insert(pid);

            let mut context = context.write();
            context.ptrace_stop = true;
        }

        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        self.handles.write().insert(id, Handle {
            flags,
            pid,
            operation
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
        let handle = {
            let handles = self.handles.read();
            *handles.get(&old_id).ok_or(Error::new(EBADF))?
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

    fn read(&self, id: usize, buf: &mut [u8]) -> Result<usize> {
        // Can't hold locks during the context switch later when
        // waiting for a process to stop running.
        let handle = {
            let handles = self.handles.read();
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        match handle.operation {
            Operation::Memory => {
                // let contexts = context::contexts();
                // let context = contexts.get(handle.pid).ok_or(Error::new(ESRCH))?;
                // let context = context.read();

                // for grant in &*context.grants.lock() {
                //     println!("Grant: {} -> {}", grant.start.get(), grant.size);
                // }
                // unimplemented!();
                return Err(Error::new(EBADF));
            },
            Operation::Regs(kind) => {
                union Output {
                    _float: FloatRegisters,
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
                            // TODO!!
                            // (Output { float: FloatRegisters::default() }, mem::size_of::<FloatRegisters>())
                            return Err(Error::new(EBADF));
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
            Operation::Trace => Err(Error::new(EBADF))
        }
    }

    fn write(&self, id: usize, buf: &[u8]) -> Result<usize> {
        // Can't hold locks during the context switch later when
        // waiting for a process to stop running.
        let handle = {
            let handles = self.handles.read();
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        let mut first = true;
        match handle.operation {
            Operation::Memory => {
                // unimplemented!()
                return Err(Error::new(EBADF));
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
                        // TODO!!
                        unimplemented!();
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
            Operation::Trace => {
                if buf.len() < 1 {
                    return Ok(0);
                }
                let op = buf[0];
                let sysemu = op & PTRACE_SYSEMU == PTRACE_SYSEMU;

                let mut blocking = handle.flags & O_NONBLOCK != O_NONBLOCK;
                let mut wait_breakpoint = false;
                let mut singlestep = false;

                match op & PTRACE_OPERATIONMASK {
                    PTRACE_CONT => { ptrace::cont(handle.pid); },
                    PTRACE_SYSCALL | PTRACE_SINGLESTEP => { // <- not a bitwise OR
                        singlestep = op & PTRACE_OPERATIONMASK == PTRACE_SINGLESTEP;
                        ptrace::set_breakpoint(handle.pid, sysemu, singlestep);
                        wait_breakpoint = true;
                    },
                    PTRACE_WAIT => {
                        wait_breakpoint = true;
                        blocking = true;
                    },
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
                    let context = contexts.get(handle.pid).ok_or(Error::new(ESRCH))?;
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

                if wait_breakpoint && blocking {
                    ptrace::wait_breakpoint(handle.pid)?;
                }

                Ok(1)
            }
        }
    }

    fn fcntl(&self, id: usize, cmd: usize, arg: usize) -> Result<usize> {
        let mut handles = self.handles.write();
        let mut handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;

        match cmd {
            F_SETFL => { handle.flags = arg; Ok(0) },
            F_GETFL => return Ok(handle.flags),
            _ => return Err(Error::new(EINVAL))
        }
    }

    fn fpath(&self, id: usize, buf: &mut [u8]) -> Result<usize> {
        let handles = self.handles.read();
        let handle = handles.get(&id).ok_or(Error::new(EBADF))?;

        let path = format!("proc:{}/{}", handle.pid.into(), match handle.operation {
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
        let handle = self.handles.write().remove(&id).ok_or(Error::new(EBADF))?;
        ptrace::cont(handle.pid);

        let contexts = context::contexts();
        if let Some(context) = contexts.get(handle.pid) {
            let mut context = context.write();
            context.ptrace_stop = false;
        }
        Ok(0)
    }
}
