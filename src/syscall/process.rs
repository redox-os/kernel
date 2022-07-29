use alloc::{
    sync::Arc,
    vec::Vec,
};
use core::mem;

use spin::{RwLock, RwLockWriteGuard};

use crate::context::{Context, ContextId, memory::AddrSpace, WaitpidKey};

use crate::Bootstrap;
use crate::context;
use crate::interrupt;
use crate::paging::mapper::{InactiveFlusher, PageFlushAll};
use crate::paging::{Page, PageFlags, VirtualAddress, PAGE_SIZE};
use crate::ptrace;
use crate::start::usermode;
use crate::syscall::data::SigAction;
use crate::syscall::error::*;
use crate::syscall::flag::{wifcontinued, wifstopped, MapFlags,
    PTRACE_STOP_EXIT, SIG_BLOCK, SIG_SETMASK, SIG_UNBLOCK,
    SIGCONT, SIGTERM, WaitFlags, WCONTINUED, WNOHANG, WUNTRACED};
use crate::syscall::ptrace_event;
use crate::syscall::validate::validate_slice_mut;

fn empty<'lock>(context_lock: &'lock RwLock<Context>, mut context: RwLockWriteGuard<'lock, Context>, reaping: bool) -> RwLockWriteGuard<'lock, Context> {
    // NOTE: If we do not replace the grants `Arc`, then a strange situation can appear where the
    // main thread and another thread exit simultaneously before either one is reaped. If that
    // happens, then the last context that runs exit will think that there is still are still
    // remaining references to the grants, where there are in fact none. However, if either one is
    // reaped before, then that reference will disappear, and no leak will occur.
    //
    // By removing the reference to the address space when the context will no longer be used, this
    // problem will never occur.
    let addr_space_arc = match context.addr_space.take() {
        Some(a) => a,
        None => return context,
    };

    if let Ok(mut addr_space) = Arc::try_unwrap(addr_space_arc).map(RwLock::into_inner) {
        let mapper = &mut addr_space.table.utable;

        for grant in addr_space.grants.into_iter() {
            let unmap_result = if reaping {
                log::error!("{}: {}: Grant should not exist: {:?}", context.id.into(), *context.name.read(), grant);

                grant.unmap(mapper, &mut InactiveFlusher::new())
            } else {
                grant.unmap(mapper, PageFlushAll::new())
            };

            if unmap_result.file_desc.is_some() {
                drop(context);

                drop(unmap_result);

                context = context_lock.write();
            }
        }
    }
    context
}

pub fn exit(status: usize) -> ! {
    ptrace::breakpoint_callback(PTRACE_STOP_EXIT, Some(ptrace_event!(PTRACE_STOP_EXIT, status)));

    {
        let context_lock = context::current().expect("exit failed to find context");

        let mut close_files;
        let pid = {
            let mut context = context_lock.write();
            close_files = Arc::try_unwrap(mem::take(&mut context.files)).map_or_else(|_| Vec::new(), RwLock::into_inner);
            context.id
        };

        // TODO: Find a better way to implement this, perhaps when the init process calls exit.
        if pid == ContextId::from(1) {
            println!("Main kernel thread exited with status {:X}", status);

            extern {
                fn kreset() -> !;
                fn kstop() -> !;
            }

            if status == SIGTERM {
                unsafe { kreset(); }
            } else {
                unsafe { kstop(); }
            }
        }

        // Files must be closed while context is valid so that messages can be passed
        for (_fd, file_opt) in close_files.drain(..).enumerate() {
            if let Some(file) = file_opt {
                let _ = file.close();
            }
        }

        // PGID and PPID must be grabbed after close, as context switches could change PGID or PPID if parent exits
        let (pgid, ppid) = {
            let context = context_lock.read();
            (context.pgid, context.ppid)
        };

        // Transfer child processes to parent
        {
            let contexts = context::contexts();
            for (_id, context_lock) in contexts.iter() {
                let mut context = context_lock.write();
                if context.ppid == pid {
                    context.ppid = ppid;
                    context.vfork = false;
                }
            }
        }

        let (vfork, children) = {
            let mut context = context_lock.write();

            context = empty(&context_lock, context, false);

            let vfork = context.vfork;
            context.vfork = false;

            context.status = context::Status::Exited(status);

            let children = context.waitpid.receive_all();

            (vfork, children)
        };

        {
            let contexts = context::contexts();
            if let Some(parent_lock) = contexts.get(ppid) {
                let waitpid = {
                    let mut parent = parent_lock.write();
                    if vfork && ! parent.unblock() {
                        println!("{}: {} not blocked for exit vfork unblock", pid.into(), ppid.into());
                    }
                    Arc::clone(&parent.waitpid)
                };

                for (c_pid, c_status) in children {
                    waitpid.send(c_pid, c_status);
                }

                waitpid.send(WaitpidKey {
                    pid: Some(pid),
                    pgid: Some(pgid)
                }, (pid, status));
            } else {
                println!("{}: {} not found for exit vfork unblock", pid.into(), ppid.into());
            }
        }

        // Alert any tracers waiting of this process
        ptrace::close_tracee(pid);
    }

    let _ = unsafe { context::switch() };

    unreachable!();
}

pub fn getpid() -> Result<ContextId> {
    let contexts = context::contexts();
    let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
    let context = context_lock.read();
    Ok(context.id)
}

pub fn getpgid(pid: ContextId) -> Result<ContextId> {
    let contexts = context::contexts();
    let context_lock = if pid.into() == 0 {
        contexts.current().ok_or(Error::new(ESRCH))?
    } else {
        contexts.get(pid).ok_or(Error::new(ESRCH))?
    };
    let context = context_lock.read();
    Ok(context.pgid)
}

pub fn getppid() -> Result<ContextId> {
    let contexts = context::contexts();
    let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
    let context = context_lock.read();
    Ok(context.ppid)
}

pub fn kill(pid: ContextId, sig: usize) -> Result<usize> {
    let (ruid, euid, current_pgid) = {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();
        (context.ruid, context.euid, context.pgid)
    };

    if sig < 0x7F {
        let mut found = 0;
        let mut sent = 0;

        {
            let contexts = context::contexts();

            let send = |context: &mut context::Context| -> bool {
                if euid == 0
                || euid == context.ruid
                || ruid == context.ruid
                {
                    // If sig = 0, test that process exists and can be
                    // signalled, but don't send any signal.
                    if sig != 0 {
                        //TODO: sigprocmask
                        context.pending.push_back(sig as u8);
                        // Convert stopped processes to blocked if sending SIGCONT
                        if sig == SIGCONT {
                            if let context::Status::Stopped(_sig) = context.status {
                                context.status = context::Status::Blocked;
                            }
                        }
                    }
                    true
                } else {
                    false
                }
            };

            if pid.into() as isize > 0 {
                // Send to a single process
                if let Some(context_lock) = contexts.get(pid) {
                    let mut context = context_lock.write();

                    found += 1;
                    if send(&mut context) {
                        sent += 1;
                    }
                }
            } else if pid.into() as isize == -1 {
                // Send to every process with permission, except for init
                for (_id, context_lock) in contexts.iter() {
                    let mut context = context_lock.write();

                    if context.id.into() > 2 {
                        found += 1;

                        if send(&mut context) {
                            sent += 1;
                        }
                    }
                }
            } else {
                let pgid = if pid.into() == 0 {
                    current_pgid
                } else {
                    ContextId::from(-(pid.into() as isize) as usize)
                };

                // Send to every process in the process group whose ID
                for (_id, context_lock) in contexts.iter() {
                    let mut context = context_lock.write();

                    if context.pgid == pgid {
                        found += 1;

                        if send(&mut context) {
                            sent += 1;
                        }
                    }
                }
            }
        }

        if found == 0 {
            Err(Error::new(ESRCH))
        } else if sent == 0 {
            Err(Error::new(EPERM))
        } else {
            // Switch to ensure delivery to self
            unsafe { context::switch(); }

            Ok(0)
        }
    } else {
        Err(Error::new(EINVAL))
    }
}

pub fn mprotect(address: usize, size: usize, flags: MapFlags) -> Result<usize> {
    // println!("mprotect {:#X}, {}, {:#X}", address, size, flags);

    if address % PAGE_SIZE != 0 || size % PAGE_SIZE != 0 { return Err(Error::new(EINVAL)); }
    if address.saturating_add(size) > crate::USER_END_OFFSET { return Err(Error::new(EFAULT)); }

    AddrSpace::current()?.write().mprotect(Page::containing_address(VirtualAddress::new(address)), size / PAGE_SIZE, flags).map(|()| 0)
}

pub fn setpgid(pid: ContextId, pgid: ContextId) -> Result<usize> {
    let contexts = context::contexts();

    let current_pid = {
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();
        context.id
    };

    let context_lock = if pid.into() == 0 {
        contexts.current().ok_or(Error::new(ESRCH))?
    } else {
        contexts.get(pid).ok_or(Error::new(ESRCH))?
    };

    let mut context = context_lock.write();
    if context.id == current_pid || context.ppid == current_pid {
        if pgid.into() == 0 {
            context.pgid = context.id;
        } else {
            context.pgid = pgid;
        }
        Ok(0)
    } else {
        Err(Error::new(ESRCH))
    }
}

pub fn sigaction(sig: usize, act_opt: Option<&SigAction>, oldact_opt: Option<&mut SigAction>, restorer: usize) -> Result<usize> {
    if sig == 0 || sig > 0x7F {
        return Err(Error::new(EINVAL));
    }
    let contexts = context::contexts();
    let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
    let context = context_lock.read();
    let mut actions = context.actions.write();

    if let Some(oldact) = oldact_opt {
        *oldact = actions[sig].0;
    }

    if let Some(act) = act_opt {
        actions[sig] = (*act, restorer);
    }

    Ok(0)
}

pub fn sigprocmask(how: usize, mask_opt: Option<&[u64; 2]>, oldmask_opt: Option<&mut [u64; 2]>) -> Result<usize> {
    {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let mut context = context_lock.write();

        if let Some(oldmask) = oldmask_opt {
            *oldmask = context.sigmask;
        }

        if let Some(mask) = mask_opt {
            match how {
                SIG_BLOCK => {
                    context.sigmask[0] |= mask[0];
                    context.sigmask[1] |= mask[1];
                },
                SIG_UNBLOCK => {
                    context.sigmask[0] &= !mask[0];
                    context.sigmask[1] &= !mask[1];
                },
                SIG_SETMASK => {
                    context.sigmask[0] = mask[0];
                    context.sigmask[1] = mask[1];
                },
                _ => {
                    return Err(Error::new(EINVAL));
                }
            }
        }
    }
    Ok(0)
}

pub fn sigreturn() -> Result<usize> {
    {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let mut context = context_lock.write();
        context.ksig_restore = true;
        context.block("sigreturn");
    }

    let _ = unsafe { context::switch() };

    unreachable!();
}

pub fn umask(mask: usize) -> Result<usize> {
    let previous;
    {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let mut context = context_lock.write();
        previous = context.umask;
        context.umask = mask;
    }

    Ok(previous)
}

fn reap(pid: ContextId) -> Result<ContextId> {
    // Spin until not running
    let mut running = true;
    while running {
        {
            let contexts = context::contexts();
            let context_lock = contexts.get(pid).ok_or(Error::new(ESRCH))?;
            let context = context_lock.read();
            running = context.running;
        }

        interrupt::pause();
    }

    let mut contexts = context::contexts_mut();
    let context_lock = contexts.remove(pid).ok_or(Error::new(ESRCH))?;
    {
        let mut context = context_lock.write();
        context = empty(&context_lock, context, true);
    }
    drop(context_lock);

    Ok(pid)
}

pub fn waitpid(pid: ContextId, status_ptr: usize, flags: WaitFlags) -> Result<ContextId> {
    let (ppid, waitpid) = {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();
        (context.id, Arc::clone(&context.waitpid))
    };

    let mut tmp = [0];
    let status_slice = if status_ptr != 0 {
        validate_slice_mut(status_ptr as *mut usize, 1)?
    } else {
        &mut tmp
    };

    let mut grim_reaper = |w_pid: ContextId, status: usize| -> Option<Result<ContextId>> {
        if wifcontinued(status) {
            if flags & WCONTINUED == WCONTINUED {
                status_slice[0] = status;
                Some(Ok(w_pid))
            } else {
                None
            }
        } else if wifstopped(status) {
            if flags & WUNTRACED == WUNTRACED {
                status_slice[0] = status;
                Some(Ok(w_pid))
            } else {
                None
            }
        } else {
            status_slice[0] = status;
            Some(reap(w_pid))
        }
    };

    loop {
        let res_opt = if pid.into() == 0 {
            // Check for existence of child
            {
                let mut found = false;

                let contexts = context::contexts();
                for (_id, context_lock) in contexts.iter() {
                    let context = context_lock.read();
                    if context.ppid == ppid {
                        found = true;
                        break;
                    }
                }

                if ! found {
                    return Err(Error::new(ECHILD));
                }
            }

            if flags & WNOHANG == WNOHANG {
                if let Some((_wid, (w_pid, status))) = waitpid.receive_any_nonblock() {
                    grim_reaper(w_pid, status)
                } else {
                    Some(Ok(ContextId::from(0)))
                }
            } else {
                let (_wid, (w_pid, status)) = waitpid.receive_any("waitpid any");
                grim_reaper(w_pid, status)
            }
        } else if (pid.into() as isize) < 0 {
            let pgid = ContextId::from(-(pid.into() as isize) as usize);

            // Check for existence of child in process group PGID
            {
                let mut found = false;

                let contexts = context::contexts();
                for (_id, context_lock) in contexts.iter() {
                    let context = context_lock.read();
                    if context.pgid == pgid {
                        found = true;
                        break;
                    }
                }

                if ! found {
                    return Err(Error::new(ECHILD));
                }
            }

            if flags & WNOHANG == WNOHANG {
                if let Some((w_pid, status)) = waitpid.receive_nonblock(&WaitpidKey {
                    pid: None,
                    pgid: Some(pgid)
                }) {
                    grim_reaper(w_pid, status)
                } else {
                    Some(Ok(ContextId::from(0)))
                }
            } else {
                let (w_pid, status) = waitpid.receive(&WaitpidKey {
                    pid: None,
                    pgid: Some(pgid)
                }, "waitpid pgid");
                grim_reaper(w_pid, status)
            }
        } else {
            let hack_status = {
                let contexts = context::contexts();
                let context_lock = contexts.get(pid).ok_or(Error::new(ECHILD))?;
                let mut context = context_lock.write();
                if context.ppid != ppid {
                    println!("TODO: Hack for rustc - changing ppid of {} from {} to {}", context.id.into(), context.ppid.into(), ppid.into());
                    context.ppid = ppid;
                    //return Err(Error::new(ECHILD));
                    Some(context.status)
                } else {
                    None
                }
            };

            if let Some(context::Status::Exited(status)) = hack_status {
                let _ = waitpid.receive_nonblock(&WaitpidKey {
                    pid: Some(pid),
                    pgid: None
                });
                grim_reaper(pid, status)
            } else if flags & WNOHANG == WNOHANG {
                if let Some((w_pid, status)) = waitpid.receive_nonblock(&WaitpidKey {
                    pid: Some(pid),
                    pgid: None
                }) {
                    grim_reaper(w_pid, status)
                } else {
                    Some(Ok(ContextId::from(0)))
                }
            } else {
                let (w_pid, status) = waitpid.receive(&WaitpidKey {
                    pid: Some(pid),
                    pgid: None
                }, "waitpid pid");
                grim_reaper(w_pid, status)
            }
        };

        if let Some(res) = res_opt {
            return res;
        }
    }
}

pub unsafe fn usermode_bootstrap(bootstrap: &Bootstrap) -> ! {
    assert_ne!(bootstrap.page_count, 0);

    {
        let addr_space = Arc::clone(context::contexts().current()
            .expect("expected a context to exist when executing init")
            .read().addr_space()
            .expect("expected bootstrap context to have an address space"));

        let mut addr_space = addr_space.write();
        let addr_space = &mut *addr_space;

        let mut grant = context::memory::Grant::physmap(
            bootstrap.base.clone(),
            Page::containing_address(VirtualAddress::new(0)),
            bootstrap.page_count,
            PageFlags::new().user(true).write(true).execute(true),
            &mut addr_space.table.utable,
            PageFlushAll::new(),
        ).expect("failed to physmap bootstrap memory");
        grant.allocator_owned = false;
        grant.owned = true;

        addr_space.grants.insert(grant);
    }

    #[cfg(target_arch = "x86_64")]
    // Start in a minimal environment without any stack.
    usermode(bootstrap.entry, 0, 0, 0);
}
