use alloc::{sync::Arc, vec::Vec};
use core::{mem, num::NonZeroUsize};

use rmm::Arch;
use spin::RwLock;

use crate::context::{
    memory::{AddrSpace, PageSpan, Grant},
    ContextId, WaitpidKey,
};

use crate::{
    context, interrupt,
    paging::{Page, VirtualAddress, PAGE_SIZE},
    ptrace,
    syscall::{
        data::{SigAction, SignalStack},
        error::*,
        flag::{
            wifcontinued, wifstopped, MapFlags, WaitFlags, PTRACE_STOP_EXIT, SIGCONT,
            SIG_BLOCK, SIG_SETMASK, SIG_UNBLOCK, WCONTINUED, WNOHANG, WUNTRACED,
        },
        ptrace_event,
    },
    Bootstrap, CurrentRmmArch,
};

use super::usercopy::{UserSliceRo, UserSliceWo, UserSlice};

pub fn exit(status: usize) -> ! {
    ptrace::breakpoint_callback(
        PTRACE_STOP_EXIT,
        Some(ptrace_event!(PTRACE_STOP_EXIT, status)),
    );

    {
        let context_lock = context::current().expect("exit failed to find context");

        let close_files;
        let addrspace_opt;

        let pid = {
            let mut context = context_lock.write();
            close_files = Arc::try_unwrap(mem::take(&mut context.files))
                .map_or_else(|_| Vec::new(), RwLock::into_inner);
            addrspace_opt = context.set_addr_space(None).and_then(|a| Arc::try_unwrap(a).ok());
            drop(context.syscall_head.take());
            drop(context.syscall_tail.take());
            context.id
        };

        // Files must be closed while context is valid so that messages can be passed
        for (_fd, file_opt) in close_files.into_iter().enumerate() {
            if let Some(file) = file_opt {
                let _ = file.close();
            }
        }
        drop(addrspace_opt);

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
                }
            }
        }

        let children = {
            let mut context = context_lock.write();

            context.status = context::Status::Exited(status);

            context.waitpid.receive_all()
        };

        {
            let contexts = context::contexts();
            if let Some(parent_lock) = contexts.get(ppid) {
                let waitpid = Arc::clone(&parent_lock.write().waitpid);

                for (c_pid, c_status) in children {
                    waitpid.send(c_pid, c_status);
                }

                waitpid.send(
                    WaitpidKey {
                        pid: Some(pid),
                        pgid: Some(pgid),
                    },
                    (pid, status),
                );
            }
        }

        // Alert any tracers waiting of this process
        ptrace::close_tracee(pid);
    }

    let _ = unsafe { context::switch() };

    unreachable!();
}

pub fn getpid() -> Result<ContextId> {
    Ok(context::context_id())
}

pub fn getpgid(pid: ContextId) -> Result<ContextId> {
    let contexts = context::contexts();
    let context_lock = if pid.get() == 0 {
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

    if sig >= 0x3F {
        return Err(Error::new(EINVAL));
    }
    let mut found = 0;
    let mut sent = 0;

    {
        let contexts = context::contexts();

        let send = |context: &mut context::Context| -> bool {
            // Non-root users cannot kill arbitrarily.
            if euid != 0 && euid != context.ruid && ruid != context.ruid {
                return false;
            }
            // If sig = 0, test that process exists and can be
            // signalled, but don't send any signal.
            if sig == 0 {
                return true;
            }

            context.sig.pending |= 1_u64 << (sig - 1);

            // Convert stopped processes to blocked if sending SIGCONT
            if sig == SIGCONT {
                if let context::Status::Stopped(_sig) = context.status {
                    context.status = context::Status::Blocked;
                }
            }

            true
        };

        if pid.get() as isize > 0 {
            // Send to a single process
            if let Some(context_lock) = contexts.get(pid) {
                let mut context = context_lock.write();

                found += 1;
                if send(&mut context) {
                    sent += 1;
                }
            }
        } else if pid.get() == 1_usize.wrapping_neg() {
            // Send to every process with permission, except for init
            for (_id, context_lock) in contexts.iter() {
                let mut context = context_lock.write();

                if context.id.get() > 2 {
                    found += 1;

                    if send(&mut context) {
                        sent += 1;
                    }
                }
            }
        } else {
            let pgid = if pid.get() == 0 {
                current_pgid
            } else {
                ContextId::from(pid.get().wrapping_neg())
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
        context::switch();

        Ok(0)
    }
}

pub fn mprotect(address: usize, size: usize, flags: MapFlags) -> Result<()> {
    // println!("mprotect {:#X}, {}, {:#X}", address, size, flags);

    let span = PageSpan::validate_nonempty(VirtualAddress::new(address), size)
        .ok_or(Error::new(EINVAL))?;

    AddrSpace::current()?.mprotect(span, flags)
}

pub fn setpgid(pid: ContextId, pgid: ContextId) -> Result<usize> {
    let contexts = context::contexts();

    let current_pid = {
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();
        context.id
    };

    let context_lock = if pid.get() == 0 {
        contexts.current().ok_or(Error::new(ESRCH))?
    } else {
        contexts.get(pid).ok_or(Error::new(ESRCH))?
    };

    let mut context = context_lock.write();
    if context.id == current_pid || context.ppid == current_pid {
        if pgid.get() == 0 {
            context.pgid = context.id;
        } else {
            context.pgid = pgid;
        }
        Ok(0)
    } else {
        Err(Error::new(ESRCH))
    }
}

pub fn sigaction(
    sig: usize,
    act_opt: Option<UserSliceRo>,
    oldact_opt: Option<UserSliceWo>,
    restorer: usize,
) -> Result<()> {
    if sig == 0 || sig > 0x7F {
        return Err(Error::new(EINVAL));
    }
    let contexts = context::contexts();
    let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
    let context = context_lock.read();
    let mut actions = context.actions.write();

    if let Some(oldact) = oldact_opt {
        oldact.copy_exactly(&actions[sig - 1].0)?;
    }

    if let Some(act) = act_opt {
        actions[sig - 1] = (unsafe { act.read_exact::<SigAction>()? }, restorer);
    }

    Ok(())
}

pub fn sigprocmask(how: usize, mask_ref_opt: Option<UserSliceRo>, oldmask_out_opt: Option<UserSliceWo>) -> Result<()> {
    let mask_opt = mask_ref_opt.map(|m| m.read_u64()).transpose()?;

    let old_sigmask;

    {
        let context_lock = context::current()?;
        let mut context = context_lock.write();

        old_sigmask = context.sig.procmask;

        if let Some(arg) = mask_opt {
            match how {
                SIG_BLOCK => context.sig.procmask |= arg,
                SIG_UNBLOCK => context.sig.procmask &= !arg,
                SIG_SETMASK => context.sig.procmask = arg,
                _ => {
                    return Err(Error::new(EINVAL));
                }
            }
        }
    };

    if let Some(oldmask_out) = oldmask_out_opt {
        oldmask_out.write_u64(old_sigmask)?;
    }
    Ok(())
}

pub fn sigreturn() -> Result<()> {
    let context = context::current()?;

    let mut stack = SignalStack::default();

    // Kernel-only contexts can't call sigreturn in the first place, so a panic would be
    // acceptable, but handle it anyway.
    let stack_ptr = context.read().regs().ok_or(Error::new(EINVAL))?.stack_pointer();

    UserSlice::ro(stack_ptr, mem::size_of::<SignalStack>())?.copy_to_slice(&mut stack)?;

    let mut context = context.write();
    context.regs_mut().ok_or(Error::new(EINVAL))?.load(&stack.intregs);
    context.sig.procmask = stack.old_procmask;

    Ok(())
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
        // TODO: exit WaitCondition?
        {
            let contexts = context::contexts();
            let context_lock = contexts.get(pid).ok_or(Error::new(ESRCH))?;
            let context = context_lock.read();
            running = context.running;
        }

        interrupt::pause();
    }

    let _ = context::contexts_mut()
        .remove(pid)
        .ok_or(Error::new(ESRCH))?;

    Ok(pid)
}

pub fn waitpid(
    pid: ContextId,
    status_ptr: Option<UserSliceWo>,
    flags: WaitFlags,
) -> Result<ContextId> {
    let (ppid, waitpid) = {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();
        (context.id, Arc::clone(&context.waitpid))
    };
    let write_status = |value| {
        status_ptr
            .map(|ptr| ptr.write_usize(value))
            .unwrap_or(Ok(()))
    };

    let grim_reaper = |w_pid: ContextId, status: usize| -> Option<Result<ContextId>> {
        if wifcontinued(status) {
            if flags & WCONTINUED == WCONTINUED {
                Some(write_status(status).map(|()| w_pid))
            } else {
                None
            }
        } else if wifstopped(status) {
            if flags & WUNTRACED == WUNTRACED {
                Some(write_status(status).map(|()| w_pid))
            } else {
                None
            }
        } else {
            Some(write_status(status).and_then(|()| reap(w_pid)))
        }
    };

    loop {
        let res_opt = if pid.get() == 0 {
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

                if !found {
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
        } else if (pid.get() as isize) < 0 {
            let pgid = ContextId::from(-(pid.get() as isize) as usize);

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

                if !found {
                    return Err(Error::new(ECHILD));
                }
            }

            if flags & WNOHANG == WNOHANG {
                if let Some((w_pid, status)) = waitpid.receive_nonblock(&WaitpidKey {
                    pid: None,
                    pgid: Some(pgid),
                }) {
                    grim_reaper(w_pid, status)
                } else {
                    Some(Ok(ContextId::from(0)))
                }
            } else {
                let (w_pid, status) = waitpid.receive(
                    &WaitpidKey {
                        pid: None,
                        pgid: Some(pgid),
                    },
                    "waitpid pgid",
                );
                grim_reaper(w_pid, status)
            }
        } else {
            let hack_status = {
                let contexts = context::contexts();
                let context_lock = contexts.get(pid).ok_or(Error::new(ECHILD))?;
                let mut context = context_lock.write();
                if context.ppid != ppid {
                    println!(
                        "TODO: Hack for rustc - changing ppid of {} from {} to {}",
                        context.id.get(),
                        context.ppid.get(),
                        ppid.get()
                    );
                    context.ppid = ppid;
                    //return Err(Error::new(ECHILD));
                    Some(context.status.clone())
                } else {
                    None
                }
            };

            if let Some(context::Status::Exited(status)) = hack_status {
                let _ = waitpid.receive_nonblock(&WaitpidKey {
                    pid: Some(pid),
                    pgid: None,
                });
                grim_reaper(pid, status)
            } else if flags & WNOHANG == WNOHANG {
                if let Some((w_pid, status)) = waitpid.receive_nonblock(&WaitpidKey {
                    pid: Some(pid),
                    pgid: None,
                }) {
                    grim_reaper(w_pid, status)
                } else {
                    Some(Ok(ContextId::from(0)))
                }
            } else {
                let (w_pid, status) = waitpid.receive(
                    &WaitpidKey {
                        pid: Some(pid),
                        pgid: None,
                    },
                    "waitpid pid",
                );
                grim_reaper(w_pid, status)
            }
        };

        if let Some(res) = res_opt {
            return res;
        }
    }
}

pub unsafe fn usermode_bootstrap(bootstrap: &Bootstrap) {
    assert_ne!(bootstrap.page_count, 0);

    {
        let addr_space = Arc::clone(
            context::contexts()
                .current()
                .expect("expected a context to exist when executing init")
                .read()
                .addr_space()
                .expect("expected bootstrap context to have an address space"),
        );

        let base = Page::containing_address(VirtualAddress::new(PAGE_SIZE));
        let flags = MapFlags::MAP_FIXED_NOREPLACE | MapFlags::PROT_EXEC | MapFlags::PROT_READ | MapFlags::PROT_WRITE;

        let page_count = NonZeroUsize::new(bootstrap.page_count)
            .expect("bootstrap contained no pages!");

        let _base_page = addr_space.acquire_write().mmap(&addr_space, Some(base), page_count, flags, &mut Vec::new(), |page, flags, mapper, flusher| {
            let shared = false;
            Ok(Grant::zeroed(PageSpan::new(page, bootstrap.page_count), flags, mapper, flusher, shared)?)
        });
    }

    let bootstrap_slice = unsafe { bootstrap_mem(bootstrap) };
    UserSliceWo::new(PAGE_SIZE, bootstrap.page_count * PAGE_SIZE)
        .expect("failed to create bootstrap user slice")
        .copy_from_slice(bootstrap_slice)
        .expect("failed to copy memory to bootstrap");

    let bootstrap_entry = u64::from_le_bytes(bootstrap_slice[0x1a..0x22].try_into().unwrap());
    log::info!("Bootstrap entry point: {:X}", bootstrap_entry);
    assert_ne!(bootstrap_entry, 0);

    // Start in a minimal environment without any stack.

    match context::current()
        .expect("bootstrap was not running inside any context").write()
        .regs_mut().expect("bootstrap needs registers to be available")
    {
        ref mut regs => {
            regs.init();
            regs.set_instr_pointer(bootstrap_entry.try_into().unwrap());
        }
    }
}

pub unsafe fn bootstrap_mem(bootstrap: &crate::Bootstrap) -> &'static [u8] {
    core::slice::from_raw_parts(
        CurrentRmmArch::phys_to_virt(bootstrap.base.start_address()).data() as *const u8,
        bootstrap.page_count * PAGE_SIZE,
    )
}
