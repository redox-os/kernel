use alloc::{sync::Arc, vec::Vec};
use core::{mem, num::NonZeroUsize, sync::atomic::Ordering};
use spinning_top::RwSpinlock;
use syscall::{sig_bit, SIGCHLD, SIGKILL, SIGSTOP, SIGTERM, SIGTSTP, SIGTTIN, SIGTTOU};

use rmm::Arch;
use spin::RwLock;

use crate::context::{
    memory::{AddrSpace, Grant, PageSpan},
    process::{self, Process, ProcessId, ProcessInfo, ProcessStatus},
    Context, ContextRef, WaitpidKey,
};

use crate::{
    context, interrupt,
    paging::{Page, VirtualAddress, PAGE_SIZE},
    ptrace,
    syscall::{
        error::*,
        flag::{
            wifcontinued, wifstopped, MapFlags, WaitFlags, PTRACE_STOP_EXIT, SIGCONT, WCONTINUED,
            WNOHANG, WUNTRACED,
        },
        ptrace_event,
    },
    Bootstrap, CurrentRmmArch,
};

use super::usercopy::UserSliceWo;

pub fn exit_context(context_lock: Arc<RwSpinlock<Context>>) {
    // TODO: Stop context?
    let close_files;
    let addrspace_opt;

    {
        let mut context = context_lock.write();
        close_files = Arc::try_unwrap(mem::take(&mut context.files))
            .map_or_else(|_| Vec::new(), RwLock::into_inner);
        addrspace_opt = context
            .set_addr_space(None)
            .and_then(|a| Arc::try_unwrap(a).ok());
        drop(context.syscall_head.take());
        drop(context.syscall_tail.take());
    }

    // Files must be closed while context is valid so that messages can be passed
    for file_opt in close_files.into_iter() {
        if let Some(file) = file_opt {
            let _ = file.close();
        }
    }
    drop(addrspace_opt);
    // TODO: Should status == Status::HardBlocked be handled differently?
    context_lock.write().status = context::Status::Dead;
    let _ = context::contexts_mut().remove(&ContextRef(context_lock));
}

pub fn exit(status: usize) -> ! {
    ptrace::breakpoint_callback(
        PTRACE_STOP_EXIT,
        Some(ptrace_event!(PTRACE_STOP_EXIT, status)),
    );

    let current_context = context::current();
    let current_process = process::current().expect("no active process during exit syscall");
    let current_pid = current_process.read().pid;

    let threads = core::mem::take(&mut current_process.write().threads);

    for context_lock in threads.into_iter().filter_map(|t| t.upgrade()) {
        // Current context must be closed last, as it would otherwise be impossible to context
        // switch back, if closing file descriptors require scheme calls.
        if Arc::ptr_eq(&context_lock, &current_context) {
            continue;
        }
        exit_context(context_lock);
    }
    exit_context(current_context);

    {
        // PGID and PPID must be grabbed after close, as context switches could change PGID or PPID if parent exits
        let (pgid, ppid) = {
            let process = current_process.read();
            (process.pgid, process.ppid)
        };
        let _ = kill(ppid, SIGCHLD, true);

        // Transfer child processes to parent (TODO: to init)
        {
            let processes = context::process::PROCESSES.read();
            for (_child_pid, child_process_lock) in processes.iter() {
                let mut process = child_process_lock.write();
                if process.ppid == current_pid {
                    process.ppid = ppid;
                }
            }
        }

        current_process.write().status = ProcessStatus::Exited(status);

        let children = current_process.write().waitpid.receive_all();

        {
            let processes = process::PROCESSES.read();
            if let Some(parent_lock) = processes.get(&ppid) {
                let waitpid = Arc::clone(&parent_lock.write().waitpid);

                for (c_pid, c_status) in children {
                    waitpid.send(c_pid, c_status);
                }

                waitpid.send(
                    WaitpidKey {
                        pid: Some(current_pid),
                        pgid: Some(pgid),
                    },
                    (current_pid, status),
                );
            }
        }

        // Alert any tracers waiting of this process
        ptrace::close_tracee(current_pid);
    }

    let _ = context::switch();

    unreachable!();
}

pub fn getpid() -> Result<ProcessId> {
    context::current_pid()
}

pub fn getpgid(pid: ProcessId) -> Result<ProcessId> {
    let process_lock = if pid.get() == 0 {
        process::current()?
    } else {
        Arc::clone(
            process::PROCESSES
                .read()
                .get(&pid)
                .ok_or(Error::new(ESRCH))?,
        )
    };
    let process = process_lock.read();
    Ok(process.pgid)
}

pub fn getppid() -> Result<ProcessId> {
    Ok(process::current()?.read().ppid)
}

pub fn kill(pid: ProcessId, sig: usize, parent_sigchld: bool) -> Result<usize> {
    let (ruid, euid, current_pgid) = {
        let process_lock = process::current()?;
        let process = process_lock.read();
        (process.ruid, process.euid, process.pgid)
    };

    if euid == 0 && pid.get() == 1 {
        match sig {
            SIGTERM => unsafe { crate::stop::kreset() },
            SIGKILL => unsafe { crate::stop::kstop() },
            _ => return Ok(0), // error?
        }
    }

    if sig > 0x3F {
        return Err(Error::new(EINVAL));
    }
    let sig_group = sig / 32;

    let mut found = 0;
    let mut sent = 0;
    let mut killed_self = false;

    {
        let processes = process::PROCESSES.read();

        enum SendResult {
            Forbidden,
            Succeeded,
            SucceededSigchld {
                ppid: ProcessId,
                pgid: ProcessId,
                orig_signal: usize,
            },
            SucceededSigcont {
                ppid: ProcessId,
                pgid: ProcessId,
            },
        }

        let mut send = |context_lock: &Arc<RwSpinlock<Context>>,
                        process_lock: &Arc<RwLock<Process>>,
                        proc_info: &ProcessInfo|
         -> SendResult {
            let is_self = context::is_current(context_lock);

            // Non-root users cannot kill arbitrarily.
            if euid != 0 && euid != proc_info.ruid && ruid != proc_info.ruid {
                return SendResult::Forbidden;
            }
            // If sig = 0, test that process exists and can be signalled, but don't send any
            // signal.
            if sig == 0 {
                return SendResult::Succeeded;
            }

            let mut process_guard = process_lock.write();

            if sig == SIGCONT
                && let ProcessStatus::Stopped(_sig) = process_guard.status
            {
                // Convert stopped processes to blocked if sending SIGCONT, regardless of whether
                // SIGCONT is blocked or ignored. It can however be controlled whether the process
                // will additionally ignore, defer, or handle that signal.
                process_guard.status = ProcessStatus::PossiblyRunnable;
                drop(process_guard);

                if let Some((tctl, pctl, _st)) = context_lock.write().sigcontrol() {
                    if !pctl.signal_will_ign(SIGCONT, false) {
                        tctl.word[0].fetch_or(sig_bit(SIGCONT), Ordering::Relaxed);
                    }

                    if (tctl.word[0].load(Ordering::Relaxed) >> 32) & sig_bit(SIGCONT) != 0 {
                        // already Runnable, SIGCONT handler will run like any other signal
                    }
                }
                // POSIX XSI allows but does not reqiure SIGCHLD to be sent when SIGCONT occurs.
                return SendResult::SucceededSigcont {
                    ppid: proc_info.ppid,
                    pgid: proc_info.pgid,
                };
            }
            drop(process_guard);
            let mut context_guard = context_lock.write();
            if sig == SIGSTOP
                || (matches!(sig, SIGTTIN | SIGTTOU | SIGTSTP)
                    && context_guard
                        .sigcontrol()
                        .map_or(false, |(_, proc, _)| proc.signal_will_stop(sig)))
            {
                context_guard.status = context::Status::Blocked;
                // TODO: Actually wait for, or IPI the context first, then clear bit. Not atomically safe otherwise.
                if let Some((ctl, _, _)) = context_guard.sigcontrol() {
                    ctl.word[0].fetch_and(!sig_bit(SIGCONT), Ordering::Relaxed);
                }
                drop(context_guard);
                process_lock.write().status = ProcessStatus::Stopped(sig);
                return SendResult::SucceededSigchld {
                    ppid: proc_info.ppid,
                    pgid: proc_info.pgid,
                    orig_signal: sig,
                };
            }
            if sig == SIGKILL {
                context_guard.being_sigkilled = true;
                context_guard.unblock();
                drop(context_guard);
                process_lock.write().status = ProcessStatus::Exited(SIGKILL);
                killed_self |= is_self;

                // exit() will signal the parent, rather than immediately in kill()
                return SendResult::Succeeded;
            }
            if let Some((tctl, pctl, _st)) = context_guard.sigcontrol()
                && !pctl.signal_will_ign(sig, parent_sigchld)
            {
                let _was_new = tctl.word[sig_group].fetch_or(sig_bit(sig), Ordering::Relaxed);
                if (tctl.word[sig_group].load(Ordering::Relaxed) >> 32) & sig_bit(sig) != 0 {
                    context_guard.unblock();
                    killed_self |= is_self;
                }
                SendResult::Succeeded
            } else {
                // Discard signals if sighandler is unset. This includes both special contexts such
                // as bootstrap, and child processes or threads that have not yet been started.
                // This is semantically equivalent to having all signals except SIGSTOP and SIGKILL
                // blocked/ignored (SIGCONT can be ignored and masked, but will always continue
                // stopped processes first).
                SendResult::Succeeded
            }
        };
        let mut handle_send = |pid, result| -> Result<()> {
            match result {
                SendResult::Forbidden => (),
                SendResult::Succeeded => sent += 1,
                SendResult::SucceededSigchld {
                    ppid,
                    pgid,
                    orig_signal,
                } => {
                    sent += 1;
                    let waitpid = Arc::clone(
                        &process::PROCESSES
                            .read()
                            .get(&ppid)
                            .ok_or(Error::new(ESRCH))?
                            .read()
                            .waitpid,
                    );
                    waitpid.send(
                        WaitpidKey {
                            pid: Some(pid),
                            pgid: Some(pgid),
                        },
                        (pid, (orig_signal << 8) | 0x7f),
                    );
                    kill(ppid, SIGCHLD, true)?;
                }
                SendResult::SucceededSigcont { ppid, pgid } => {
                    sent += 1;
                    process::PROCESSES
                        .read()
                        .get(&ppid)
                        .ok_or(Error::new(ESRCH))?
                        .read()
                        .waitpid
                        .send(
                            WaitpidKey {
                                pid: Some(pid),
                                pgid: Some(pgid),
                            },
                            (pid, 0xffff),
                        );
                }
            }
            Ok(())
        };

        if pid.get() as isize > 0 {
            // Send to a single process
            if let Some(process_lock) = processes.get(&pid) {
                found += 1;
                let (context_lock, info) = {
                    let process = process_lock.read();
                    (
                        process
                            .threads
                            .first()
                            .ok_or(Error::new(ESRCH))?
                            .upgrade()
                            .ok_or(Error::new(ESRCH))?,
                        process.info,
                    )
                };
                let result = send(&context_lock, process_lock, &info);
                handle_send(pid, result)?;
            }
        } else if pid.get() == 1_usize.wrapping_neg() {
            // Send to every process with permission, except for init
            for (pid, process_lock) in processes.iter() {
                let (context_lock, info) = {
                    let process = process_lock.read();
                    (
                        process
                            .threads
                            .first()
                            .ok_or(Error::new(ESRCH))?
                            .upgrade()
                            .ok_or(Error::new(ESRCH))?,
                        process.info,
                    )
                };

                if info.pid.get() <= 1 {
                    continue;
                }
                found += 1;
                let result = send(&context_lock, process_lock, &info);
                handle_send(*pid, result)?;
            }
        } else {
            let pgid = if pid.get() == 0 {
                current_pgid
            } else {
                ProcessId::from(pid.get().wrapping_neg())
            };

            // Send to every process in the process group whose ID
            for (pid, process_lock) in processes.iter() {
                let (context_lock, info) = {
                    let process = process_lock.read();
                    (
                        process
                            .threads
                            .first()
                            .ok_or(Error::new(ESRCH))?
                            .upgrade()
                            .ok_or(Error::new(ESRCH))?,
                        process.info,
                    )
                };

                if info.pgid != pgid {
                    continue;
                }
                found += 1;

                let result = send(&context_lock, process_lock, &info);

                handle_send(*pid, result)?;
            }
        }
    }

    if found == 0 {
        Err(Error::new(ESRCH))
    } else if sent == 0 {
        Err(Error::new(EPERM))
    } else if killed_self {
        // Inform userspace it should check its own mask

        Err(Error::new(EINTR))
    } else {
        Ok(0)
    }
}

pub fn mprotect(address: usize, size: usize, flags: MapFlags) -> Result<()> {
    // println!("mprotect {:#X}, {}, {:#X}", address, size, flags);

    let span = PageSpan::validate_nonempty(VirtualAddress::new(address), size)
        .ok_or(Error::new(EINVAL))?;

    AddrSpace::current()?.mprotect(span, flags)
}

pub fn setpgid(pid: ProcessId, pgid: ProcessId) -> Result<()> {
    let current_pid = context::current_pid()?;

    let processes = process::PROCESSES.read();

    let process_lock = if pid.get() == 0 {
        process::current()?
    } else {
        Arc::clone(processes.get(&pid).ok_or(Error::new(ESRCH))?)
    };

    let mut process = process_lock.write();
    if process.pid == current_pid || process.ppid == current_pid {
        if pgid.get() == 0 {
            process.pgid = process.pid;
        } else {
            process.pgid = pgid;
        }
        Ok(())
    } else {
        Err(Error::new(ESRCH))
    }
}

pub fn umask(mask: usize) -> Result<usize> {
    let previous;
    {
        let process_lock = process::current()?;
        let mut process = process_lock.write();
        previous = process.umask;
        process.umask = mask;
    }

    Ok(previous)
}

fn reap(pid: ProcessId) -> Result<ProcessId> {
    let process_lock = Arc::clone(
        process::PROCESSES
            .read()
            .get(&pid)
            .ok_or(Error::new(ESRCH))?,
    );

    // Spin until not running
    loop {
        // TODO: exit WaitCondition?
        {
            let mut process = process_lock.read();
            if process
                .threads
                .iter()
                .all(|t| t.upgrade().map_or(true, |t| !t.read().running))
            {
                break;
            }
        }

        // TODO: context switch?
        interrupt::pause();
    }

    let _ = process::PROCESSES
        .write()
        .remove(&pid)
        .ok_or(Error::new(ESRCH))?;

    Ok(pid)
}

pub fn waitpid(
    pid: ProcessId,
    status_ptr: Option<UserSliceWo>,
    flags: WaitFlags,
) -> Result<ProcessId> {
    let process_lock = process::current()?;
    let (ppid, waitpid) = {
        let process = process_lock.read();
        (process.pid, Arc::clone(&process.waitpid))
    };

    let write_status = |value| {
        status_ptr
            .map(|ptr| ptr.write_usize(value))
            .unwrap_or(Ok(()))
    };

    let grim_reaper = |w_pid: ProcessId, status: usize| -> Option<Result<ProcessId>> {
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

                let processes = process::PROCESSES.read();
                for (_id, process_lock) in processes.iter() {
                    let process = process_lock.read();
                    if process.ppid == ppid {
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
                    Some(Ok(ProcessId::from(0)))
                }
            } else {
                let (_wid, (w_pid, status)) = waitpid.receive_any("waitpid any");
                grim_reaper(w_pid, status)
            }
        } else if (pid.get() as isize) < 0 {
            let pgid = ProcessId::from(-(pid.get() as isize) as usize);

            // Check for existence of child in process group PGID
            {
                let mut found = false;

                let processes = process::PROCESSES.read();
                for (_pid, process_lock) in processes.iter() {
                    let process = process_lock.read();
                    if process.pgid == pgid {
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
                    Some(Ok(ProcessId::from(0)))
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
                let processes = process::PROCESSES.read();
                let process_lock = processes.get(&pid).ok_or(Error::new(ECHILD))?;
                let process = process_lock.read();

                if process.ppid != ppid {
                    log::info!("HACK");
                    return Err(Error::new(ECHILD));
                    // TODO
                    /*
                    println!(
                        "TODO: Hack for rustc - changing ppid of {} from {} to {}",
                        process.pid.get(),
                        process.ppid.get(),
                        ppid.get()
                    );
                    process.ppid = ppid;
                    Some(context.status.clone())
                    */
                } else {
                    None
                }
            };

            if let Some(ProcessStatus::Exited(_status)) = hack_status {
                /*let _ = waitpid.receive_nonblock(&WaitpidKey {
                    pid: Some(pid),
                    pgid: None,
                });
                grim_reaper(pid, status)*/
                unreachable!()
            } else if flags & WNOHANG == WNOHANG {
                let res = waitpid.receive_nonblock(&WaitpidKey {
                    pid: Some(pid),
                    pgid: None,
                });
                if let Some((w_pid, status)) = res {
                    grim_reaper(w_pid, status)
                } else {
                    Some(Ok(ProcessId::from(0)))
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
            context::current()
                .read()
                .addr_space()
                .expect("expected bootstrap context to have an address space"),
        );

        let base = Page::containing_address(VirtualAddress::new(PAGE_SIZE));
        let flags = MapFlags::MAP_FIXED_NOREPLACE
            | MapFlags::PROT_EXEC
            | MapFlags::PROT_READ
            | MapFlags::PROT_WRITE;

        let page_count =
            NonZeroUsize::new(bootstrap.page_count).expect("bootstrap contained no pages!");

        let _base_page = addr_space.acquire_write().mmap(
            &addr_space,
            Some(base),
            page_count,
            flags,
            &mut Vec::new(),
            |page, flags, mapper, flusher| {
                let shared = false;
                Ok(Grant::zeroed(
                    PageSpan::new(page, bootstrap.page_count),
                    flags,
                    mapper,
                    flusher,
                    shared,
                )?)
            },
        );
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
        .write()
        .regs_mut()
        .expect("bootstrap needs registers to be available")
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
