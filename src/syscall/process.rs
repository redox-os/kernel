use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use core::{mem, num::NonZeroUsize, sync::atomic::Ordering};
use spinning_top::RwSpinlock;
use syscall::{
    sig_bit, RtSigInfo, SenderInfo, SIGCHLD, SIGKILL, SIGSTOP, SIGTERM, SIGTSTP, SIGTTIN, SIGTTOU,
};

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

pub fn exit_this_context() -> ! {
    let close_files;
    let addrspace_opt;

    let context_lock = context::current();
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
    context::switch();
    unreachable!();
}

pub fn wait_for_exit(context_lock: Arc<RwSpinlock<Context>>) {
    {
        let mut ctxt = context_lock.write();
        ctxt.status = context::Status::Runnable;
        ctxt.being_sigkilled = true;
    }
    while !matches!(context_lock.read().status, context::Status::Dead) {
        context::switch();
    }
}

pub fn exit(status: usize) -> ! {
    if matches!(
        mem::replace(
            &mut process::current().unwrap().write().status,
            ProcessStatus::Exiting
        ),
        ProcessStatus::Exiting
    ) {
        // already exiting the current process, so just set our status to Dead and context switch.
        exit_this_context();
    }

    ptrace::breakpoint_callback(
        PTRACE_STOP_EXIT,
        Some(ptrace_event!(PTRACE_STOP_EXIT, status)),
    );

    let current_pid;
    let current_ruid;
    {
        let current_context = context::current();
        let current_process = process::current().expect("no active process during exit syscall");
        current_pid = current_process.read().pid;

        let threads = core::mem::take(&mut current_process.write().threads);

        for context_lock in threads.into_iter().filter_map(|t| t.upgrade()) {
            // Current context must be closed last, as it would otherwise be impossible to context
            // switch back, if closing file descriptors require scheme calls.
            if Arc::ptr_eq(&context_lock, &current_context) {
                continue;
            }
            wait_for_exit(context_lock);
        }

        {
            // PGID and PPID must be grabbed after close, as context switches could change PGID or PPID if parent exits
            let (pgid, ppid) = {
                let process = current_process.read();
                current_ruid = process.ruid;
                (process.pgid, process.ppid)
            };
            if let Some(parent) = process::PROCESSES.read().get(&ppid).map(Arc::clone) {
                let _ = send_signal(
                    KillTarget::Process(parent),
                    SIGCHLD,
                    KillMode::Idempotent,
                    true,
                    &mut false,
                    SenderInfo {
                        pid: current_pid.get().try_into().unwrap_or(0),
                        ruid: current_ruid,
                    },
                );
            }

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
    }
    exit_this_context();
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

pub enum KillTarget {
    Process(Arc<RwLock<Process>>),
    Thread(Arc<RwSpinlock<Context>>),
}

pub fn send_signal(
    target: KillTarget,
    sig: usize,
    mode: KillMode,
    is_sigchld_to_parent: bool,
    killed_self: &mut bool,
    sender: SenderInfo,
) -> Result<()> {
    if sig > 64 {
        return Err(Error::new(EINVAL));
    }

    let sig_group = (sig - 1) / 32;
    let sig_idx = sig - 1;

    let (context_lock, process_lock) = match target {
        KillTarget::Thread(ref c) => (Arc::clone(&c), Arc::clone(&c.read().process)),
        KillTarget::Process(ref p) => (
            p.read()
                .threads
                .iter()
                .filter_map(|t| t.upgrade())
                .next()
                .ok_or(Error::new(ESRCH))?,
            Arc::clone(p),
        ),
    };
    let proc_info = process_lock.read().info;

    enum SendResult {
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
        FullQ,
        Invalid,
    }

    let result = (|| {
        let is_self = context::is_current(&context_lock);

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

            let mut context_guard = context_lock.write();
            if let Some((_, pctl, _)) = context_guard.sigcontrol() {
                if !pctl.signal_will_ign(SIGCONT, false) {
                    pctl.pending.fetch_or(sig_bit(SIGCONT), Ordering::Relaxed);
                }
                drop(context_guard);

                // TODO: which threads should become Runnable?
                for thread in process_lock
                    .read()
                    .threads
                    .iter()
                    .filter_map(|t| t.upgrade())
                {
                    let mut thread = thread.write();
                    if let Some((tctl, _, _)) = thread.sigcontrol() {
                        tctl.word[0].fetch_and(
                            !(sig_bit(SIGSTOP)
                                | sig_bit(SIGTTIN)
                                | sig_bit(SIGTTOU)
                                | sig_bit(SIGTSTP)),
                            Ordering::Relaxed,
                        );
                    }
                    thread.unblock();
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
            drop(context_guard);
            process_lock.write().status = ProcessStatus::Stopped(sig);

            // TODO: Actually wait for, or IPI the context first, then clear bit. Not atomically safe otherwise.
            let mut already = false;
            for thread in process_lock
                .read()
                .threads
                .iter()
                .filter_map(|t| t.upgrade())
            {
                let mut thread = thread.write();
                if let Some((tctl, pctl, _)) = thread.sigcontrol() {
                    if !already {
                        pctl.pending.fetch_and(!sig_bit(SIGCONT), Ordering::Relaxed);
                        already = true;
                    }
                    tctl.word[0].fetch_and(!sig_bit(SIGCONT), Ordering::Relaxed);
                }
            }

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
            *killed_self |= is_self;

            // exit() will signal the parent, rather than immediately in kill()
            return SendResult::Succeeded;
        }
        if let Some((tctl, pctl, sigst)) = context_guard.sigcontrol()
            && !pctl.signal_will_ign(sig, is_sigchld_to_parent)
        {
            match target {
                KillTarget::Thread(_) => {
                    tctl.sender_infos[sig_idx].store(sender.raw(), Ordering::Relaxed);

                    let _was_new = tctl.word[sig_group].fetch_or(sig_bit(sig), Ordering::Release);
                    if (tctl.word[sig_group].load(Ordering::Relaxed) >> 32) & sig_bit(sig) != 0 {
                        context_guard.unblock();
                        *killed_self |= is_self;
                    }
                }
                KillTarget::Process(proc) => {
                    match mode {
                        KillMode::Queued(arg) => {
                            if sig_group != 1 || sig_idx < 32 || sig_idx >= 64 {
                                return SendResult::Invalid;
                            }
                            let rtidx = sig_idx - 32;
                            //log::info!("QUEUEING {arg:?} RTIDX {rtidx}");
                            if rtidx >= sigst.rtqs.len() {
                                sigst.rtqs.resize_with(rtidx + 1, VecDeque::new);
                            }
                            let rtq = sigst.rtqs.get_mut(rtidx).unwrap();

                            // TODO: configurable limit?
                            if rtq.len() > 32 {
                                return SendResult::FullQ;
                            }

                            rtq.push_back(arg);
                        }
                        KillMode::Idempotent => {
                            if pctl.pending.load(Ordering::Acquire) & sig_bit(sig) != 0 {
                                // If already pending, do not send this signal. While possible that
                                // another thread is concurrently clearing pending, and that other
                                // spuriously awoken threads would benefit from actually receiving
                                // this signal, there is no requirement by POSIX for such signals
                                // not to be mergeable. So unless the signal handler is observed to
                                // happen-before this syscall, it can be ignored. The pending bits
                                // would certainly have been cleared, thus contradicting this
                                // already reached statement.
                                return SendResult::Succeeded;
                            }

                            if sig_group != 0 {
                                return SendResult::Invalid;
                            }
                            pctl.sender_infos[sig_idx].store(sender.raw(), Ordering::Relaxed);
                        }
                    }

                    pctl.pending.fetch_or(sig_bit(sig), Ordering::Release);
                    drop(context_guard);

                    for thread in proc.read().threads.iter().filter_map(|t| t.upgrade()) {
                        let mut thread = thread.write();
                        let Some((tctl, _, _)) = thread.sigcontrol() else {
                            continue;
                        };
                        if (tctl.word[sig_group].load(Ordering::Relaxed) >> 32) & sig_bit(sig) != 0
                        {
                            thread.unblock();
                            *killed_self |= is_self;
                            break;
                        }
                    }
                }
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
    })();

    match result {
        SendResult::Succeeded => (),
        SendResult::FullQ => return Err(Error::new(EAGAIN)),
        SendResult::Invalid => return Err(Error::new(EINVAL)),
        SendResult::SucceededSigchld {
            ppid,
            pgid,
            orig_signal,
        } => {
            let parent = process::PROCESSES
                .read()
                .get(&ppid)
                .map(Arc::clone)
                .ok_or(Error::new(ESRCH))?;
            let waitpid = Arc::clone(&parent.read().waitpid);
            waitpid.send(
                WaitpidKey {
                    pid: Some(proc_info.pid),
                    pgid: Some(pgid),
                },
                (proc_info.pid, (orig_signal << 8) | 0x7f),
            );
            send_signal(
                KillTarget::Process(parent),
                SIGCHLD,
                mode,
                true,
                killed_self,
                sender,
            )?;
        }
        SendResult::SucceededSigcont { ppid, pgid } => {
            let parent = process::PROCESSES
                .read()
                .get(&ppid)
                .map(Arc::clone)
                .ok_or(Error::new(ESRCH))?;
            let waitpid = Arc::clone(&parent.read().waitpid);
            waitpid.send(
                WaitpidKey {
                    pid: Some(proc_info.pid),
                    pgid: Some(pgid),
                },
                (proc_info.pid, 0xffff),
            );
            // POSIX XSI allows but does not require SIGCONT to send signals to the parent.
            //send_signal(KillTarget::Process(parent), SIGCHLD, true, killed_self)?;
        }
    }

    Ok(())
}

#[derive(Clone, Copy)]
pub enum KillMode {
    Idempotent,
    Queued(RtSigInfo),
}

pub fn kill(pid: ProcessId, sig: usize, mode: KillMode) -> Result<usize> {
    let (current_ruid, current_euid, current_pgid, current_pid) = {
        let process_lock = process::current()?;
        let process = process_lock.read();
        (process.ruid, process.euid, process.pgid, process.pid)
    };
    let sender = SenderInfo {
        pid: current_pid.get().try_into().unwrap_or(0),
        ruid: current_ruid,
    };

    if current_euid == 0 && pid.get() == 1 {
        match sig {
            SIGTERM => unsafe { crate::stop::kreset() },
            SIGKILL => unsafe { crate::stop::kstop() },
            _ => return Ok(0), // error?
        }
    }

    let mut found = 0;
    let mut sent = 0;
    let mut killed_self = false;

    // Non-root users cannot kill arbitrarily.
    let can_send = |proc_info: &ProcessInfo| {
        current_euid == 0 || current_euid == proc_info.ruid || current_ruid == proc_info.ruid
    };

    {
        let processes = process::PROCESSES.read();

        if pid.get() as isize > 0 {
            // Send to a single process
            if let Some(process_lock) = processes.get(&pid).map(Arc::clone) {
                found += 1;
                if can_send(&process_lock.read().info) {
                    sent += 1;
                    send_signal(
                        KillTarget::Process(process_lock),
                        sig,
                        mode,
                        false,
                        &mut killed_self,
                        sender,
                    )?;
                }
            }
        } else if pid.get() == 1_usize.wrapping_neg() {
            // Send to every process with permission, except for init
            for (pid, process_lock) in processes.iter() {
                if pid.get() <= 1 {
                    continue;
                }
                found += 1;
                if can_send(&process_lock.read().info) {
                    sent += 1;
                    send_signal(
                        KillTarget::Process(Arc::clone(process_lock)),
                        sig,
                        mode,
                        false,
                        &mut killed_self,
                        sender,
                    )?;
                }
            }
        } else {
            let pgid = if pid.get() == 0 {
                current_pgid
            } else {
                ProcessId::from(pid.get().wrapping_neg())
            };

            // Send to every process in the process group whose ID
            for (_pid, process_lock) in processes.iter() {
                if process_lock.read().pgid != pgid {
                    continue;
                }
                found += 1;

                if can_send(&process_lock.read().info) {
                    sent += 1;
                    send_signal(
                        KillTarget::Process(Arc::clone(process_lock)),
                        sig,
                        mode,
                        false,
                        &mut killed_self,
                        sender,
                    )?;
                }
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
            let process = process_lock.read();
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
    let (ppid, waitpid) = {
        let process_lock = process::current()?;
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
                let (w_pid, status) = waitpid
                    .receive(
                        &WaitpidKey {
                            pid: None,
                            pgid: Some(pgid),
                        },
                        "waitpid pgid",
                    )
                    .ok_or(Error::new(EINTR))?;
                grim_reaper(w_pid, status)
            }
        } else {
            let status = {
                let process_lock = Arc::clone(
                    process::PROCESSES
                        .read()
                        .get(&pid)
                        .ok_or(Error::new(ESRCH))?,
                );
                let process_guard = process_lock.read();

                if process_guard.ppid != ppid {
                    return Err(Error::new(ECHILD));
                }
                process_guard.status
            };

            if let ProcessStatus::Exited(status) = status {
                let _ = waitpid.receive_nonblock(&WaitpidKey {
                    pid: Some(pid),
                    pgid: None,
                });
                grim_reaper(pid, status)
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
                let (w_pid, status) = waitpid
                    .receive(
                        &WaitpidKey {
                            pid: Some(pid),
                            pgid: None,
                        },
                        "waitpid pid",
                    )
                    .ok_or(Error::new(EINTR))?;
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

        let _base_page = addr_space
            .acquire_write()
            .mmap(
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
            )
            .expect("Failed to allocate bootstrap pages");
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
        CurrentRmmArch::phys_to_virt(bootstrap.base.base()).data() as *const u8,
        bootstrap.page_count * PAGE_SIZE,
    )
}
pub fn sigdequeue(out: UserSliceWo, sig_idx: u32) -> Result<()> {
    let current = context::current();
    let mut current = current.write();
    let Some((_tctl, pctl, st)) = current.sigcontrol() else {
        return Err(Error::new(ESRCH));
    };
    if sig_idx >= 32 {
        return Err(Error::new(EINVAL));
    }
    let q = st
        .rtqs
        .get_mut(sig_idx as usize)
        .ok_or(Error::new(EAGAIN))?;
    let Some(front) = q.pop_front() else {
        return Err(Error::new(EAGAIN));
    };
    if q.is_empty() {
        pctl.pending
            .fetch_and(!(1 << (32 + sig_idx as usize)), Ordering::Relaxed);
    }
    out.copy_exactly(&front)?;
    Ok(())
}
