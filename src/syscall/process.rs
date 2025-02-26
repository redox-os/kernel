use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use core::{mem, num::NonZeroUsize, sync::atomic::Ordering};
use spinning_top::RwSpinlock;
use syscall::{
    sig_bit, EventFlags, RtSigInfo, SenderInfo, SIGCHLD, SIGKILL, SIGSTOP, SIGTERM, SIGTSTP,
    SIGTTIN, SIGTTOU,
};

use rmm::Arch;
use spin::RwLock;

use crate::{
    context::{
        memory::{AddrSpace, Grant, PageSpan},
        Context, ContextRef,
    },
    event,
    scheme::GlobalSchemes,
};

use crate::{
    context, interrupt,
    paging::{Page, VirtualAddress, PAGE_SIZE},
    ptrace,
    syscall::{error::*, flag::MapFlags, ptrace_event},
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
    let owner = {
        let mut guard = context_lock.write();
        guard.status = context::Status::Dead;
        guard.owner_proc_id
    };
    if let Some(owner) = owner {
        let _ = event::trigger(
            GlobalSchemes::Proc.scheme_id(),
            owner.get(),
            EventFlags::EVENT_READ,
        );
    }
    let _ = context::contexts_mut().remove(&ContextRef(context_lock));
    context::switch();
    unreachable!();
}

pub fn send_signal(
    context: Arc<RwLock<Context>>,
    sig: usize,
    mode: KillMode,
    is_sigchld_to_parent: bool,
    killed_self: &mut bool,
    sender: SenderInfo,
) -> Result<()> {
    /*
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
            orig_signal: usize,
        },
        SucceededSigcont {
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
        }
        SendResult::SucceededSigcont { ppid, pgid } => {
            // POSIX XSI allows but does not require SIGCONT to send signals to the parent.
            //send_signal(KillTarget::Process(parent), SIGCHLD, true, killed_self)?;
        }
    }

    Ok(())
        */
    Ok(())
}

#[derive(Clone, Copy)]
pub enum KillMode {
    Idempotent,
    Queued(RtSigInfo),
}

pub fn mprotect(address: usize, size: usize, flags: MapFlags) -> Result<()> {
    // println!("mprotect {:#X}, {}, {:#X}", address, size, flags);

    let span = PageSpan::validate_nonempty(VirtualAddress::new(address), size)
        .ok_or(Error::new(EINVAL))?;

    AddrSpace::current()?.mprotect(span, flags)
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
    println!("\n");

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
