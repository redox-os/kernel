use alloc::{
    boxed::Box,
    collections::BTreeSet,
    string::String,
    sync::Arc,
    vec::Vec,
};
use core::alloc::{GlobalAlloc, Layout};
use core::convert::TryFrom;
use core::ops::DerefMut;
use core::{intrinsics, mem, str};
use crate::context::file::{FileDescription, FileDescriptor};

use spin::{RwLock, RwLockWriteGuard};

use crate::context::{Context, ContextId, WaitpidKey};
use crate::context::memory::{Grant, Region, NewTables, page_flags, setup_new_utable, UserGrants};

use crate::context;
#[cfg(not(feature="doc"))]
use crate::elf::{self, program_header};
use crate::interrupt;
use crate::ipi::{ipi, IpiKind, IpiTarget};
use crate::memory::{allocate_frames, Frame, PhysicalAddress};
use crate::paging::mapper::PageFlushAll;
use crate::paging::{ActivePageTable, InactivePageTable, Page, PageFlags, RmmA, TableKind, VirtualAddress, PAGE_SIZE};
use crate::{ptrace, syscall};
use crate::scheme::FileHandle;
use crate::start::usermode;
use crate::syscall::data::{CloneInfo, ExecMemRange, SigAction, Stat};
use crate::syscall::error::*;
use crate::syscall::flag::{wifcontinued, wifstopped, AT_ENTRY, AT_NULL, AT_PHDR, AT_PHENT, AT_PHNUM, CloneFlags,
                           CLONE_FILES, CLONE_FS, CLONE_SIGHAND, CLONE_STACK, CLONE_VFORK, CLONE_VM,
                           MapFlags, PROT_EXEC, PROT_READ, PROT_WRITE, PTRACE_EVENT_CLONE,
                           PTRACE_STOP_EXIT, SigActionFlags, SIG_BLOCK, SIG_DFL, SIG_SETMASK, SIG_UNBLOCK,
                           SIGCONT, SIGTERM, WaitFlags, WCONTINUED, WNOHANG, WUNTRACED};
use crate::syscall::ptrace_event;
use crate::syscall::validate::{validate_slice, validate_slice_mut};

pub fn clone(flags: CloneFlags, stack_base: usize, info: Option<&CloneInfo>) -> Result<ContextId> {
    let ppid;
    let pid;
    {
        let pgid;
        let ruid;
        let rgid;
        let rns;
        let euid;
        let egid;
        let ens;
        let umask;
        let sigmask;
        let mut cpu_id_opt = None;
        let arch;
        let vfork;
        let mut kfx_opt = None;
        let mut kstack_opt = None;
        let mut offset = 0;
        let mut grants;
        let name;
        let cwd;
        let files;
        let actions;
        let old_sigstack;

        // Copy from old process
        {
            let contexts = context::contexts();
            let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
            let context = context_lock.read();

            ppid = context.id;
            pgid = context.pgid;
            ruid = context.ruid;
            rgid = context.rgid;
            rns = context.rns;
            euid = context.euid;
            egid = context.egid;
            ens = context.ens;
            sigmask = context.sigmask;
            umask = context.umask;
            old_sigstack = context.sigstack;

            // Uncomment to disable threads on different CPUs
            //TODO: fix memory allocation races when this is removed
            if flags.contains(CLONE_VM) {
                cpu_id_opt = context.cpu_id;
            }

            arch = context.arch.clone();

            if let Some(ref fx) = context.kfx {
                let new_fx = unsafe {
                    let new_fx_ptr = crate::ALLOCATOR.alloc(Layout::from_size_align_unchecked(1024, 16));
                    if new_fx_ptr.is_null() {
                        // FIXME: It's mildly ironic that the only place where clone can fail with
                        // ENOMEM, is when copying 1024 bytes to merely store vector registers.
                        // Although in order to achieve full kernel-panic immunity, we'll need to
                        // completely phase out all usage of liballoc data structures, and use our
                        // own library/port liballoc, since panicking on OOM is not good for a
                        // kernel.
                        return Err(Error::new(ENOMEM));
                    }
                    new_fx_ptr.copy_from_nonoverlapping(fx.as_ptr(), fx.len());
                    Box::from_raw(new_fx_ptr as *mut [u8; 1024])
                };
                kfx_opt = Some(new_fx);
            }

            #[cfg(target_arch = "x86_64")]
            {
                if let Some(ref stack) = context.kstack {
                    // Get the relative offset to the return address of the function
                    // obtaining `stack_base`.
                    //
                    // (base pointer - start of stack) - one
                    offset = stack_base - stack.as_ptr() as usize - mem::size_of::<usize>(); // Add clone ret
                    let mut new_stack = stack.clone();

                    unsafe {
                        // Set clone's return value to zero. This is done because
                        // the clone won't return like normal, which means the value
                        // would otherwise never get set.
                        if let Some(regs) = ptrace::rebase_regs_ptr_mut(context.regs, Some(&mut new_stack)) {
                            (*regs).scratch.rax = 0;
                        }

                        // Change the return address of the child (previously
                        // syscall) to the arch-specific clone_ret callback
                        let func_ptr = new_stack.as_mut_ptr().add(offset);
                        *(func_ptr as *mut usize) = interrupt::syscall::clone_ret as usize;
                    }

                    kstack_opt = Some(new_stack);
                }
            }

            #[cfg(not(target_arch = "x86_64"))]
            {
                if let Some(ref stack) = context.kstack {
                    offset = stack_base - stack.as_ptr() as usize;
                    let mut new_stack = stack.clone();

                    kstack_opt = Some(new_stack);
                }
            }

            grants = Arc::clone(&context.grants);

            if flags.contains(CLONE_VM) {
                name = Arc::clone(&context.name);
            } else {
                name = Arc::new(RwLock::new(context.name.read().clone()));
            }

            if flags.contains(CLONE_FS) {
                cwd = Arc::clone(&context.cwd);
            } else {
                cwd = Arc::new(RwLock::new(context.cwd.read().clone()));
            }

            if flags.contains(CLONE_FILES) {
                files = Arc::clone(&context.files);
            } else {
                files = Arc::new(RwLock::new(context.files.read().clone()));
            }

            if flags.contains(CLONE_SIGHAND) {
                actions = Arc::clone(&context.actions);
            } else {
                actions = Arc::new(RwLock::new(context.actions.read().clone()));
            }
        }

        // If not cloning files, dup to get a new number from scheme
        // This has to be done outside the context lock to prevent deadlocks
        if !flags.contains(CLONE_FILES) {
            for (_fd, file_opt) in files.write().iter_mut().enumerate() {
                let new_file_opt = if let Some(ref file) = *file_opt {
                    Some(FileDescriptor {
                        description: Arc::clone(&file.description),
                        cloexec: file.cloexec,
                    })
                } else {
                    None
                };

                *file_opt = new_file_opt;
            }
        }

        let maps_to_reobtain = if flags.contains(CLONE_VM) {
            Vec::new()
        } else {
            grants.read().iter().filter_map(|grant| grant.desc_opt.as_ref().and_then(|file_ref| {
                let FileDescription { scheme, number, .. } = { *file_ref.desc.description.read() };
                let scheme_arc = match crate::scheme::schemes().get(scheme) {
                    Some(s) => Arc::downgrade(s),
                    None => return None,
                };
                let map = crate::syscall::data::Map {
                    address: grant.start_address().data(),
                    size: grant.size(),
                    offset: file_ref.offset,
                    flags: file_ref.flags | MapFlags::MAP_FIXED_NOREPLACE,
                };

                Some((scheme_arc, number, map))
            })).collect()
        };

        // If vfork, block the current process
        // This has to be done after the operations that may require context switches
        if flags.contains(CLONE_VFORK) {
            let contexts = context::contexts();
            let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
            let mut context = context_lock.write();
            context.block("vfork");
            vfork = true;
        } else {
            vfork = false;
        }

        // Set up new process
        let new_context_lock = {
            let mut contexts = context::contexts_mut();
            let context_lock = contexts.new_context()?;
            let mut context = context_lock.write();

            pid = context.id;

            context.pgid = pgid;
            context.ppid = ppid;
            context.ruid = ruid;
            context.rgid = rgid;
            context.rns = rns;
            context.euid = euid;
            context.egid = egid;
            context.ens = ens;
            context.sigmask = sigmask;
            context.umask = umask;

            //TODO: Better CPU balancing
            if let Some(cpu_id) = cpu_id_opt {
                context.cpu_id = Some(cpu_id);
            } else {
                context.cpu_id = Some(pid.into() % crate::cpu_count());
            }

            // Start as blocked. This is to ensure the context is never switched before any grants
            // that have to be remapped, are mapped.
            context.status = context::Status::Blocked;

            context.vfork = vfork;

            context.arch = arch;

            // This is needed because these registers may have changed after this context was
            // switched to, but before this was called.
            #[cfg(all(target_arch = "x86_64", feature = "x86_fsgsbase"))]
            unsafe {
                context.arch.fsbase = x86::bits64::segmentation::rdfsbase() as usize;
                x86::bits64::segmentation::swapgs();
                context.arch.gsbase = x86::bits64::segmentation::rdgsbase() as usize;
                x86::bits64::segmentation::swapgs();
            }

            if flags.contains(CloneFlags::CLONE_VM) {
                // Reuse same CR3, same grants, everything.
                context.grants = grants;
            } else {
                // TODO: Handle ENOMEM
                let mut new_tables = setup_new_utable().expect("failed to allocate new page tables for cloned process");

                let mut new_grants = UserGrants::new();
                for old_grant in grants.read().iter().filter(|g| g.desc_opt.is_none()) {
                    new_grants.insert(old_grant.secret_clone(&mut new_tables.new_utable));
                }
                context.grants = Arc::new(RwLock::new(new_grants));

                drop(grants);

                new_tables.take();

                context.arch.set_page_utable(unsafe { new_tables.new_utable.address() });

                #[cfg(target_arch = "aarch64")]
                context.arch.set_page_ktable(unsafe { new_tables.new_ktable.address() });
            }

            if let Some(fx) = kfx_opt.take() {
                context.arch.set_fx(fx.as_ptr() as usize);
                context.kfx = Some(fx);
            }

            // Set kernel stack
            if let Some(stack) = kstack_opt.take() {
                context.arch.set_stack(stack.as_ptr() as usize + offset);
                context.kstack = Some(stack);
                #[cfg(target_arch = "aarch64")]
                {
                    context.arch.set_lr(interrupt::syscall::clone_ret as usize);
                }
            }

            // TODO: Clone ksig?

            #[cfg(target_arch = "aarch64")]
            {
                if let Some(stack) = &mut context.kstack {
                    unsafe {
                        // stack_base contains a pointer to InterruptStack. Get its offset from
                        // stack_base itself
                        let istack_offset = *(stack_base as *const u64) - stack_base as u64;

                        // Get the top of the new process' stack
                        let new_sp = stack.as_mut_ptr().add(offset);

                        // Update the pointer to the InterruptStack to reflect the new process'
                        // stack. (Without this the pointer would be InterruptStack on the parent
                        // process' stack).
                        *(new_sp as *mut u64) = new_sp as u64 + istack_offset;

                        // Update tpidr_el0 in the new process' InterruptStack
                        let mut interrupt_stack = &mut *(stack.as_mut_ptr().add(offset + istack_offset as usize) as *mut crate::arch::interrupt::InterruptStack);
                        interrupt_stack.iret.tpidr_el0 = tcb_addr;
                    }
                }
            }


            context.name = name;

            context.cwd = cwd;

            context.files = files;

            context.actions = actions;

            if flags.contains(CLONE_VM) {
                context.sigstack = info.and_then(|info| (info.target_sigstack != !0).then(|| info.target_sigstack));
            } else {
                context.sigstack = old_sigstack;
            }

            Arc::clone(context_lock)
        };
        for (scheme_weak, number, map) in maps_to_reobtain {
            let scheme = match scheme_weak.upgrade() {
                Some(s) => s,
                None => continue,
            };
            let _ = scheme.kfmap(number, &map, &new_context_lock);
        }
        new_context_lock.write().unblock();
    }

    if ptrace::send_event(ptrace_event!(PTRACE_EVENT_CLONE, pid.into())).is_some() {
        // Freeze the clone, allow ptrace to put breakpoints
        // to it before it starts
        let contexts = context::contexts();
        let context = contexts.get(pid).expect("Newly created context doesn't exist??");
        let mut context = context.write();
        context.ptrace_stop = true;
    }

    // Race to pick up the new process!
    ipi(IpiKind::Switch, IpiTarget::Other);

    let _ = unsafe { context::switch() };

    Ok(pid)
}

fn empty<'lock>(context_lock: &'lock RwLock<Context>, mut context: RwLockWriteGuard<'lock, Context>, reaping: bool) -> RwLockWriteGuard<'lock, Context> {
    // NOTE: If we do not replace the grants `Arc`, then a strange situation can appear where the
    // main thread and another thread exit simultaneously before either one is reaped. If that
    // happens, then the last context that runs exit will think that there is still are still
    // remaining references to the grants, where there are in fact none. However, if either one is
    // reaped before, then that reference will disappear, and no leak will occur.
    //
    // By removing the reference to the grants when the context will no longer be used, this
    // problem will never occur.

    // FIXME, UNOPTIMIZED: Right now, this will allocate memory in order to store the new empty
    // grants, which may not even be used (only in fexec I think). We should turn grants into an
    // `Option`, and only reinitialize it there.
    let mut grants_arc = mem::take(&mut context.grants);

    if let Some(grants_lock_mut) = Arc::get_mut(&mut grants_arc) {
        let mut grants_guard = grants_lock_mut.get_mut();

        let grants = mem::replace(&mut *grants_guard, UserGrants::default());
        for grant in grants.into_iter() {
            let unmap_result = if reaping {
                log::error!("{}: {}: Grant should not exist: {:?}", context.id.into(), *context.name.read(), grant);

                let mut new_table = unsafe { InactivePageTable::from_address(context.arch.get_page_utable()) };

                grant.unmap_inactive(&mut new_table)
            } else {
                grant.unmap()
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

struct ExecFile(FileHandle);

impl Drop for ExecFile {
    fn drop(&mut self) {
        let _ = syscall::close(self.0);
    }
}

pub fn exit(status: usize) -> ! {
    ptrace::breakpoint_callback(PTRACE_STOP_EXIT, Some(ptrace_event!(PTRACE_STOP_EXIT, status)));

    {
        let context_lock = {
            let contexts = context::contexts();
            let context_lock = contexts.current().ok_or(Error::new(ESRCH)).expect("exit failed to find context");
            Arc::clone(&context_lock)
        };

        let mut close_files = Vec::new();
        let pid = {
            let mut context = context_lock.write();
            {
                let mut lock = context.files.write();
                if Arc::strong_count(&context.files) == 1 {
                    mem::swap(lock.deref_mut(), &mut close_files);
                }
            }
            context.files = Arc::new(RwLock::new(Vec::new()));
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

    let end_offset = size.checked_sub(1).ok_or(Error::new(EFAULT))?;
    let end_address = address.checked_add(end_offset).ok_or(Error::new(EFAULT))?;

    let mut active_table = unsafe { ActivePageTable::new(TableKind::User) };

    let flush_all = PageFlushAll::new();

    let start_page = Page::containing_address(VirtualAddress::new(address));
    let end_page = Page::containing_address(VirtualAddress::new(end_address));
    for page in Page::range_inclusive(start_page, end_page) {
        // Check if the page is actually mapped before trying to change the flags.
        // FIXME can other processes change if a page is mapped beneath our feet?
        let mut page_flags = if let Some(page_flags) = active_table.translate_page_flags(page) {
            page_flags
        } else {
            flush_all.flush();
            return Err(Error::new(EFAULT));
        };
        if !page_flags.has_present() {
            flush_all.flush();
            return Err(Error::new(EFAULT));
        }

        if flags.contains(PROT_EXEC) {
            page_flags = page_flags.execute(true);
        } else {
            page_flags = page_flags.execute(false);
        }

        if flags.contains(PROT_WRITE) {
            //TODO: Not allowing gain of write privileges
        } else {
            page_flags = page_flags.write(false);
        }

        if flags.contains(PROT_READ) {
            //TODO: No flags for readable pages
        } else {
            //TODO: No flags for readable pages
        }

        let flush = active_table.remap(page, page_flags);
        flush_all.consume(flush);
    }

    flush_all.flush();

    Ok(0)
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

pub fn usermode_bootstrap(mut data: Box<[u8]>) -> ! {
    assert!(!data.is_empty());

    const LOAD_BASE: usize = 0;
    let grant = context::memory::Grant::map(VirtualAddress::new(LOAD_BASE), ((data.len()+PAGE_SIZE-1)/PAGE_SIZE)*PAGE_SIZE, PageFlags::new().user(true).write(true).execute(true));

    let mut active_table = unsafe { ActivePageTable::new(TableKind::User) };

    for (index, page) in grant.pages().enumerate() {
        let len = if data.len() - index * PAGE_SIZE < PAGE_SIZE { data.len() % PAGE_SIZE } else { PAGE_SIZE };
        let frame = active_table.translate_page(page).expect("expected mapped init memory to have a corresponding frame");
        unsafe { ((frame.start_address().data() + crate::PHYS_OFFSET) as *mut u8).copy_from_nonoverlapping(data.as_ptr().add(index * PAGE_SIZE), len); }
    }

    context::contexts().current().expect("expected a context to exist when executing init").read().grants.write().insert(grant);

    drop(data);

    #[cfg(target_arch = "x86_64")]
    unsafe {
        let start = ((LOAD_BASE + 0x18) as *mut usize).read();
        // Start with the (probably) ELF executable loaded, without any stack the ability to load
        // sections to arbitrary addresses.
        usermode(start, 0, 0, 0);
    }
}

pub fn exec(memranges: &[ExecMemRange], instruction_ptr: usize, stack_ptr: usize) -> Result<usize> {
    // TODO: rlimit?
    if memranges.len() > 1024 {
        return Err(Error::new(EINVAL));
    }

    let mut new_grants = UserGrants::new();

    {
        let current_context_lock = Arc::clone(context::contexts().current().ok_or(Error::new(ESRCH))?);

        // Linux will always destroy other threads immediately if one of them executes execve(2).
        // At the moment the Redox kernel is ignorant of threads, other than them sharing files,
        // memory, etc. We fail with EBUSY if any resources that are being replaced, are shared.

        let mut old_grants = Arc::try_unwrap(mem::take(&mut current_context_lock.write().grants)).map_err(|_| Error::new(EBUSY))?.into_inner();
        // TODO: Allow multiple contexts which share the file table, to have one of them run exec?
        let mut old_files = Arc::try_unwrap(mem::take(&mut current_context_lock.write().files)).map_err(|_| Error::new(EBUSY))?.into_inner();

        // FIXME: Handle leak in case of ENOMEM.
        let mut new_tables = setup_new_utable()?;

        let mut flush = PageFlushAll::new();

        // FIXME: This is to the extreme, but fetch with atomic volatile?
        for memrange in memranges.iter().copied() {
            let old_address = if memrange.old_address == !0 { None } else { Some(memrange.old_address) };

            if memrange.address % PAGE_SIZE != 0 || old_address.map_or(false, |a| a % PAGE_SIZE != 0) || memrange.size % PAGE_SIZE != 0 {
                return Err(Error::new(EINVAL));
            }
            if memrange.size == 0 { continue }

            let new_start = Page::containing_address(VirtualAddress::new(memrange.address));
            let flags = MapFlags::from_bits(memrange.flags).ok_or(Error::new(EINVAL))?;
            let page_count = memrange.size / PAGE_SIZE;
            let flags = page_flags(flags);

            if let Some(old_address) = old_address {
                let old_start = VirtualAddress::new(memrange.old_address);

                let entire_region = Region::new(old_start, memrange.size);

                // TODO: This will do one B-Tree search for each memrange. If a process runs exec
                // and keeps every range the way it is, then this would be O(n log n)!
                loop {
                    let region = match old_grants.conflicts(entire_region).next().map(|g| *g.region()) {
                        Some(r) => r,
                        None => break,
                    };
                    let owned = old_grants.take(&region).expect("cannot fail");
                    let (before, mut current, after) = owned.extract(region).expect("cannot fail");

                    if let Some(before) = before { old_grants.insert(before); }
                    if let Some(after) = after { old_grants.insert(after); }

                    new_grants.insert(current.move_to_address_space(new_start, &mut new_tables.new_utable, flags, &mut flush));
                }
            } else {
                new_grants.insert(Grant::zeroed_inactive(new_start, page_count, flags, &mut new_tables.new_utable)?);
            }
        }

        {
            unsafe { flush.ignore(); }

            new_tables.take();

            let mut context = current_context_lock.write();
            context.grants = Arc::new(RwLock::new(new_grants));

            let old_utable = context.arch.get_page_utable();
            let old_frame = Frame::containing_address(PhysicalAddress::new(old_utable));

            context.arch.set_page_utable(unsafe { new_tables.new_utable.address() });

            #[cfg(target_arch = "x86_64")]
            unsafe { x86::controlregs::cr3_write(new_tables.new_utable.address() as u64); }

            for old_grant in old_grants.into_iter() {
                old_grant.unmap_inactive(&mut unsafe { InactivePageTable::from_address(old_utable) });
            }
            crate::memory::deallocate_frames(old_frame, 1);

            #[cfg(target_arch = "aarch64")]
            context.arch.set_page_ktable(unsafe { new_tables.new_ktable.address() });

            context.actions = Arc::new(RwLock::new(vec![(
                SigAction {
                    sa_handler: unsafe { mem::transmute(SIG_DFL) },
                    sa_mask: [0; 2],
                    sa_flags: SigActionFlags::empty(),
                },
                0
            ); 128]));
            let was_vfork = mem::replace(&mut context.vfork, false);

            // TODO: Reuse in place if the file table is not shared.
            drop(context);

            let mut context = current_context_lock.write();

            context.files = Arc::new(RwLock::new(old_files));
            let ppid = context.ppid;
            drop(context);

            // TODO: Should this code be preserved as is?
            if was_vfork {
                let contexts = context::contexts();
                if let Some(context_lock) = contexts.get(ppid) {
                    let mut context = context_lock.write();
                    if !context.unblock() {
                        println!("{} not blocked for exec vfork unblock", ppid.into());
                    }
                } else {
                    println!("{} not found for exec vfork unblock", ppid.into());
                }
            }
        }
    }

    unsafe { usermode(instruction_ptr, stack_ptr, 0, 0); }
}
