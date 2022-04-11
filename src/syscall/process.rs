use alloc::{
    boxed::Box,
    collections::BTreeSet,
    string::String,
    sync::Arc,
    vec::Vec,
};
use core::alloc::{GlobalAlloc, Layout};
use core::ops::DerefMut;
use core::{intrinsics, mem, str};
use spin::{RwLock, RwLockWriteGuard};

use crate::context::file::{FileDescription, FileDescriptor};
use crate::context::memory::{UserGrants, Region};
use crate::context::{Context, ContextId, WaitpidKey};
use crate::context;
#[cfg(not(feature="doc"))]
use crate::elf::{self, program_header};
use crate::interrupt;
use crate::ipi::{ipi, IpiKind, IpiTarget};
use crate::memory::allocate_frames;
use crate::paging::mapper::PageFlushAll;
use crate::paging::{ActivePageTable, InactivePageTable, Page, PageFlags, TableKind, VirtualAddress, PAGE_SIZE};
use crate::{ptrace, syscall};
use crate::scheme::FileHandle;
use crate::start::usermode;
use crate::syscall::data::{SigAction, Stat};
use crate::syscall::error::*;
use crate::syscall::flag::{wifcontinued, wifstopped, AT_ENTRY, AT_NULL, AT_PHDR, AT_PHENT, AT_PHNUM, CloneFlags,
                           CLONE_FILES, CLONE_FS, CLONE_SIGHAND, CLONE_STACK, CLONE_VFORK, CLONE_VM,
                           MapFlags, PROT_EXEC, PROT_READ, PROT_WRITE, PTRACE_EVENT_CLONE,
                           PTRACE_STOP_EXIT, SigActionFlags, SIG_BLOCK, SIG_DFL, SIG_SETMASK, SIG_UNBLOCK,
                           SIGCONT, SIGTERM, WaitFlags, WCONTINUED, WNOHANG, WUNTRACED};
use crate::syscall::ptrace_event;
use crate::syscall::validate::{validate_slice, validate_slice_mut};

pub fn clone(flags: CloneFlags, stack_base: usize) -> Result<ContextId> {
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
        let mut image = vec![];
        let mut stack_opt = None;
        let mut sigstack_opt = None;
        let mut grants;
        let name;
        let cwd;
        let files;
        let actions;

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

            if flags.contains(CLONE_VM) {
                for memory_shared in context.image.iter() {
                    image.push(memory_shared.clone());
                }
            } else {
                for memory_shared in context.image.iter() {
                    memory_shared.with(|memory| {
                        let mut new_memory = context::memory::Memory::new(
                            VirtualAddress::new(memory.start_address().data() + crate::USER_TMP_OFFSET),
                            memory.size(),
                            PageFlags::new().write(true),
                            false
                        );

                        unsafe {
                            intrinsics::copy(memory.start_address().data() as *const u8,
                                            new_memory.start_address().data() as *mut u8,
                                            memory.size());
                        }

                        new_memory.remap(memory.flags());
                        image.push(new_memory.to_shared());
                    });
                }
            }

            if let Some(ref stack_shared) = context.stack {
                if flags.contains(CLONE_STACK) {
                    stack_opt = Some(stack_shared.clone());
                } else {
                    stack_shared.with(|stack| {
                        let mut new_stack = context::memory::Memory::new(
                            VirtualAddress::new(crate::USER_TMP_STACK_OFFSET),
                            stack.size(),
                            PageFlags::new().write(true),
                            false
                        );

                        unsafe {
                            intrinsics::copy(stack.start_address().data() as *const u8,
                                            new_stack.start_address().data() as *mut u8,
                                            stack.size());
                        }

                        new_stack.remap(stack.flags());
                        stack_opt = Some(new_stack.to_shared());
                    });
                }
            }

            if let Some(ref sigstack) = context.sigstack {
                let mut new_sigstack = context::memory::Memory::new(
                    VirtualAddress::new(crate::USER_TMP_SIGSTACK_OFFSET),
                    sigstack.size(),
                    PageFlags::new().write(true),
                    false
                );

                unsafe {
                    intrinsics::copy(sigstack.start_address().data() as *const u8,
                                    new_sigstack.start_address().data() as *mut u8,
                                    sigstack.size());
                }

                new_sigstack.remap(sigstack.flags());
                sigstack_opt = Some(new_sigstack);
            }

            if flags.contains(CLONE_VM) {
                grants = Arc::clone(&context.grants);
            } else {
                let mut grants_set = UserGrants::default();
                for grant in context.grants.read().iter() {
                    let start = VirtualAddress::new(grant.start_address().data() + crate::USER_TMP_GRANT_OFFSET - crate::USER_GRANT_OFFSET);
                    grants_set.insert(grant.secret_clone(start));
                }
                grants = Arc::new(RwLock::new(grants_set));
            }

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

        // If not cloning virtual memory, use fmap to re-obtain every grant where possible
        if !flags.contains(CLONE_VM) {
            let grants = Arc::get_mut(&mut grants).ok_or(Error::new(EBUSY))?.get_mut();
            let old_grants = mem::take(&mut grants.inner);

            // TODO: Find some way to do this without having to allocate.

            // TODO: Check that the current process is not allowed to serve any scheme this logic
            // could interfere with. Deadlocks would otherwise seem inevitable.

            for mut grant in old_grants.into_iter() {
                let region = *grant.region();
                let address = region.start_address().data();
                let size = region.size();

                let new_grant = if let Some(ref mut file_ref) = grant.desc_opt.take() {
                    // TODO: Technically this is redundant as the grants are already secret_cloned.
                    // Maybe grants with fds can be excluded from that step?
                    grant.unmap();

                    let FileDescription { scheme, number, .. } = { *file_ref.desc.description.read() };
                    let scheme_arc = match crate::scheme::schemes().get(scheme) {
                        Some(s) => Arc::clone(s),
                        None => continue,
                    };
                    let map = crate::syscall::data::Map {
                        address,
                        size,
                        offset: file_ref.offset,
                        flags: file_ref.flags | MapFlags::MAP_FIXED_NOREPLACE,
                    };

                    let ptr = match scheme_arc.fmap(number, &map) {
                        Ok(new_range) => new_range as *mut u8,
                        Err(_) => continue,
                    };

                    // This will eventually be freed from the parent context after move_to is
                    // called.
                    context::contexts().current().ok_or(Error::new(ESRCH))?
                        .read().grants.write()
                        .take(&Region::new(VirtualAddress::new(ptr as usize), map.size))
                        .ok_or(Error::new(EFAULT))?
                } else {
                    grant
                };
                grants.insert(new_grant);
            }
        }

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
        {
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

            context.status = context::Status::Runnable;

            context.vfork = vfork;

            context.arch = arch;

            // This is needed because these registers may have changed after this context was
            // switched to, but before this was called.
            #[cfg(all(target_arch = "x86_64", feature = "x86_fsgsbase"))]
            unsafe {
                context.arch.fsbase = x86::bits64::segmentation::rdfsbase() as usize;
                context.arch.gsbase = x86::bits64::segmentation::rdgsbase() as usize;
            }

            let mut active_utable = unsafe { ActivePageTable::new(TableKind::User) };
            let active_ktable = unsafe { ActivePageTable::new(TableKind::Kernel) };

            let mut new_utable = unsafe {
                let frame = allocate_frames(1).ok_or(Error::new(ENOMEM))?;
                // SAFETY: This is safe because the frame is exclusive, owned, and valid, as we
                // have just allocated it.
                InactivePageTable::new(&mut active_utable, frame)
            };
            context.arch.set_page_utable(unsafe { new_utable.address() });

            #[cfg(target_arch = "aarch64")]
            let mut new_ktable = {
                let mut new_ktable = {
                    let frame = allocate_frames(1).expect("no more frames in syscall::clone new_table");
                    InactivePageTable::new(frame, &mut active_ktable)
                };
                context.arch.set_page_ktable(unsafe { new_ktable.address() });
                new_ktable
            };

            #[cfg(not(target_arch = "aarch64"))]
            let mut new_ktable = unsafe {
                InactivePageTable::from_address(new_utable.address())
            };

            // Copy kernel image mapping
            {
                let frame = active_ktable.p4()[crate::KERNEL_PML4].pointed_frame().expect("kernel image not mapped");
                let flags = active_ktable.p4()[crate::KERNEL_PML4].flags();

                new_ktable.mapper().p4_mut()[crate::KERNEL_PML4].set(frame, flags);
            }

            // Copy kernel heap mapping
            {
                let frame = active_ktable.p4()[crate::KERNEL_HEAP_PML4].pointed_frame().expect("kernel heap not mapped");
                let flags = active_ktable.p4()[crate::KERNEL_HEAP_PML4].flags();

                new_ktable.mapper().p4_mut()[crate::KERNEL_HEAP_PML4].set(frame, flags);
            }

            // Copy physmap mapping
            {
                let frame = active_ktable.p4()[crate::PHYS_PML4].pointed_frame().expect("physmap not mapped");
                let flags = active_ktable.p4()[crate::PHYS_PML4].flags();
                new_ktable.mapper().p4_mut()[crate::PHYS_PML4].set(frame, flags);
            }
            // Copy kernel percpu (similar to TLS) mapping.
            {
                let frame = active_ktable.p4()[crate::KERNEL_PERCPU_PML4].pointed_frame().expect("kernel TLS not mapped");
                let flags = active_ktable.p4()[crate::KERNEL_PERCPU_PML4].flags();
                new_ktable.mapper().p4_mut()[crate::KERNEL_PERCPU_PML4].set(frame, flags);
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

            // Setup image, heap, and grants
            if flags.contains(CLONE_VM) {
                // Copy user image mapping, if found
                if ! image.is_empty() {
                    let frame = active_utable.p4()[crate::USER_PML4].pointed_frame().expect("user image not mapped");
                    let flags = active_utable.p4()[crate::USER_PML4].flags();

                    new_utable.mapper().p4_mut()[crate::USER_PML4].set(frame, flags);
                }
                context.image = image;

                // Copy grant mapping
                if ! grants.read().is_empty() {
                    let frame = active_utable.p4()[crate::USER_GRANT_PML4].pointed_frame().expect("user grants not mapped");
                    let flags = active_utable.p4()[crate::USER_GRANT_PML4].flags();

                    new_utable.mapper().p4_mut()[crate::USER_GRANT_PML4].set(frame, flags);
                }
                context.grants = grants;
            } else {
                // Move copy of image
                for memory_shared in image.iter_mut() {
                    memory_shared.with(|memory| {
                        let start = VirtualAddress::new(memory.start_address().data() - crate::USER_TMP_OFFSET + crate::USER_OFFSET);
                        memory.move_to(start, &mut new_utable);
                    });
                }
                context.image = image;

                // Move grants
                {
                    let mut grants = grants.write();
                    let old_grants = mem::replace(&mut *grants, UserGrants::default());

                    for mut grant in old_grants.inner.into_iter() {
                        let start = VirtualAddress::new(grant.start_address().data() + crate::USER_GRANT_OFFSET - crate::USER_TMP_GRANT_OFFSET);
                        grant.move_to(start, &mut new_utable);
                        grants.insert(grant);
                    }
                }
                context.grants = grants;
            }

            // Setup user stack
            if let Some(stack_shared) = stack_opt {
                if flags.contains(CLONE_STACK) {
                    let frame = active_utable.p4()[crate::USER_STACK_PML4].pointed_frame().expect("user stack not mapped");
                    let flags = active_utable.p4()[crate::USER_STACK_PML4].flags();

                    new_utable.mapper().p4_mut()[crate::USER_STACK_PML4].set(frame, flags);
                } else {
                    stack_shared.with(|stack| {
                        stack.move_to(VirtualAddress::new(crate::USER_STACK_OFFSET), &mut new_utable);
                    });
                }
                context.stack = Some(stack_shared);
            }

            // Setup user sigstack
            if let Some(mut sigstack) = sigstack_opt {
                sigstack.move_to(VirtualAddress::new(crate::USER_SIGSTACK_OFFSET), &mut new_utable);
                context.sigstack = Some(sigstack);
            }

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
        }
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
    if reaping {
        // Memory should already be unmapped
        assert!(context.image.is_empty());
        assert!(context.stack.is_none());
        assert!(context.sigstack.is_none());
    } else {
        // Unmap previous image, heap, grants, stack
        context.image.clear();
        drop(context.stack.take());
        drop(context.sigstack.take());
    }

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
        // TODO: Use get_mut to bypass the need to acquire a lock when there we already have an
        // exclusive reference from `Arc::get_mut`. This will require updating `spin`.
        let mut grants_guard = grants_lock_mut.write();

        let grants = mem::replace(&mut *grants_guard, UserGrants::default());
        for grant in grants.inner.into_iter() {
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

#[allow(clippy::too_many_arguments)]
fn fexec_noreturn(
    setuid: Option<u32>,
    setgid: Option<u32>,
    name: Box<str>,
    data: Box<[u8]>,
    phdr_grant: context::memory::Grant,
    args: Box<[Box<[u8]>]>,
    vars: Box<[Box<[u8]>]>,
    auxv: Box<[usize]>,
) -> ! {
    let entry;
    let singlestep;
    let mut sp = crate::USER_STACK_OFFSET + crate::USER_STACK_SIZE - 256;

    {
        let (vfork, ppid, files) = {
            let contexts = context::contexts();
            let context_lock = contexts.current().ok_or(Error::new(ESRCH)).expect("exec_noreturn pid not found");
            let mut context = context_lock.write();

            singlestep = unsafe {
                ptrace::regs_for(&context).map(|s| s.is_singlestep()).unwrap_or(false)
            };

            context.name = Arc::new(RwLock::new(name));

            context = empty(&context_lock, context, false);

            context.grants.write().insert(phdr_grant);

            #[cfg(all(target_arch = "x86_64"))]
            {
                context.arch.fsbase = 0;
                context.arch.gsbase = 0;

                #[cfg(feature = "x86_fsgsbase")]
                unsafe {
                    x86::bits64::segmentation::wrfsbase(0);
                    x86::bits64::segmentation::swapgs();
                    x86::bits64::segmentation::wrgsbase(0);
                    x86::bits64::segmentation::swapgs();
                }
                #[cfg(not(feature = "x86_fsgsbase"))]
                unsafe {
                    x86::msr::wrmsr(x86::msr::IA32_FS_BASE, 0);
                    x86::msr::wrmsr(x86::msr::IA32_KERNEL_GSBASE, 0);
                }
            }

            if let Some(uid) = setuid {
                context.euid = uid;
            }

            if let Some(gid) = setgid {
                context.egid = gid;
            }

            // Map and copy new segments
            {
                let elf = elf::Elf::from(&data).unwrap();
                entry = elf.entry();

                for segment in elf.segments() {
                    match segment.p_type {
                        program_header::PT_LOAD => {
                            let voff = segment.p_vaddr as usize % PAGE_SIZE;
                            let vaddr = segment.p_vaddr as usize - voff;

                            let mut memory = context::memory::Memory::new(
                                VirtualAddress::new(vaddr),
                                segment.p_memsz as usize + voff,
                                PageFlags::new().write(true),
                                true
                            );

                            unsafe {
                                // Copy file data
                                intrinsics::copy((elf.data.as_ptr() as usize + segment.p_offset as usize) as *const u8,
                                                 segment.p_vaddr as *mut u8,
                                                 segment.p_filesz as usize);
                            }

                            let mut flags = PageFlags::new().user(true);

                            // W ^ X. If it is executable, do not allow it to be writable, even if requested
                            if segment.p_flags & program_header::PF_X == program_header::PF_X {
                                flags = flags.execute(true);
                            } else if segment.p_flags & program_header::PF_W == program_header::PF_W {
                                flags = flags.write(true);
                            }

                            memory.remap(flags);

                            context.image.push(memory.to_shared());
                        },
                        _ => (),
                    }
                }
            }

            // Map stack
            context.stack = Some(context::memory::Memory::new(
                VirtualAddress::new(crate::USER_STACK_OFFSET),
                crate::USER_STACK_SIZE,
                PageFlags::new().write(true).user(true),
                true
            ).to_shared());

            // Map stack
            context.sigstack = Some(context::memory::Memory::new(
                VirtualAddress::new(crate::USER_SIGSTACK_OFFSET),
                crate::USER_SIGSTACK_SIZE,
                PageFlags::new().write(true).user(true),
                true
            ));

            // Data no longer required, can deallocate
            drop(data);

            let mut push = |arg| {
                sp -= mem::size_of::<usize>();
                unsafe { *(sp as *mut usize) = arg; }
            };

            // Push auxiliary vector
            push(AT_NULL);
            for &arg in auxv.iter().rev() {
                push(arg);
            }

            drop(auxv); // no longer required

            let mut arg_size = 0;

            // Push environment variables and arguments
            for iter in &[&vars, &args] {
                // Push null-terminator
                push(0);

                // Push pointer to content
                for arg in iter.iter().rev() {
                    push(crate::USER_ARG_OFFSET + arg_size);
                    arg_size += arg.len() + 1;
                }
            }

            // For some reason, Linux pushes the argument count here (in
            // addition to being null-terminated), but not the environment
            // variable count.
            // TODO: Push more counts? Less? Stop having null-termination?
            push(args.len());

            // Write environment and argument pointers to USER_ARG_OFFSET
            if arg_size > 0 {
                let mut memory = context::memory::Memory::new(
                    VirtualAddress::new(crate::USER_ARG_OFFSET),
                    arg_size,
                    PageFlags::new().write(true),
                    true
                );

                let mut arg_offset = 0;
                for arg in vars.iter().rev().chain(args.iter().rev()) {
                    unsafe {
                        intrinsics::copy(arg.as_ptr(),
                               (crate::USER_ARG_OFFSET + arg_offset) as *mut u8,
                               arg.len());
                    }
                    arg_offset += arg.len();

                    unsafe {
                        *((crate::USER_ARG_OFFSET + arg_offset) as *mut u8) = 0;
                    }
                    arg_offset += 1;
                }

                memory.remap(PageFlags::new().user(true));

                context.image.push(memory.to_shared());
            }

            // Args and vars no longer required, can deallocate
            drop(args);
            drop(vars);

            context.actions = Arc::new(RwLock::new(vec![(
                SigAction {
                    sa_handler: unsafe { mem::transmute(SIG_DFL) },
                    sa_mask: [0; 2],
                    sa_flags: SigActionFlags::empty(),
                },
                0
            ); 128]));

            let vfork = context.vfork;
            context.vfork = false;

            let files = Arc::clone(&context.files);

            (vfork, context.ppid, files)
        };

        for (_fd, file_opt) in files.write().iter_mut().enumerate() {
            let mut cloexec = false;
            if let Some(ref file) = *file_opt {
                if file.cloexec {
                    cloexec = true;
                }
            }

            if cloexec {
                let _ = file_opt.take().unwrap().close();
            }
        }

        if vfork {
            let contexts = context::contexts();
            if let Some(context_lock) = contexts.get(ppid) {
                let mut context = context_lock.write();
                if ! context.unblock() {
                    println!("{} not blocked for exec vfork unblock", ppid.into());
                }
            } else {
                println!("{} not found for exec vfork unblock", ppid.into());
            }
        }
    }

    // Go to usermode
    unsafe { usermode(entry, sp, 0, usize::from(singlestep)) }
}

pub fn fexec_kernel(fd: FileHandle, args: Box<[Box<[u8]>]>, vars: Box<[Box<[u8]>]>, name_override_opt: Option<Box<str>>, auxv: Option<(Vec<usize>, context::memory::Grant)>) -> Result<usize> {
    let (uid, gid) = {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();
        (context.euid, context.egid)
    };

    let mut stat: Stat;
    let name: String;
    let mut data: Vec<u8>;
    {
        let file = ExecFile(fd);

        stat = Stat::default();
        syscall::file_op_mut_slice(syscall::number::SYS_FSTAT, file.0, &mut stat)?;

        let mut perm = stat.st_mode & 0o7;
        if stat.st_uid == uid {
            perm |= (stat.st_mode >> 6) & 0o7;
        }
        if stat.st_gid == gid {
            perm |= (stat.st_mode >> 3) & 0o7;
        }
        if uid == 0 {
            perm |= 0o7;
        }

        if perm & 0o1 != 0o1 {
            return Err(Error::new(EACCES));
        }

        if let Some(name_override) = name_override_opt {
            name = String::from(name_override);
        } else {
            let mut name_bytes = vec![0; 4096];
            let len = syscall::file_op_mut_slice(syscall::number::SYS_FPATH, file.0, &mut name_bytes)?;
            name_bytes.truncate(len);
            name = match String::from_utf8(name_bytes) {
                Ok(ok) => ok,
                Err(_err) => {
                    //TODO: print error?
                    return Err(Error::new(EINVAL));
                }
            };
        }

        //TODO: Only read elf header, not entire file. Then read required segments
        data = vec![0; stat.st_size as usize];
        syscall::file_op_mut_slice(syscall::number::SYS_READ, file.0, &mut data)?;
        drop(file);
    }

    // Set UID and GID are determined after resolving any hashbangs
    let setuid = if stat.st_mode & syscall::flag::MODE_SETUID == syscall::flag::MODE_SETUID {
        Some(stat.st_uid)
    } else {
        None
    };

    let setgid = if stat.st_mode & syscall::flag::MODE_SETGID == syscall::flag::MODE_SETGID {
        Some(stat.st_gid)
    } else {
        None
    };

    // The argument list is limited to avoid using too much userspace stack
    // This check is done last to allow all hashbangs to be resolved
    //
    // This should be based on the size of the userspace stack, divided
    // by the cost of each argument, which should be usize * 2, with
    // one additional argument added to represent the total size of the
    // argument pointer array and potential padding
    //
    // A limit of 4095 would mean a stack of (4095 + 1) * 8 * 2 = 65536, or 64KB
    if (args.len() + vars.len()) > 4095 {
        return Err(Error::new(E2BIG));
    }

    let elf = match elf::Elf::from(&data) {
        Ok(elf) => elf,
        Err(err) => {
            let contexts = context::contexts();
            if let Some(context_lock) = contexts.current() {
                let context = context_lock.read();
                println!(
                    "{}: {}: fexec failed to execute {}: {}",
                    context.id.into(),
                    *context.name.read(),
                    fd.into(),
                    err
                );
            }
            return Err(Error::new(ENOEXEC));
        }
    };

    // `fexec_kernel` can recurse if an interpreter is found. We get the
    // auxiliary vector from the first invocation, which is passed via an
    // argument, or if this is the first one we create it.
    let (auxv, phdr_grant) = if let Some((auxv, phdr_grant)) = auxv {
        (auxv, phdr_grant)
    } else {
        let phdr_grant = match context::contexts().current().ok_or(Error::new(ESRCH))?.read().grants.write() {
            grants => {
                let size = elf.program_headers_size() * elf.program_header_count();
                let aligned_size = (size + PAGE_SIZE - 1) / PAGE_SIZE * PAGE_SIZE;

                if aligned_size > MAX_PHDRS_SIZE {
                    return Err(Error::new(ENOMEM));
                }

                let phdrs_region = grants.find_free(aligned_size);
                let grant = context::memory::Grant::map(phdrs_region.start_address(), aligned_size, PageFlags::new().write(true).user(true));

                unsafe {
                    let dst = core::slice::from_raw_parts_mut(grant.start_address().data() as *mut u8, aligned_size);
                    dst[..size].copy_from_slice(&data[elf.program_headers()..elf.program_headers() + elf.program_headers_size() * elf.program_header_count()]);
                }

                grant
            }
        };
        let mut auxv = Vec::with_capacity(3);

        auxv.push(AT_ENTRY);
        auxv.push(elf.entry());
        auxv.push(AT_PHDR);
        auxv.push(phdr_grant.start_address().data());
        auxv.push(AT_PHENT);
        auxv.push(elf.program_headers_size());
        auxv.push(AT_PHNUM);
        auxv.push(elf.program_header_count());

        (auxv, phdr_grant)
    };

    // We check the validity of all loadable sections here
    for segment in elf.segments() {
        match segment.p_type {
            program_header::PT_INTERP => {
                //TODO: length restraint, parse interp earlier
                let mut interp = vec![0; segment.p_memsz as usize];
                unsafe {
                    intrinsics::copy((elf.data.as_ptr() as usize + segment.p_offset as usize) as *const u8,
                                     interp.as_mut_ptr(),
                                     segment.p_filesz as usize);
                }

                let mut i = 0;
                while i < interp.len() {
                    if interp[i] == 0 {
                        break;
                    }
                    i += 1;
                }
                interp.truncate(i);

                let interp_str = str::from_utf8(&interp).map_err(|_| Error::new(EINVAL))?;

                let interp_fd = super::fs::open(interp_str, super::flag::O_RDONLY | super::flag::O_CLOEXEC)?;

                let mut args_vec = Vec::from(args);
                //TODO: pass file handle in auxv
                let name_override = name.into_boxed_str();
                args_vec[0] = name_override.clone().into();

                // Drop variables, since fexec_kernel probably won't return
                drop(elf);
                drop(interp);

                return fexec_kernel(
                    interp_fd,
                    args_vec.into_boxed_slice(),
                    vars,
                    Some(name_override),
                    Some((auxv, phdr_grant)),
                );
            },
            _ => (),
        }
    }

    // This is the point of no return, quite literaly. Any checks for validity need
    // to be done before, and appropriate errors returned. Otherwise, we have nothing
    // to return to.
    fexec_noreturn(setuid, setgid, name.into_boxed_str(), data.into_boxed_slice(), phdr_grant, args, vars, auxv.into_boxed_slice());
}
const MAX_PHDRS_SIZE: usize = PAGE_SIZE;

pub fn fexec(fd: FileHandle, arg_ptrs: &[[usize; 2]], var_ptrs: &[[usize; 2]]) -> Result<usize> {
    let mut args = Vec::new();
    for arg_ptr in arg_ptrs {
        let arg = validate_slice(arg_ptr[0] as *const u8, arg_ptr[1])?;
        // Argument must be moved into kernel space before exec unmaps all memory
        args.push(arg.to_vec().into_boxed_slice());
    }

    let mut vars = Vec::new();
    for var_ptr in var_ptrs {
        let var = validate_slice(var_ptr[0] as *const u8, var_ptr[1])?;
        // Argument must be moved into kernel space before exec unmaps all memory
        vars.push(var.to_vec().into_boxed_slice());
    }

    // Neither arg_ptrs nor var_ptrs should be used after this point, the kernel
    // now has owned copies in args and vars

    fexec_kernel(fd, args.into_boxed_slice(), vars.into_boxed_slice(), None, None)
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
    if sig > 0 && sig <= 0x7F {
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
    } else {
        Err(Error::new(EINVAL))
    }
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
