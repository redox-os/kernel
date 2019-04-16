use alloc::sync::Arc;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::{intrinsics, mem};
use core::ops::DerefMut;
use spin::Mutex;

use memory::allocate_frames;
use paging::{ActivePageTable, InactivePageTable, Page, VirtualAddress, PAGE_SIZE};
use paging::entry::EntryFlags;
use paging::mapper::MapperFlushAll;
use paging::temporary_page::TemporaryPage;
use start::usermode;
use interrupt;
use context;
use context::{ContextId, WaitpidKey};
use context::file::FileDescriptor;
#[cfg(not(feature="doc"))]
use elf::{self, program_header};
use ipi::{ipi, IpiKind, IpiTarget};
use scheme::FileHandle;
use syscall;
use syscall::data::{SigAction, Stat};
use syscall::error::*;
use syscall::flag::{CLONE_VFORK, CLONE_VM, CLONE_FS, CLONE_FILES, CLONE_SIGHAND, CLONE_STACK,
                    PROT_EXEC, PROT_READ, PROT_WRITE, SIG_DFL, SIGCONT, SIGTERM,
                    WCONTINUED, WNOHANG, WUNTRACED, wifcontinued, wifstopped};
use syscall::validate::{validate_slice, validate_slice_mut};

pub fn brk(address: usize) -> Result<usize> {
    let contexts = context::contexts();
    let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
    let context = context_lock.read();

    //println!("{}: {}: BRK {:X}", unsafe { ::core::str::from_utf8_unchecked(&context.name.lock()) },
    //                             context.id.into(), address);

    let current = if let Some(ref heap_shared) = context.heap {
        heap_shared.with(|heap| {
            heap.start_address().get() + heap.size()
        })
    } else {
        panic!("user heap not initialized");
    };

    if address == 0 {
        //println!("Brk query {:X}", current);
        Ok(current)
    } else if address >= ::USER_HEAP_OFFSET {
        //TODO: out of memory errors
        if let Some(ref heap_shared) = context.heap {
            heap_shared.with(|heap| {
                heap.resize(address - ::USER_HEAP_OFFSET, true);
            });
        } else {
            panic!("user heap not initialized");
        }

        //println!("Brk resize {:X}", address);
        Ok(address)
    } else {
        //println!("Brk no mem");
        Err(Error::new(ENOMEM))
    }
}

pub fn clone(flags: usize, stack_base: usize) -> Result<ContextId> {
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
        let mut cpu_id = None;
        let arch;
        let vfork;
        let mut kfx_option = None;
        let mut kstack_option = None;
        let mut offset = 0;
        let mut image = vec![];
        let mut heap_option = None;
        let mut stack_option = None;
        let mut sigstack_option = None;
        let mut tls_option = None;
        let grants;
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
            umask = context.umask;

            if flags & CLONE_VM == CLONE_VM {
                cpu_id = context.cpu_id;
            }

            arch = context.arch.clone();

            if let Some(ref fx) = context.kfx {
                let mut new_fx = unsafe { Box::from_raw(::ALLOCATOR.alloc(Layout::from_size_align_unchecked(512, 16)) as *mut [u8; 512]) };
                for (new_b, b) in new_fx.iter_mut().zip(fx.iter()) {
                    *new_b = *b;
                }
                kfx_option = Some(new_fx);
            }

            if let Some(ref stack) = context.kstack {
                offset = stack_base - stack.as_ptr() as usize - mem::size_of::<usize>(); // Add clone ret
                let mut new_stack = stack.clone();

                unsafe {
                    let func_ptr = new_stack.as_mut_ptr().offset(offset as isize);
                    *(func_ptr as *mut usize) = interrupt::syscall::clone_ret as usize;
                }

                kstack_option = Some(new_stack);
            }

            if flags & CLONE_VM == CLONE_VM {
                for memory_shared in context.image.iter() {
                    image.push(memory_shared.clone());
                }

                if let Some(ref heap_shared) = context.heap {
                    heap_option = Some(heap_shared.clone());
                }
            } else {
                for memory_shared in context.image.iter() {
                    memory_shared.with(|memory| {
                        let mut new_memory = context::memory::Memory::new(
                            VirtualAddress::new(memory.start_address().get() + ::USER_TMP_OFFSET),
                            memory.size(),
                            EntryFlags::PRESENT | EntryFlags::NO_EXECUTE | EntryFlags::WRITABLE,
                            false
                        );

                        unsafe {
                            intrinsics::copy(memory.start_address().get() as *const u8,
                                            new_memory.start_address().get() as *mut u8,
                                            memory.size());
                        }

                        new_memory.remap(memory.flags());
                        image.push(new_memory.to_shared());
                    });
                }

                if let Some(ref heap_shared) = context.heap {
                    heap_shared.with(|heap| {
                        let mut new_heap = context::memory::Memory::new(
                            VirtualAddress::new(::USER_TMP_HEAP_OFFSET),
                            heap.size(),
                            EntryFlags::PRESENT | EntryFlags::NO_EXECUTE | EntryFlags::WRITABLE,
                            false
                        );

                        unsafe {
                            intrinsics::copy(heap.start_address().get() as *const u8,
                                            new_heap.start_address().get() as *mut u8,
                                            heap.size());
                        }

                        new_heap.remap(heap.flags());
                        heap_option = Some(new_heap.to_shared());
                    });
                }
            }

            if let Some(ref stack_shared) = context.stack {
                if flags & CLONE_STACK == CLONE_STACK {
                    stack_option = Some(stack_shared.clone());
                } else {
                    stack_shared.with(|stack| {
                        let mut new_stack = context::memory::Memory::new(
                            VirtualAddress::new(::USER_TMP_STACK_OFFSET),
                            stack.size(),
                            EntryFlags::PRESENT | EntryFlags::NO_EXECUTE | EntryFlags::WRITABLE,
                            false
                        );

                        unsafe {
                            intrinsics::copy(stack.start_address().get() as *const u8,
                                            new_stack.start_address().get() as *mut u8,
                                            stack.size());
                        }

                        new_stack.remap(stack.flags());
                        stack_option = Some(new_stack.to_shared());
                    });
                }
            }

            if let Some(ref sigstack) = context.sigstack {
                let mut new_sigstack = context::memory::Memory::new(
                    VirtualAddress::new(::USER_TMP_SIGSTACK_OFFSET),
                    sigstack.size(),
                    EntryFlags::PRESENT | EntryFlags::NO_EXECUTE | EntryFlags::WRITABLE,
                    false
                );

                unsafe {
                    intrinsics::copy(sigstack.start_address().get() as *const u8,
                                    new_sigstack.start_address().get() as *mut u8,
                                    sigstack.size());
                }

                new_sigstack.remap(sigstack.flags());
                sigstack_option = Some(new_sigstack);
            }

            if let Some(ref tls) = context.tls {
                let mut new_tls = context::memory::Tls {
                    master: tls.master,
                    file_size: tls.file_size,
                    mem: context::memory::Memory::new(
                        VirtualAddress::new(::USER_TMP_TLS_OFFSET),
                        tls.mem.size(),
                        EntryFlags::PRESENT | EntryFlags::NO_EXECUTE | EntryFlags::WRITABLE,
                        true
                    ),
                    offset: tls.offset,
                };


                if flags & CLONE_VM == CLONE_VM {
                    unsafe {
                        new_tls.load();
                    }
                } else {
                    unsafe {
                        intrinsics::copy(tls.mem.start_address().get() as *const u8,
                                        new_tls.mem.start_address().get() as *mut u8,
                                        tls.mem.size());
                    }
                }

                new_tls.mem.remap(tls.mem.flags());
                tls_option = Some(new_tls);
            }

            if flags & CLONE_VM == CLONE_VM {
                grants = Arc::clone(&context.grants);
            } else {
                let mut grants_vec = Vec::new();
                for grant in context.grants.lock().iter() {
                    let start = VirtualAddress::new(grant.start_address().get() + ::USER_TMP_GRANT_OFFSET - ::USER_GRANT_OFFSET);
                    grants_vec.push(grant.secret_clone(start));
                }
                grants = Arc::new(Mutex::new(grants_vec));
            }

            if flags & CLONE_VM == CLONE_VM {
                name = Arc::clone(&context.name);
            } else {
                name = Arc::new(Mutex::new(context.name.lock().clone()));
            }

            if flags & CLONE_FS == CLONE_FS {
                cwd = Arc::clone(&context.cwd);
            } else {
                cwd = Arc::new(Mutex::new(context.cwd.lock().clone()));
            }

            if flags & CLONE_FILES == CLONE_FILES {
                files = Arc::clone(&context.files);
            } else {
                files = Arc::new(Mutex::new(context.files.lock().clone()));
            }

            if flags & CLONE_SIGHAND == CLONE_SIGHAND {
                actions = Arc::clone(&context.actions);
            } else {
                actions = Arc::new(Mutex::new(context.actions.lock().clone()));
            }
        }

        // If not cloning files, dup to get a new number from scheme
        // This has to be done outside the context lock to prevent deadlocks
        if flags & CLONE_FILES == 0 {
            for (_fd, file_option) in files.lock().iter_mut().enumerate() {
                let new_file_option = if let Some(ref file) = *file_option {
                    Some(FileDescriptor {
                        description: Arc::clone(&file.description),
                        cloexec: file.cloexec,
                    })
                } else {
                    None
                };

                *file_option = new_file_option;
            }
        }

        // If not cloning virtual memory, use fmap to re-obtain every grant where possible
        if flags & CLONE_VM == 0 {
            let mut i = 0;
            while i < grants.lock().len() {
                let mut remove = false;
                if let Some(grant) = grants.lock().get(i) {
                    if let Some(ref _desc) = grant.desc_opt {
                        println!("todo: clone grant {} using fmap: {:?}", i, grant);
                    }
                }
                if remove {
                    grants.lock().remove(i);
                } else {
                    i += 1;
                }
            }
        }

        // If vfork, block the current process
        // This has to be done after the operations that may require context switches
        if flags & CLONE_VFORK == CLONE_VFORK {
            let contexts = context::contexts();
            let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
            let mut context = context_lock.write();
            context.block();
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
            context.umask = umask;

            context.cpu_id = cpu_id;

            context.status = context::Status::Runnable;

            context.vfork = vfork;

            context.arch = arch;

            let mut active_table = unsafe { ActivePageTable::new() };

            let mut temporary_page = TemporaryPage::new(Page::containing_address(VirtualAddress::new(::USER_TMP_MISC_OFFSET)));

            let mut new_table = {
                let frame = allocate_frames(1).expect("no more frames in syscall::clone new_table");
                InactivePageTable::new(frame, &mut active_table, &mut temporary_page)
            };

            context.arch.set_page_table(unsafe { new_table.address() });

            // Copy kernel image mapping
            {
                let frame = active_table.p4()[::KERNEL_PML4].pointed_frame().expect("kernel image not mapped");
                let flags = active_table.p4()[::KERNEL_PML4].flags();
                active_table.with(&mut new_table, &mut temporary_page, |mapper| {
                    mapper.p4_mut()[::KERNEL_PML4].set(frame, flags);
                });
            }

            // Copy kernel heap mapping
            {
                let frame = active_table.p4()[::KERNEL_HEAP_PML4].pointed_frame().expect("kernel heap not mapped");
                let flags = active_table.p4()[::KERNEL_HEAP_PML4].flags();
                active_table.with(&mut new_table, &mut temporary_page, |mapper| {
                    mapper.p4_mut()[::KERNEL_HEAP_PML4].set(frame, flags);
                });
            }

            if let Some(fx) = kfx_option.take() {
                context.arch.set_fx(fx.as_ptr() as usize);
                context.kfx = Some(fx);
            }

            // Set kernel stack
            if let Some(stack) = kstack_option.take() {
                context.arch.set_stack(stack.as_ptr() as usize + offset);
                context.kstack = Some(stack);
            }

            // TODO: Clone ksig?

            // Setup image, heap, and grants
            if flags & CLONE_VM == CLONE_VM {
                // Copy user image mapping, if found
                if ! image.is_empty() {
                    let frame = active_table.p4()[::USER_PML4].pointed_frame().expect("user image not mapped");
                    let flags = active_table.p4()[::USER_PML4].flags();
                    active_table.with(&mut new_table, &mut temporary_page, |mapper| {
                        mapper.p4_mut()[::USER_PML4].set(frame, flags);
                    });
                }
                context.image = image;

                // Copy user heap mapping, if found
                if let Some(heap_shared) = heap_option {
                    let frame = active_table.p4()[::USER_HEAP_PML4].pointed_frame().expect("user heap not mapped");
                    let flags = active_table.p4()[::USER_HEAP_PML4].flags();
                    active_table.with(&mut new_table, &mut temporary_page, |mapper| {
                        mapper.p4_mut()[::USER_HEAP_PML4].set(frame, flags);
                    });
                    context.heap = Some(heap_shared);
                }

                // Copy grant mapping
                if ! grants.lock().is_empty() {
                    let frame = active_table.p4()[::USER_GRANT_PML4].pointed_frame().expect("user grants not mapped");
                    let flags = active_table.p4()[::USER_GRANT_PML4].flags();
                    active_table.with(&mut new_table, &mut temporary_page, |mapper| {
                        mapper.p4_mut()[::USER_GRANT_PML4].set(frame, flags);
                    });
                }
                context.grants = grants;
            } else {
                // Copy percpu mapping
                for cpu_id in 0..::cpu_count() {
                    extern {
                        // The starting byte of the thread data segment
                        static mut __tdata_start: u8;
                        // The ending byte of the thread BSS segment
                        static mut __tbss_end: u8;
                    }

                    let size = unsafe { & __tbss_end as *const _ as usize - & __tdata_start as *const _ as usize };

                    let start = ::KERNEL_PERCPU_OFFSET + ::KERNEL_PERCPU_SIZE * cpu_id;
                    let end = start + size;

                    let start_page = Page::containing_address(VirtualAddress::new(start));
                    let end_page = Page::containing_address(VirtualAddress::new(end - 1));
                    for page in Page::range_inclusive(start_page, end_page) {
                        let frame = active_table.translate_page(page).expect("kernel percpu not mapped");
                        active_table.with(&mut new_table, &mut temporary_page, |mapper| {
                            let result = mapper.map_to(page, frame, EntryFlags::PRESENT | EntryFlags::NO_EXECUTE | EntryFlags::WRITABLE);
                            // Ignore result due to operating on inactive table
                            unsafe { result.ignore(); }
                        });
                    }
                }

                // Move copy of image
                for memory_shared in image.iter_mut() {
                    memory_shared.with(|memory| {
                        let start = VirtualAddress::new(memory.start_address().get() - ::USER_TMP_OFFSET + ::USER_OFFSET);
                        memory.move_to(start, &mut new_table, &mut temporary_page);
                    });
                }
                context.image = image;

                // Move copy of heap
                if let Some(heap_shared) = heap_option {
                    heap_shared.with(|heap| {
                        heap.move_to(VirtualAddress::new(::USER_HEAP_OFFSET), &mut new_table, &mut temporary_page);
                    });
                    context.heap = Some(heap_shared);
                }

                // Move grants
                for grant in grants.lock().iter_mut() {
                    let start = VirtualAddress::new(grant.start_address().get() + ::USER_GRANT_OFFSET - ::USER_TMP_GRANT_OFFSET);
                    grant.move_to(start, &mut new_table, &mut temporary_page);
                }
                context.grants = grants;
            }

            // Setup user stack
            if let Some(stack_shared) = stack_option {
                if flags & CLONE_STACK == CLONE_STACK {
                    let frame = active_table.p4()[::USER_STACK_PML4].pointed_frame().expect("user stack not mapped");
                    let flags = active_table.p4()[::USER_STACK_PML4].flags();
                    active_table.with(&mut new_table, &mut temporary_page, |mapper| {
                        mapper.p4_mut()[::USER_STACK_PML4].set(frame, flags);
                    });
                } else {
                    stack_shared.with(|stack| {
                        stack.move_to(VirtualAddress::new(::USER_STACK_OFFSET), &mut new_table, &mut temporary_page);
                    });
                }
                context.stack = Some(stack_shared);
            }

            // Setup user sigstack
            if let Some(mut sigstack) = sigstack_option {
                sigstack.move_to(VirtualAddress::new(::USER_SIGSTACK_OFFSET), &mut new_table, &mut temporary_page);
                context.sigstack = Some(sigstack);
            }

            // Set up TCB
            let tcb_addr = ::USER_TCB_OFFSET + context.id.into() * PAGE_SIZE;
            let mut tcb = context::memory::Memory::new(
                VirtualAddress::new(tcb_addr),
                PAGE_SIZE,
                EntryFlags::NO_EXECUTE | EntryFlags::WRITABLE | EntryFlags::USER_ACCESSIBLE,
                true
            );

            // Setup user TLS
            if let Some(mut tls) = tls_option {
                tls.mem.move_to(VirtualAddress::new(::USER_TLS_OFFSET), &mut new_table, &mut temporary_page);
                unsafe {
                    *(tcb_addr as *mut usize) = tls.mem.start_address().get() + tls.mem.size();
                }
                context.tls = Some(tls);
            } else {
                let parent_tcb_addr = ::USER_TCB_OFFSET + ppid.into() * PAGE_SIZE;
                unsafe {
                    intrinsics::copy(parent_tcb_addr as *const u8,
                                    tcb_addr as *mut u8,
                                    tcb.size());
                }
            }

            tcb.move_to(VirtualAddress::new(tcb_addr), &mut new_table, &mut temporary_page);
            context.image.push(tcb.to_shared());

            context.name = name;

            context.cwd = cwd;

            context.files = files;

            context.actions = actions;
        }
    }

    // Race to pick up the new process!
    ipi(IpiKind::Switch, IpiTarget::Other);

    let _ = unsafe { context::switch() };

    Ok(pid)
}

fn empty(context: &mut context::Context, reaping: bool) {
    if reaping {
        // Memory should already be unmapped
        assert!(context.image.is_empty());
        assert!(context.heap.is_none());
        assert!(context.stack.is_none());
        assert!(context.sigstack.is_none());
        assert!(context.tls.is_none());
    } else {
        // Unmap previous image, heap, grants, stack, and tls
        context.image.clear();
        drop(context.heap.take());
        drop(context.stack.take());
        drop(context.sigstack.take());
        drop(context.tls.take());
    }

    let mut grants = context.grants.lock();
    if Arc::strong_count(&context.grants) == 1 {
        for grant in grants.drain(..) {
            if reaping {
                println!("{}: {}: Grant should not exist: {:?}", context.id.into(), unsafe { ::core::str::from_utf8_unchecked(&context.name.lock()) }, grant);

                let mut new_table = unsafe { InactivePageTable::from_address(context.arch.get_page_table()) };
                let mut temporary_page = TemporaryPage::new(Page::containing_address(VirtualAddress::new(::USER_TMP_GRANT_OFFSET)));

                grant.unmap_inactive(&mut new_table, &mut temporary_page);
            } else {
                grant.unmap();
            }
        }
    }
}

struct ExecFile(FileHandle);

impl Drop for ExecFile {
    fn drop(&mut self) {
        let _ = syscall::close(self.0);
    }
}

fn fexec_noreturn(
    setuid: Option<u32>,
    setgid: Option<u32>,
    name: Box<[u8]>,
    data: Box<[u8]>,
    args: Box<[Box<[u8]>]>,
    vars: Box<[Box<[u8]>]>
) -> ! {
    let entry;
    let mut sp = ::USER_STACK_OFFSET + ::USER_STACK_SIZE - 256;

    {
        let (vfork, ppid, files) = {
            let contexts = context::contexts();
            let context_lock = contexts.current().ok_or(Error::new(ESRCH)).expect("exec_noreturn pid not found");
            let mut context = context_lock.write();

            context.name = Arc::new(Mutex::new(name));

            empty(&mut context, false);

            if let Some(uid) = setuid {
                context.euid = uid;
            }

            if let Some(gid) = setgid {
                context.egid = gid;
            }

            // Map and copy new segments
            let mut tls_option = None;
            {
                let elf = elf::Elf::from(&data).unwrap();
                entry = elf.entry();

                // Always map TCB
                let tcb_addr = ::USER_TCB_OFFSET + context.id.into() * PAGE_SIZE;
                let tcb_mem = context::memory::Memory::new(
                    VirtualAddress::new(tcb_addr),
                    PAGE_SIZE,
                    EntryFlags::NO_EXECUTE | EntryFlags::WRITABLE | EntryFlags::USER_ACCESSIBLE,
                    true
                );

                for segment in elf.segments() {
                    match segment.p_type {
                        program_header::PT_LOAD => {
                            let voff = segment.p_vaddr as usize % PAGE_SIZE;
                            let vaddr = segment.p_vaddr as usize - voff;

                            let mut memory = context::memory::Memory::new(
                                VirtualAddress::new(vaddr),
                                segment.p_memsz as usize + voff,
                                EntryFlags::NO_EXECUTE | EntryFlags::WRITABLE,
                                true
                            );

                            unsafe {
                                // Copy file data
                                intrinsics::copy((elf.data.as_ptr() as usize + segment.p_offset as usize) as *const u8,
                                                segment.p_vaddr as *mut u8,
                                                segment.p_filesz as usize);
                            }

                            let mut flags = EntryFlags::NO_EXECUTE | EntryFlags::USER_ACCESSIBLE;

                            if segment.p_flags & program_header::PF_R == program_header::PF_R {
                                flags.insert(EntryFlags::PRESENT);
                            }

                            // W ^ X. If it is executable, do not allow it to be writable, even if requested
                            if segment.p_flags & program_header::PF_X == program_header::PF_X {
                                flags.remove(EntryFlags::NO_EXECUTE);
                            } else if segment.p_flags & program_header::PF_W == program_header::PF_W {
                                flags.insert(EntryFlags::WRITABLE);
                            }

                            memory.remap(flags);

                            context.image.push(memory.to_shared());
                        },
                        program_header::PT_TLS => {
                            let aligned_size = if segment.p_align > 0 {
                                ((segment.p_memsz + (segment.p_align - 1))/segment.p_align) * segment.p_align
                            } else {
                                segment.p_memsz
                            } as usize;
                            let rounded_size = ((aligned_size + PAGE_SIZE - 1)/PAGE_SIZE) * PAGE_SIZE;
                            let rounded_offset = rounded_size - aligned_size;

                            let tls = context::memory::Tls {
                                master: VirtualAddress::new(segment.p_vaddr as usize),
                                file_size: segment.p_filesz as usize,
                                mem: context::memory::Memory::new(
                                    VirtualAddress::new(::USER_TLS_OFFSET),
                                    rounded_size as usize,
                                    EntryFlags::NO_EXECUTE | EntryFlags::WRITABLE | EntryFlags::USER_ACCESSIBLE,
                                    true
                                ),
                                offset: rounded_offset as usize,
                            };

                            unsafe {
                                *(tcb_addr as *mut usize) = ::USER_TLS_OFFSET + tls.mem.size();
                            }

                            tls_option = Some(tls);
                        },
                        _ => (),
                    }
                }

                context.image.push(tcb_mem.to_shared());
            }

            // Data no longer required, can deallocate
            drop(data);

            // Map heap
            context.heap = Some(context::memory::Memory::new(
                VirtualAddress::new(::USER_HEAP_OFFSET),
                0,
                EntryFlags::NO_EXECUTE | EntryFlags::WRITABLE | EntryFlags::USER_ACCESSIBLE,
                true
            ).to_shared());

            // Map stack
            context.stack = Some(context::memory::Memory::new(
                VirtualAddress::new(::USER_STACK_OFFSET),
                ::USER_STACK_SIZE,
                EntryFlags::NO_EXECUTE | EntryFlags::WRITABLE | EntryFlags::USER_ACCESSIBLE,
                true
            ).to_shared());

            // Map stack
            context.sigstack = Some(context::memory::Memory::new(
                VirtualAddress::new(::USER_SIGSTACK_OFFSET),
                ::USER_SIGSTACK_SIZE,
                EntryFlags::NO_EXECUTE | EntryFlags::WRITABLE | EntryFlags::USER_ACCESSIBLE,
                true
            ));

            // Map TLS
            if let Some(mut tls) = tls_option {
                unsafe {
                    tls.load();
                }

                context.tls = Some(tls);
            }

            let mut arg_size = 0;

            // Push arguments and variables
            for iter in &[&vars, &args] {
                // Push null-terminator
                sp -= mem::size_of::<usize>();
                unsafe { *(sp as *mut usize) = 0; }

                // Push content
                for arg in iter.iter().rev() {
                    sp -= mem::size_of::<usize>();
                    unsafe { *(sp as *mut usize) = ::USER_ARG_OFFSET + arg_size; }

                    arg_size += arg.len() + 1;
                }
            }

            // Push arguments length
            sp -= mem::size_of::<usize>();
            unsafe { *(sp as *mut usize) = args.len(); }

            if arg_size > 0 {
                let mut memory = context::memory::Memory::new(
                    VirtualAddress::new(::USER_ARG_OFFSET),
                    arg_size,
                    EntryFlags::NO_EXECUTE | EntryFlags::WRITABLE,
                    true
                );

                let mut arg_offset = 0;
                for arg in vars.iter().rev().chain(args.iter().rev()) {
                    unsafe {
                        intrinsics::copy(arg.as_ptr(),
                               (::USER_ARG_OFFSET + arg_offset) as *mut u8,
                               arg.len());
                    }
                    arg_offset += arg.len();

                    unsafe {
                        *((::USER_ARG_OFFSET + arg_offset) as *mut u8) = 0;
                    }
                    arg_offset += 1;
                }

                memory.remap(EntryFlags::NO_EXECUTE | EntryFlags::USER_ACCESSIBLE);

                context.image.push(memory.to_shared());
            }

            // Args no longer required, can deallocate
            drop(args);

            context.actions = Arc::new(Mutex::new(vec![(
                SigAction {
                    sa_handler: unsafe { mem::transmute(SIG_DFL) },
                    sa_mask: [0; 2],
                    sa_flags: 0,
                },
                0
            ); 128]));

            let vfork = context.vfork;
            context.vfork = false;

            let files = Arc::clone(&context.files);

            (vfork, context.ppid, files)
        };

        for (_fd, file_option) in files.lock().iter_mut().enumerate() {
            let mut cloexec = false;
            if let Some(ref file) = *file_option {
                if file.cloexec {
                    cloexec = true;
                }
            }

            if cloexec {
                let _ = file_option.take().unwrap().close();
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
    unsafe { usermode(entry, sp, 0); }
}

pub fn fexec_kernel(fd: FileHandle, args: Box<[Box<[u8]>]>, vars: Box<[Box<[u8]>]>, name_override_opt: Option<Box<[u8]>>) -> Result<usize> {
    let (uid, gid) = {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();
        (context.euid, context.egid)
    };

    let mut stat: Stat;
    let mut name: Vec<u8>;
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
            name = Vec::from(name_override);
        } else {
            name = vec![0; 4096];
            let len = syscall::file_op_mut_slice(syscall::number::SYS_FPATH, file.0, &mut name)?;
            name.truncate(len);
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

    match elf::Elf::from(&data) {
        Ok(elf) => {
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

                        println!("  interpreter: {:?}", ::core::str::from_utf8(&interp));

                        let interp_fd = super::fs::open(&interp, super::flag::O_RDONLY | super::flag::O_CLOEXEC)?;

                        let mut args_vec = Vec::from(args);
                        args_vec.insert(0, interp.into_boxed_slice());
                        //TODO: pass file handle in auxv
                        let name_override = name.into_boxed_slice();
                        args_vec[1] = name_override.clone();

                        return fexec_kernel(
                            interp_fd,
                            args_vec.into_boxed_slice(),
                            vars,
                            Some(name_override),
                        );
                    },
                    program_header::PT_LOAD => {
                        let voff = segment.p_vaddr as usize % PAGE_SIZE;
                        let vaddr = segment.p_vaddr as usize - voff;

                        // Due to the Userspace and kernel TLS bases being located right above 2GB,
                        // limit any loadable sections to lower than that. Eventually we will need
                        // to replace this with a more intelligent TLS address
                        if vaddr >= 0x8000_0000 {
                            println!("exec: invalid section address {:X}", segment.p_vaddr);
                            return Err(Error::new(ENOEXEC));
                        }
                    },
                    _ => (),
                }
            }
        },
        Err(err) => {
            println!("fexec: failed to execute {}: {}", fd.into(), err);
            return Err(Error::new(ENOEXEC));
        }
    }

    // This is the point of no return, quite literaly. Any checks for validity need
    // to be done before, and appropriate errors returned. Otherwise, we have nothing
    // to return to.
    fexec_noreturn(setuid, setgid, name.into_boxed_slice(), data.into_boxed_slice(), args, vars);
}

pub fn fexec(fd: FileHandle, arg_ptrs: &[[usize; 2]], var_ptrs: &[[usize; 2]]) -> Result<usize> {
    let mut args = Vec::new();
    for arg_ptr in arg_ptrs {
        let arg = validate_slice(arg_ptr[0] as *const u8, arg_ptr[1])?;
        // Argument must be moved into kernel space before exec unmaps all memory
        args.push(arg.to_vec().into_boxed_slice());
    }
    drop(arg_ptrs);

    let mut vars = Vec::new();
    for var_ptr in var_ptrs {
        let var = validate_slice(var_ptr[0] as *const u8, var_ptr[1])?;
        // Argument must be moved into kernel space before exec unmaps all memory
        vars.push(var.to_vec().into_boxed_slice());
    }
    drop(var_ptrs);

    fexec_kernel(fd, args.into_boxed_slice(), vars.into_boxed_slice(), None)
}

pub fn exit(status: usize) -> ! {
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
                let mut lock = context.files.lock();
                if Arc::strong_count(&context.files) == 1 {
                    mem::swap(lock.deref_mut(), &mut close_files);
                }
            }
            context.files = Arc::new(Mutex::new(Vec::new()));
            context.id
        };

        // Files must be closed while context is valid so that messages can be passed
        for (_fd, file_option) in close_files.drain(..).enumerate() {
            if let Some(file) = file_option {
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

            empty(&mut context, false);

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
                    if vfork {
                        if ! parent.unblock() {
                            println!("{}: {} not blocked for exit vfork unblock", pid.into(), ppid.into());
                        }
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

pub fn mprotect(address: usize, size: usize, flags: usize) -> Result<usize> {
    println!("mprotect {:#X}, {}, {:#X}", address, size, flags);

    let end_offset = size.checked_sub(1).ok_or(Error::new(EFAULT))?;
    let end_address = address.checked_add(end_offset).ok_or(Error::new(EFAULT))?;

    let mut active_table = unsafe { ActivePageTable::new() };

    let mut flush_all = MapperFlushAll::new();

    let start_page = Page::containing_address(VirtualAddress::new(address));
    let end_page = Page::containing_address(VirtualAddress::new(end_address));
    for page in Page::range_inclusive(start_page, end_page) {
        if let Some(mut page_flags) = active_table.translate_page_flags(page) {
            if flags & PROT_EXEC > 0 {
                page_flags.remove(EntryFlags::NO_EXECUTE);
            } else {
                page_flags.insert(EntryFlags::NO_EXECUTE);
            }

            if flags & PROT_WRITE > 0 {
                //TODO: Not allowing gain of write privileges
            } else {
                page_flags.remove(EntryFlags::WRITABLE);
            }

            if flags & PROT_READ > 0 {
                //TODO: No flags for readable pages
            } else {
                //TODO: No flags for readable pages
            }

            let flush = active_table.remap(page, page_flags);
            flush_all.consume(flush);
        } else {
            return Err(Error::new(EFAULT));
        }
    }

    flush_all.flush(&mut active_table);

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
        let mut actions = context.actions.lock();

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
    println!("sigprocmask {}, {:?}, {:?}", how, mask_opt, oldmask_opt);
    Ok(0)
}

pub fn sigreturn() -> Result<usize> {
    {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let mut context = context_lock.write();
        context.ksig_restore = true;
        context.block();
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
        empty(&mut context, true);
    }
    drop(context_lock);

    Ok(pid)
}

pub fn waitpid(pid: ContextId, status_ptr: usize, flags: usize) -> Result<ContextId> {
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
                let (_wid, (w_pid, status)) = waitpid.receive_any();
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
                });
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
                });
                grim_reaper(w_pid, status)
            }
        };

        if let Some(res) = res_opt {
            return res;
        }
    }
}
