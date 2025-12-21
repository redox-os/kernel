use crate::{
    context::{context::SyscallFrame, Context, ContextLock},
    memory::{get_page_info, the_zeroed_frame, Frame, RefCount},
    paging::{RmmA, RmmArch, TableKind, PAGE_SIZE},
    sync::CleanLockToken,
};
use alloc::sync::Arc;
use hashbrown::{HashMap, HashSet};

/// Super unsafe due to page table switching and raw pointers!
pub unsafe fn debugger(target_id: Option<*const ContextLock>, token: &mut CleanLockToken) {
    println!("DEBUGGER START");
    println!();

    let mut tree = HashMap::new();
    let mut spaces = HashSet::new();

    tree.insert(the_zeroed_frame().0, (1, false));

    let old_table = unsafe { RmmA::table(TableKind::User) };

    let mut contexts_guard = crate::context::contexts(token.token());
    let (contexts, mut context_token) = contexts_guard.token_split();
    for context_lock in contexts.iter() {
        if target_id.map_or(false, |target_id| Arc::as_ptr(&context_lock.0) != target_id) {
            continue;
        }
        let context = context_lock.0.read(context_token.token());
        println!("{:p}: {}", Arc::as_ptr(&context_lock.0), context.name);

        let mut mark_frame_use = |frame| {
            tree.entry(frame).or_insert((0, false)).0 += 1;
        };

        match &context.syscall_head {
            SyscallFrame::Free(head) => mark_frame_use(head.get()),
            SyscallFrame::Used { _frame: head } => mark_frame_use(*head),
            SyscallFrame::Dummy => {}
        }
        match &context.syscall_tail {
            SyscallFrame::Free(tail) => mark_frame_use(tail.get()),
            SyscallFrame::Used { _frame: tail } => mark_frame_use(*tail),
            SyscallFrame::Dummy => {}
        }

        if let Some(sig) = &context.sig {
            mark_frame_use(sig.proc_control.get());
            mark_frame_use(sig.thread_control.get());
        }

        // Switch to context page table to ensure syscall debug and stack dump will work
        if let Some(ref space) = context.addr_space {
            let was_new = spaces.insert(space.acquire_read().table.utable.table().phys().data());
            unsafe {
                RmmA::set_table(
                    TableKind::User,
                    space.acquire_read().table.utable.table().phys(),
                );
                #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
                check_page_table_consistency(&mut space.acquire_write(), was_new, &mut tree);
            }
        }

        println!("status: {:?}", context.status);
        if !context.status_reason.is_empty() {
            println!("reason: {}", context.status_reason);
        }
        if let Some([a, b, c, d, e, f, g]) = context.current_syscall() {
            println!(
                "syscall: {}",
                crate::syscall::debug::format_call(a, b, c, d, e, f, g)
            );
        }
        if let Some(ref addr_space) = context.addr_space {
            let addr_space = addr_space.acquire_read();
            if !addr_space.grants.is_empty() {
                println!("grants:");
                for (base, info) in addr_space.grants.iter() {
                    let size = info.page_count() * PAGE_SIZE;

                    #[cfg(target_arch = "aarch64")]
                    println!(
                        "    virt 0x{:016x}:0x{:016x} size 0x{:08x} {:?}",
                        base.start_address().data(),
                        base.next_by(info.page_count() - 1).start_address().data() + 0xFFF,
                        size,
                        info.provider,
                    );

                    // FIXME riscv64 implementation

                    #[cfg(target_arch = "x86")]
                    println!(
                        "    virt 0x{:08x}:0x{:08x} size 0x{:08x} {:?}",
                        base.start_address().data(),
                        base.next_by(info.page_count()).start_address().data() + 0xFFF,
                        size,
                        info.provider,
                    );

                    #[cfg(target_arch = "x86_64")]
                    println!(
                        "    virt 0x{:016x}:0x{:016x} size 0x{:08x} {:?}",
                        base.start_address().data(),
                        base.start_address().data() + size - 1,
                        size,
                        info.provider,
                    );
                }
            }
        }
        if let Some(regs) = context.regs() {
            println!("regs:");
            regs.dump();

            #[cfg(target_arch = "aarch64")]
            dump_stack(&*context, regs.iret.sp_el0);

            // FIXME riscv64 implementation

            #[cfg(target_arch = "x86")]
            dump_stack(&*context, regs.iret.esp);

            #[cfg(target_arch = "x86_64")]
            {
                unsafe {
                    x86::bits64::rflags::stac();
                }
                dump_stack(&*context, regs.iret.rsp);
                unsafe {
                    x86::bits64::rflags::clac();
                }
            }
        }

        // Switch to original page table
        unsafe { RmmA::set_table(TableKind::User, old_table) };

        println!();
    }
    drop(contexts_guard);
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    crate::scheme::proc::foreach_addrsp(token, |addrsp| {
        let was_new = spaces.insert(addrsp.acquire_read().table.utable.table().phys().data());
        unsafe { check_page_table_consistency(&mut *addrsp.acquire_write(), was_new, &mut tree) };
    });
    for (frame, (count, p)) in tree {
        let Some(info) = get_page_info(frame) else {
            assert!(p);
            continue;
        };
        let (c, s) = match info.refcount() {
            None => (0, ""),
            Some(RefCount::One) => (1, ""),
            Some(RefCount::Cow(c)) => (c.get(), " cow"),
            Some(RefCount::Shared(s)) => (s.get(), " shared"),
        };
        if c != count {
            println!(
                "frame refcount mismatch for {:?} ({} != {}{})",
                frame, c, count, s
            );
        }
    }

    println!("DEBUGGER END");
}

fn dump_stack(context: &Context, mut sp: usize) {
    let width = size_of::<usize>();

    println!("stack: {:>0width$x}", sp, width = width);

    //Maximum 64 usizes
    for _ in 0..64 {
        if context.addr_space.as_ref().map_or(false, |space| {
            space
                .acquire_read()
                .table
                .utable
                .translate(crate::paging::VirtualAddress::new(sp))
                .is_some()
        }) {
            let value = unsafe { *(sp as *const usize) };
            println!("    {:>0width$x}: {:>0width$x}", sp, value, width = width);
            if let Some(next_sp) = sp.checked_add(core::mem::size_of::<usize>()) {
                sp = next_sp;
            } else {
                println!("    {:>0width$x}: OVERFLOW", sp, width = width);
                break;
            }
        } else {
            println!("    {:>0width$x}: GUARD PAGE", sp, width = width);
            break;
        }
    }
}

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
unsafe fn check_page_table_consistency(
    addr_space: &mut crate::context::memory::AddrSpace,
    new_as: bool,
    tree: &mut HashMap<Frame, (usize, bool)>,
) {
    use crate::{
        context::memory::{PageSpan, Provider},
        memory::{get_page_info, RefCount},
        paging::*,
    };

    let p4 = addr_space.table.utable.table();

    for p4i in 0..256 {
        let p3 = match unsafe { p4.next(p4i) } {
            Some(p3) => p3,
            None => continue,
        };

        for p3i in 0..512 {
            let p2 = match unsafe { p3.next(p3i) } {
                Some(p2) => p2,
                None => continue,
            };

            for p2i in 0..512 {
                let p1 = match unsafe { p2.next(p2i) } {
                    Some(p1) => p1,
                    None => continue,
                };

                for p1i in 0..512 {
                    let (physaddr, flags) = match unsafe { p1.entry(p1i) } {
                        Some(e) => {
                            if let Ok(address) = e.address() {
                                (address, e.flags())
                            } else {
                                continue;
                            }
                        }
                        _ => continue,
                    };
                    let address =
                        VirtualAddress::new((p1i << 12) | (p2i << 21) | (p3i << 30) | (p4i << 39));

                    let (base, grant) = match addr_space
                        .grants
                        .contains(Page::containing_address(address))
                    {
                        Some(g) => g,
                        None => {
                            error!(
                                "ADDRESS {:p} LACKING GRANT BUT MAPPED TO {:#0x} FLAGS {:?}!",
                                address.data() as *const u8,
                                physaddr.data(),
                                flags
                            );
                            continue;
                        }
                    };

                    const EXCLUDE: usize = (1 << 5) | (1 << 6); // accessed+dirty+writable
                    if grant.flags().write(false).data() & !EXCLUDE
                        != flags.write(false).data() & !EXCLUDE
                    {
                        error!(
                            "FLAG MISMATCH: {:?} != {:?}, address {:p} in grant at {:?}",
                            grant.flags(),
                            flags,
                            address.data() as *const u8,
                            PageSpan::new(base, grant.page_count())
                        );
                    }
                    let p = matches!(
                        grant.provider,
                        Provider::PhysBorrowed { .. }
                            | Provider::External { .. }
                            | Provider::FmapBorrowed { .. }
                    );
                    let frame = Frame::containing(physaddr);
                    if new_as {
                        tree.entry(frame).or_insert((0, p)).0 += 1;
                    }

                    if let Some(page) = get_page_info(frame) {
                        match page.refcount() {
                            None => panic!("mapped page with zero refcount"),

                            Some(RefCount::One | RefCount::Shared(_)) => assert!(
                                !(flags.has_write() && !grant.flags().has_write()),
                                "page entry has higher permissions than grant!"
                            ),
                            Some(RefCount::Cow(_)) => {
                                assert!(!flags.has_write(), "directly writable CoW page!")
                            }
                        }
                    } else {
                        //println!("!OWNED {:?}", frame);
                    }
                }
            }
        }
    }

    /*for (base, info) in addr_space.grants.iter() {
        let span = PageSpan::new(base, info.page_count());
        for page in span.pages() {
            let _entry = match addr_space.table.utable.translate(page.start_address()) {
                Some(e) => e,
                None => {
                    error!("GRANT AT {:?} LACKING MAPPING AT PAGE {:p}", span, page.start_address().data() as *const u8);
                    continue;
                }
            };
        }
    }*/
    println!("Consistency appears correct");
}
