use crate::{
    context::Context,
    paging::{RmmA, RmmArch, TableKind, PAGE_SIZE},
};
use spinning_top::RwSpinlock;

//TODO: combine arches into one function (aarch64 one is newest)

// Super unsafe due to page table switching and raw pointers!
#[cfg(target_arch = "aarch64")]
pub unsafe fn debugger(target_id: Option<crate::context::ContextId>) {
    use hashbrown::HashSet;

    use crate::memory::{get_page_info, RefCount};

    println!("DEBUGGER START");
    println!();

    let mut tree = HashMap::new();

    let old_table = RmmA::table(TableKind::User);

    let mut spaces = HashSet::new();

    for (id, context_lock) in crate::context::contexts().iter() {
        if target_id.map_or(false, |target_id| *id != target_id) {
            continue;
        }
        let context = context_lock.read();
        println!("{}: {}", (*id).get(), context.name);

        println!("status: {:?}", context.status);
        if !context.status_reason.is_empty() {
            println!("reason: {}", context.status_reason);
        }

        // Switch to context page table to ensure syscall debug and stack dump will work
        if let Some(ref space) = context.addr_space {
            let new_as = spaces.insert(space.acquire_read().table.utable.table().phys().data());

            RmmA::set_table(
                TableKind::User,
                space.acquire_read().table.utable.table().phys(),
            );
            check_consistency(&mut *space.acquire_write(), new_as, &mut tree);

            if let Some([a, b, c, d, e, f]) = context.current_syscall() {
                println!(
                    "syscall: {}",
                    crate::syscall::debug::format_call(a, b, c, d, e, f)
                );
            }

            {
                let space = space.acquire_read();
                if !space.grants.is_empty() {
                    println!("grants:");
                    for (base, grant) in space.grants.iter() {
                        println!(
                            "    virt 0x{:016x}:0x{:016x} size 0x{:08x} {:?}",
                            base.start_address().data(),
                            base.next_by(grant.page_count() - 1).start_address().data() + 0xFFF,
                            grant.page_count() * PAGE_SIZE,
                            grant.provider,
                        );
                    }
                }
            }

            if let Some(regs) = context.regs() {
                println!("regs:");
                regs.dump();

                let mut sp = regs.iret.sp_el0;
                println!("stack: {:>016x}", sp);
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
                        let value = *(sp as *const usize);
                        println!("    {:>016x}: {:>016x}", sp, value);
                        if let Some(next_sp) = sp.checked_add(core::mem::size_of::<usize>()) {
                            sp = next_sp;
                        } else {
                            println!("    {:>016x}: OVERFLOW", sp);
                            break;
                        }
                    } else {
                        println!("    {:>016x}: GUARD PAGE", sp);
                        break;
                    }
                }
            }

            // Switch to original page table
            RmmA::set_table(TableKind::User, old_table);
        }

        println!();
    }
    for (frame, (count, p)) in tree {
        let rc = get_page_info(frame).unwrap().refcount();
        let c = match rc {
            RefCount::Zero => 0,
            RefCount::One => 1,
            RefCount::Cow(c) => c.get(),
            RefCount::Shared(s) => s.get(),
        };
        if c < count {
            println!("undercounted frame {:?} ({} < {})", frame, c, count);
        }
    }

    println!("DEBUGGER END");
}

// Super unsafe due to page table switching and raw pointers!
#[cfg(target_arch = "x86")]
pub unsafe fn debugger(target_id: Option<crate::context::ContextId>) {
    println!("DEBUGGER START");
    println!();

    let old_table = RmmA::table(TableKind::User);

    for (id, context_lock) in crate::context::contexts().iter() {
        if target_id.map_or(false, |target_id| *id != target_id) {
            continue;
        }
        let context = context_lock.read();
        println!("{}: {}", (*id).get(), context.name);

        // Switch to context page table to ensure syscall debug and stack dump will work
        if let Some(ref space) = context.addr_space {
            RmmA::set_table(
                TableKind::User,
                space.acquire_read().table.utable.table().phys(),
            );
            //TODO check_consistency(&mut space.write());
        }

        println!("status: {:?}", context.status);
        if !context.status_reason.is_empty() {
            println!("reason: {}", context.status_reason);
        }
        if let Some([a, b, c, d, e, f]) = context.current_syscall() {
            println!(
                "syscall: {}",
                crate::syscall::debug::format_call(a, b, c, d, e, f)
            );
        }
        if let Some(ref addr_space) = context.addr_space {
            let addr_space = addr_space.acquire_read();
            if !addr_space.grants.is_empty() {
                println!("grants:");
                for (base, grant) in addr_space.grants.iter() {
                    println!(
                        "    virt 0x{:08x}:0x{:08x} size 0x{:08x} {:?}",
                        base.start_address().data(),
                        base.next_by(grant.page_count()).start_address().data() + 0xFFF,
                        grant.page_count() * crate::memory::PAGE_SIZE,
                        grant.provider,
                    );
                }
            }
        }
        if let Some(regs) = context.regs() {
            println!("regs:");
            regs.dump();

            let mut sp = regs.iret.esp;
            println!("stack: {:>08x}", sp);
            //Maximum 64 dwords
            for _ in 0..64 {
                if context.addr_space.as_ref().map_or(false, |space| {
                    space
                        .acquire_read()
                        .table
                        .utable
                        .translate(crate::paging::VirtualAddress::new(sp))
                        .is_some()
                }) {
                    let value = *(sp as *const usize);
                    println!("    {:>08x}: {:>08x}", sp, value);
                    if let Some(next_sp) = sp.checked_add(core::mem::size_of::<usize>()) {
                        sp = next_sp;
                    } else {
                        println!("    {:>08x}: OVERFLOW", sp);
                        break;
                    }
                } else {
                    println!("    {:>08x}: GUARD PAGE", sp);
                    break;
                }
            }
        }

        // Switch to original page table
        RmmA::set_table(TableKind::User, old_table);

        println!();
    }

    println!("DEBUGGER END");
}

// Super unsafe due to page table switching and raw pointers!
#[cfg(target_arch = "x86_64")]
pub unsafe fn debugger(target_id: Option<*const RwSpinlock<Context>>) {
    use core::sync::atomic::Ordering;

    use alloc::sync::Arc;
    use hashbrown::HashSet;

    use crate::memory::{get_page_info, the_zeroed_frame, RefCount};

    unsafe {
        x86::bits64::rflags::stac();
    }

    println!("DEBUGGER START");
    println!();

    let mut tree = HashMap::new();
    let mut spaces = HashSet::new();

    let mut temporarily_taken_htbufs = 0;

    tree.insert(the_zeroed_frame().0, (1, false));

    let old_table = RmmA::table(TableKind::User);

    for context_lock in crate::context::contexts().iter() {
        if target_id.map_or(false, |target_id| Arc::as_ptr(&context_lock.0) != target_id) {
            continue;
        }
        let context = context_lock.0.read();
        println!("{:p}: {}", Arc::as_ptr(&context_lock.0), context.name);

        if let Some(ref head) = context.syscall_head {
            tree.insert(head.get(), (1, false));
        } else {
            temporarily_taken_htbufs += 1;
        }
        if let Some(ref tail) = context.syscall_tail {
            tree.insert(tail.get(), (1, false));
        } else {
            temporarily_taken_htbufs += 1;
        }

        // Switch to context page table to ensure syscall debug and stack dump will work
        if let Some(ref space) = context.addr_space {
            let was_new = spaces.insert(space.acquire_read().table.utable.table().phys().data());
            RmmA::set_table(
                TableKind::User,
                space.acquire_read().table.utable.table().phys(),
            );
            check_consistency(&mut space.acquire_write(), was_new, &mut tree);
        }

        println!("status: {:?}", context.status);
        if !context.status_reason.is_empty() {
            println!("reason: {}", context.status_reason);
        }
        if let Some([a, b, c, d, e, f]) = context.current_syscall() {
            println!(
                "syscall: {}",
                crate::syscall::debug::format_call(a, b, c, d, e, f)
            );
        }
        if let Some(ref addr_space) = context.addr_space {
            let addr_space = addr_space.acquire_read();
            if !addr_space.grants.is_empty() {
                println!("grants:");
                for (base, info) in addr_space.grants.iter() {
                    let size = info.page_count() * PAGE_SIZE;
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

            let mut rsp = regs.iret.rsp;
            println!("stack: {:>016x}", rsp);
            //Maximum 64 qwords
            for _ in 0..64 {
                if context.addr_space.as_ref().map_or(false, |space| {
                    space
                        .acquire_read()
                        .table
                        .utable
                        .translate(crate::paging::VirtualAddress::new(rsp))
                        .is_some()
                }) {
                    let value = *(rsp as *const usize);
                    println!("    {:>016x}: {:>016x}", rsp, value);
                    if let Some(next_rsp) = rsp.checked_add(core::mem::size_of::<usize>()) {
                        rsp = next_rsp;
                    } else {
                        println!("    {:>016x}: OVERFLOW", rsp);
                        break;
                    }
                } else {
                    println!("    {:>016x}: GUARD PAGE", rsp);
                    break;
                }
            }
        }

        // Switch to original page table
        RmmA::set_table(TableKind::User, old_table);

        println!();
    }
    crate::scheme::proc::foreach_addrsp(|addrsp| {
        let was_new = spaces.insert(addrsp.acquire_read().table.utable.table().phys().data());
        check_consistency(&mut *addrsp.acquire_write(), was_new, &mut tree);
    });
    for (frame, (count, p)) in tree {
        let Some(info) = get_page_info(frame) else {
            assert!(p);
            continue;
        };
        let rc = info.refcount();
        let (c, s) = match rc {
            None => (0, false),
            Some(RefCount::One) => (1, false),
            Some(RefCount::Cow(c)) => (c.get(), false),
            Some(RefCount::Shared(s)) => (s.get(), true),
        };
        if c != count {
            println!(
                "frame refcount mismatch for {:?} ({} != {} s {})",
                frame, c, count, s
            );
        }
    }
    println!(
        "({} kernel-owned references were not counted)",
        temporarily_taken_htbufs
    );

    println!("DEBUGGER END");
    unsafe {
        x86::bits64::rflags::clac();
    }
}
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
use {crate::memory::Frame, hashbrown::HashMap};

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
pub unsafe fn check_consistency(
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
        let p3 = match p4.next(p4i) {
            Some(p3) => p3,
            None => continue,
        };

        for p3i in 0..512 {
            let p2 = match p3.next(p3i) {
                Some(p2) => p2,
                None => continue,
            };

            for p2i in 0..512 {
                let p1 = match p2.next(p2i) {
                    Some(p1) => p1,
                    None => continue,
                };

                for p1i in 0..512 {
                    let (physaddr, flags) = match p1.entry(p1i) {
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
                            log::error!(
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
                        log::error!(
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
                    log::error!("GRANT AT {:?} LACKING MAPPING AT PAGE {:p}", span, page.start_address().data() as *const u8);
                    continue;
                }
            };
        }
    }*/
    println!("Consistency appears correct");
}
