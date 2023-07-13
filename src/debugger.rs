use crate::paging::{RmmA, RmmArch, TableKind, PAGE_SIZE};

//TODO: combine arches into one function (aarch64 one is newest)

// Super unsafe due to page table switching and raw pointers!
#[cfg(target_arch = "aarch64")]
pub unsafe fn debugger(target_id: Option<crate::context::ContextId>) {
    println!("DEBUGGER START");
    println!();

    let old_table = RmmA::table(TableKind::User);

    for (id, context_lock) in crate::context::contexts().iter() {
        if target_id.map_or(false, |target_id| *id != target_id) { continue; }
        let context = context_lock.read();
        println!("{}: {}", (*id).into(), context.name);

        println!("status: {:?}", context.status);
        if ! context.status_reason.is_empty() {
            println!("reason: {}", context.status_reason);
        }

        // Switch to context page table to ensure syscall debug and stack dump will work
        if let Some(ref space) = context.addr_space {
            RmmA::set_table(TableKind::User, space.read().table.utable.table().phys());

            if let Some((a, b, c, d, e, f)) = context.syscall {
                println!("syscall: {}", crate::syscall::debug::format_call(a, b, c, d, e, f));
            }

            {
                let space = space.read();
                if ! space.grants.is_empty() {
                    println!("grants:");
                    for grant in space.grants.iter() {
                        let region = grant.region();
                        println!(
                            "    virt 0x{:016x}:0x{:016x} size 0x{:08x} {}",
                            region.start_address().data(), region.final_address().data(), region.size(),
                            if grant.is_owned() { "owned" } else { "borrowed" },
                        );
                    }
                }
            }

            if let Some(regs) = crate::ptrace::regs_for(&context) {
                println!("regs:");
                regs.dump();

                let mut sp = regs.iret.sp_el0;
                println!("stack: {:>016x}", sp);
                //Maximum 64 usizes
                for _ in 0..64 {
                    if context.addr_space.as_ref().map_or(false, |space| space.read().table.utable.translate(crate::paging::VirtualAddress::new(sp)).is_some()) {
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

    println!("DEBUGGER END");
}

// Super unsafe due to page table switching and raw pointers!
#[cfg(target_arch = "x86")]
pub unsafe fn debugger(target_id: Option<crate::context::ContextId>) {
    println!("DEBUGGER START");
    println!();

    let old_table = RmmA::table(TableKind::User);

    for (id, context_lock) in crate::context::contexts().iter() {
        if target_id.map_or(false, |target_id| *id != target_id) { continue; }
        let context = context_lock.read();
        println!("{}: {}", (*id).into(), context.name);

        // Switch to context page table to ensure syscall debug and stack dump will work
        if let Some(ref space) = context.addr_space {
            RmmA::set_table(TableKind::User, space.read().table.utable.table().phys());
            //TODO check_consistency(&mut space.write());
        }

        println!("status: {:?}", context.status);
        if ! context.status_reason.is_empty() {
            println!("reason: {}", context.status_reason);
        }
        if let Some((a, b, c, d, e, f)) = context.syscall {
            println!("syscall: {}", crate::syscall::debug::format_call(a, b, c, d, e, f));
        }
        if let Some(ref addr_space) = context.addr_space {
            let addr_space = addr_space.read();
            if ! addr_space.grants.is_empty() {
                println!("grants:");
                for grant in addr_space.grants.iter() {
                    let region = grant.region();
                    println!(
                        "    virt 0x{:08x}:0x{:08x} size 0x{:08x} {}",
                        region.start_address().data(), region.final_address().data(), region.size(),
                        if grant.is_owned() { "owned" } else { "borrowed" },
                    );
                }
            }
        }
        if let Some(regs) = crate::ptrace::regs_for(&context) {
            println!("regs:");
            regs.dump();

            let mut sp = regs.iret.esp;
            println!("stack: {:>08x}", sp);
            //Maximum 64 dwords
            for _ in 0..64 {
                if context.addr_space.as_ref().map_or(false, |space| space.read().table.utable.translate(crate::paging::VirtualAddress::new(sp)).is_some()) {
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
pub unsafe fn debugger(target_id: Option<crate::context::ContextId>) {
    unsafe { x86::bits64::rflags::stac(); }

    println!("DEBUGGER START");
    println!();

    let old_table = RmmA::table(TableKind::User);

    for (id, context_lock) in crate::context::contexts().iter() {
        if target_id.map_or(false, |target_id| *id != target_id) { continue; }
        let context = context_lock.read();
        println!("{}: {}", (*id).into(), context.name);

        // Switch to context page table to ensure syscall debug and stack dump will work
        if let Some(ref space) = context.addr_space {
            RmmA::set_table(TableKind::User, space.read().table.utable.table().phys());
            check_consistency(&mut space.write());
        }

        println!("status: {:?}", context.status);
        if ! context.status_reason.is_empty() {
            println!("reason: {}", context.status_reason);
        }
        if let Some((a, b, c, d, e, f)) = context.syscall {
            println!("syscall: {}", crate::syscall::debug::format_call(a, b, c, d, e, f));
        }
        if let Some(ref addr_space) = context.addr_space {
            let addr_space = addr_space.read();
            if ! addr_space.grants.is_empty() {
                println!("grants:");
                for (base, info) in addr_space.grants.iter() {
                    let size = info.page_count() * PAGE_SIZE;
                    println!(
                        "    virt 0x{:016x}:0x{:016x} size 0x{:08x} {}",
                        base.start_address().data(), base.start_address().data() + size - 1, size,
                        //if info.is_owned() { "owned" } else { "borrowed" },
                        // TODO
                        "",
                    );
                }
            }
        }
        if let Some(regs) = crate::ptrace::regs_for(&context) {
            println!("regs:");
            regs.dump();

            let mut rsp = regs.iret.rsp;
            println!("stack: {:>016x}", rsp);
            //Maximum 64 qwords
            for _ in 0..64 {
                if context.addr_space.as_ref().map_or(false, |space| space.read().table.utable.translate(crate::paging::VirtualAddress::new(rsp)).is_some()) {
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

    println!("DEBUGGER END");
    unsafe { x86::bits64::rflags::clac(); }
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn check_consistency(addr_space: &mut crate::context::memory::AddrSpace) {
    use crate::context::memory::PageSpan;
    use crate::paging::*;

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
                        Some(e) => if let Ok(address) = e.address() {
                            (address, e.flags())
                        } else {
                            continue;
                        }
                        _ => continue,
                    };
                    let address = VirtualAddress::new((p1i << 12) | (p2i << 21) | (p3i << 30) | (p4i << 39));

                    let (base, grant) = match addr_space.grants.contains(Page::containing_address(address)) {
                        Some(g) => g,
                        None => {
                            log::error!("ADDRESS {:p} LACKING GRANT BUT MAPPED TO {:#0x} FLAGS {:?}!", address.data() as *const u8, physaddr.data(), flags);
                            continue;
                        }
                    };
                    const STICKY: usize = (1 << 5) | (1 << 6); // accessed+dirty
                    if grant.flags().data() & !STICKY != flags.data() & !STICKY {
                        log::error!("FLAG MISMATCH: {:?} != {:?}, address {:p} in grant at {:?}", grant.flags(), flags, address.data() as *const u8, PageSpan::new(base, grant.page_count()));
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
}
