// Super unsafe due to page table switching and raw pointers!
pub unsafe fn debugger() {
    println!("DEBUGGER START");
    println!();

    let mut active_table = crate::paging::ActivePageTable::new(crate::paging::TableKind::User);
    for (id, context_lock) in crate::context::contexts().iter() {
        let context = context_lock.read();
        println!("{}: {}", (*id).into(), context.name.read());

        // Switch to context page table to ensure syscall debug and stack dump will work
        let new_table = crate::paging::InactivePageTable::from_address(context.arch.get_page_utable());
        let old_table = active_table.switch(new_table);

        println!("status: {:?}", context.status);
        if ! context.status_reason.is_empty() {
            println!("reason: {}", context.status_reason);
        }
        if let Some((a, b, c, d, e, f)) = context.syscall {
            println!("syscall: {}", crate::syscall::debug::format_call(a, b, c, d, e, f));
        }
        if ! context.image.is_empty() {
            println!("image:");
            for shared_memory in context.image.iter() {
                shared_memory.with(|memory| {
                    let region = crate::context::memory::Region::new(
                        memory.start_address(),
                        memory.size()
                    );
                    println!(
                        "    virt 0x{:016x}:0x{:016x} size 0x{:08x}",
                        region.start_address().data(), region.final_address().data(), region.size()
                    );
                });
            }
        }
        {
            let grants = context.grants.read();
            if ! grants.is_empty() {
                println!("grants:");
                for grant in grants.iter() {
                    let region = grant.region();
                    println!(
                        "    virt 0x{:016x}:0x{:016x} size 0x{:08x} {}",
                        region.start_address().data(), region.final_address().data(), region.size(),
                        if grant.is_owned() { "owned" } else { "borrowed" },
                    );
                }
            }
        }
        if let Some(regs) = unsafe { crate::ptrace::regs_for(&context) } {
            println!("regs:");
            regs.dump();

            let mut rsp = regs.iret.rsp;
            println!("stack: {:>016x}", rsp);
            //Maximum 64 qwords
            for i in 0..64 {
                if active_table.translate(crate::paging::VirtualAddress::new(rsp)).is_some() {
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
        active_table.switch(old_table);

        println!();
    }

    println!("DEBUGGER END");
}
