use core::{mem, str};
use goblin::elf::sym;
use rustc_demangle::demangle;

use crate::paging::{ActivePageTable, TableKind, VirtualAddress};

/// Get a stack trace
//TODO: Check for stack being mapped before dereferencing
#[inline(never)]
pub unsafe fn stack_trace() {
    let mut fp: usize;
    asm!("mv {}, fp", out(reg) fp);

    println!("TRACE: {:>016x}", fp);
    //Maximum 64 frames
    let active_table = ActivePageTable::new(TableKind::User);
    for _frame in 0..64 {
        if let Some(pc_fp) = fp.checked_add(mem::size_of::<usize>()) {
            if active_table.translate(VirtualAddress::new(fp)).is_some() && active_table.translate(VirtualAddress::new(pc_fp)).is_some() {
                let pc = *(pc_fp as *const usize);
                if pc == 0 {
                    println!(" {:>016x}: EMPTY RETURN", fp);
                    break;
                }
                println!("  FP {:>016x}: PC {:>016x}", fp, pc);
                fp = *(fp as *const usize);
                //TODO symbol_trace(pc);
            } else {
                println!("  {:>016x}: GUARD PAGE", fp);
                break;
            }
        } else {
            println!("  {:>016x}: FP OVERFLOW", fp);
            break;
        }
    }
}
