use core::{arch::asm, mem};

use crate::{memory::KernelMapper, paging::VirtualAddress};

/// Get a stack trace
//TODO: Check for stack being mapped before dereferencing
#[inline(never)]
pub unsafe fn stack_trace() {
    let mut fp: usize;
    asm!("mov {}, fp", out(reg) fp);

    println!("TRACE: {:>016x}", fp);

    let mapper = KernelMapper::lock();

    //Maximum 64 frames
    for _frame in 0..64 {
        if let Some(pc_fp) = fp.checked_add(mem::size_of::<usize>()) {
            if mapper.translate(VirtualAddress::new(fp)).is_some()
                && mapper.translate(VirtualAddress::new(pc_fp)).is_some()
            {
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
            println!("  {:>016x}: fp OVERFLOW", fp);
        }
    }
}
