use core::{mem, str};

use goblin::elf::sym;
use rustc_demangle::demangle;

use crate::{context, paging::{KernelMapper, VirtualAddress}};

/// Get a stack trace
//TODO: Check for stack being mapped before dereferencing
#[inline(never)]
pub unsafe fn stack_trace() {
    let mut ebp: usize;
    core::arch::asm!("mov {}, ebp", out(reg) ebp);

    println!("TRACE: {:>016X}", ebp);
    //Maximum 64 frames

    let mapper = KernelMapper::lock();

    for _frame in 0..64 {
        if let Some(eip_ebp) = ebp.checked_add(mem::size_of::<usize>()) {
            let ebp_virt = VirtualAddress::new(ebp);
            let eip_ebp_virt = VirtualAddress::new(eip_ebp);
            if mapper.translate(ebp_virt).is_some() && mapper.translate(eip_ebp_virt).is_some() {
                let eip = *(eip_ebp as *const usize);
                if eip == 0 {
                    println!(" {:>016X}: EMPTY RETURN", ebp);
                    break;
                }
                println!("  {:>016X}: {:>016X}", ebp, eip);
                ebp = *(ebp as *const usize);
                symbol_trace(eip);
            } else {
                println!("  {:>016X}: GUARD PAGE", ebp);
                break;
            }
        } else {
            println!("  {:>016X}: EBP OVERFLOW", ebp);
            break;
        }
    }
}

/// Get a symbol
//TODO: Do not create Elf object for every symbol lookup
#[inline(never)]
pub unsafe fn symbol_trace(addr: usize) {
    use core::slice;
    use core::sync::atomic::Ordering;

    use crate::elf::Elf;
    use crate::start::{KERNEL_BASE, KERNEL_SIZE};

    let kernel_ptr = (KERNEL_BASE.load(Ordering::SeqCst) + crate::PHYS_OFFSET) as *const u8;
    let kernel_slice = slice::from_raw_parts(kernel_ptr, KERNEL_SIZE.load(Ordering::SeqCst));
    if let Ok(elf) = Elf::from(kernel_slice) {
        let mut strtab_opt = None;
        for section in elf.sections() {
            if section.sh_type == ::goblin::elf::section_header::SHT_STRTAB {
                strtab_opt = Some(section);
                break;
            }
        }

        if let Some(symbols) = elf.symbols() {
            for sym in symbols {
                if sym::st_type(sym.st_info) == sym::STT_FUNC
                && addr >= sym.st_value as usize
                && addr < (sym.st_value + sym.st_size) as usize
                {
                    println!("    {:>016X}+{:>04X}", sym.st_value, addr - sym.st_value as usize);

                    if let Some(strtab) = strtab_opt {
                        let start = strtab.sh_offset as usize + sym.st_name as usize;
                        let mut end = start;
                        while end < elf.data.len() {
                            let b = elf.data[end];
                            end += 1;
                            if b == 0 {
                                break;
                            }
                        }

                        if end > start {
                            let sym_slice = &elf.data[start .. end - 1];
                            if let Ok(sym_name) = str::from_utf8(sym_slice) {
                                println!("    {:#}", demangle(sym_name));
                            }
                        }
                    }
                }
            }
        }
    }
}
