//! Intrinsics for panic handling

use core::{panic::PanicInfo, slice, str, sync::atomic::Ordering};
use goblin::elf::sym;
use rmm::VirtualAddress;
use rustc_demangle::demangle;

use crate::{
    arch::{consts::USER_END_OFFSET, interrupt::trace::StackTrace},
    context, cpu_id,
    elf::Elf,
    interrupt,
    memory::KernelMapper,
    start::KERNEL_SIZE,
    syscall,
};

/// Required to handle panics
#[cfg(not(test))]
#[panic_handler]
fn rust_begin_unwind(info: &PanicInfo) -> ! {
    println!("KERNEL PANIC: {}", info);

    unsafe {
        stack_trace();
    }
    let context_lock = context::current();

    println!("CPU {}, CID {:p}", cpu_id(), context_lock);

    // This could deadlock, but at this point we are going to halt anyways
    {
        let context = context_lock.read();
        println!("NAME: {}", context.name);

        if let Some([a, b, c, d, e, f]) = context.current_syscall() {
            println!("SYSCALL: {}", syscall::debug::format_call(a, b, c, d, e, f));
        }
    }

    println!("HALT");
    loop {
        unsafe {
            interrupt::halt();
        }
    }
}

/// Get a stack trace
#[inline(never)]
pub unsafe fn stack_trace() {
    let mapper = KernelMapper::lock();

    let mut frame = StackTrace::start();

    //Maximum 64 frames
    for _ in 0..64 {
        if let Some(frame_) = frame {
            let fp_virt = VirtualAddress::new(frame_.fp);
            let pc_virt = VirtualAddress::new(frame_.pc_ptr as usize);
            if fp_virt.data() >= USER_END_OFFSET
                && pc_virt.data() >= USER_END_OFFSET
                && (fp_virt.data() as *const usize).is_aligned()
                && (pc_virt.data() as *const usize).is_aligned()
                && mapper.translate(fp_virt).is_some()
                && mapper.translate(pc_virt).is_some()
            {
                let pc = *frame_.pc_ptr;
                if pc == 0 {
                    println!(" {:>016x}: EMPTY RETURN", frame_.fp);
                    break;
                } else {
                    println!("  FP {:>016x}: PC {:>016x}", frame_.fp, pc);
                    symbol_trace(pc);
                    frame = frame_.next();
                }
            } else {
                println!("  {:>016x}: GUARD PAGE", frame_.fp);
                break;
            }
        } else {
            break;
        }
    }
}
///
/// Get a symbol
//TODO: Do not create Elf object for every symbol lookup
#[inline(never)]
pub unsafe fn symbol_trace(addr: usize) {
    let kernel_ptr = crate::KERNEL_OFFSET as *const u8;
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
                    println!(
                        "    {:>016X}+{:>04X}",
                        sym.st_value,
                        addr - sym.st_value as usize
                    );

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
                            let sym_slice = &elf.data[start..end - 1];
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
