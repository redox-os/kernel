//! Intrinsics for panic handling

use core::{panic::PanicInfo, slice, str, sync::atomic::Ordering};
use goblin::elf::sym;
use rmm::VirtualAddress;
#[cfg(target_arch = "x86_64")]
use rmm::{PageMapper, X8664Arch};
use rustc_demangle::demangle;

#[cfg(target_arch = "x86_64")]
use crate::memory::TheFrameAllocator;
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

    let Some(context_lock) = context::try_current() else {
        println!("CPU {}, CID <none>", cpu_id());

        println!("HALT");
        loop {
            unsafe {
                interrupt::halt();
            }
        }
    };

    println!("CPU {}, CID {:p}", cpu_id(), context_lock);

    // This could deadlock, but at this point we are going to halt anyways
    {
        let context = context_lock.read();
        println!("NAME: {}, DEBUG ID: {}", context.name, context.debug_id);

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

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn user_stack_trace(start_rbp: usize) {
    // unimplemented
}

/// Get a user stack trace
#[inline(never)]
#[cfg(target_arch = "x86_64")]
pub unsafe fn user_stack_trace(start_rbp: usize) {
    let mut rbp = start_rbp;

    let context_lock = crate::context::current();
    let context = context_lock.read();

    if let Ok(addr_space) = context.addr_space() {
        let page_tables = &addr_space.acquire_read().table.utable;

        for i in 0..64 {
            if rbp == 0 || rbp >= crate::USER_END_OFFSET {
                break; // end of stack or pointing into kernel
            }

            let rip_addr = rbp + mem::size_of::<usize>();
            let rip = match read_from_user_space(rip_addr, page_tables) {
                Some(val) => val,
                None => {
                    println!("  {:>016x}: <Failed to read RIP at {:016x}>", rbp, rip_addr);
                    break;
                }
            };

            if rip == 0 {
                break;
            }

            println!("  FP {:>016x}: PC {:>016x}", rbp, rip);

            rbp = match read_from_user_space(rbp, page_tables) {
                Some(val) => val,
                None => {
                    println!("  {:>016x}: <Failed to read next FP>", rbp);
                    break;
                }
            };
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn read_from_user_space(
    user_vaddr: usize,
    page_tables: &PageMapper<X8664Arch, TheFrameAllocator>,
) -> Option<usize> {
    // 1. Convert the raw address into a `VirtualAddress` struct.
    let virt_addr = VirtualAddress::new(user_vaddr);

    // 2. Use the `translate` method of the user's page table.
    // This is the most important step. It checks if the address is mapped
    // and returns the corresponding physical address if it is.
    // If the address is invalid, it will safely return `None`.
    if let Some(phys_addr) = page_tables.translate(virt_addr) {
        // 3. Convert the physical address to a virtual address that the kernel can access.
        // The kernel maps all physical memory at a high virtual offset (`KERNEL_OFFSET`).

        use crate::arch::consts::KERNEL_OFFSET;
        let kernel_vaddr = KERNEL_OFFSET + phys_addr.data();

        // 4. Now that we have a valid kernel virtual address, we can safely
        // dereference it. We use `read_volatile` to prevent the compiler
        // from making optimizations that might be invalid for memory-mapped I/O
        // or shared memory.
        unsafe {
            // It's a good practice to check for null pointers, even though a translated
            // address is unlikely to be null.
            if kernel_vaddr != 0 {
                return Some((kernel_vaddr as *const usize).read_volatile());
            }
        }
    }

    // If the address translation failed, the pointer is invalid. Return None.
    None
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
