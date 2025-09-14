//! Intrinsics for panic handling

use core::{panic::PanicInfo, slice};

#[cfg(target_pointer_width = "32")]
use object::elf::FileHeader32 as FileHeader;
#[cfg(target_pointer_width = "64")]
use object::elf::FileHeader64 as FileHeader;
use object::{
    elf,
    read::elf::{FileHeader as _, Sym as _},
    NativeEndian,
};
use rmm::VirtualAddress;
use rustc_demangle::demangle;

use crate::{
    arch::{consts::USER_END_OFFSET, interrupt::trace::StackTrace},
    context, cpu_id, interrupt,
    memory::KernelMapper,
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
    unsafe {
        let mapper = KernelMapper::lock();

        let kernel_ptr = crate::KERNEL_OFFSET as *const u8;
        let elf_header: &FileHeader<NativeEndian> = object::pod::from_bytes(slice::from_raw_parts(
            kernel_ptr,
            size_of::<FileHeader<NativeEndian>>(),
        ))
        .unwrap()
        .0;

        // This assumes that the linker places .shstrtab as last section. If it
        // isn't, that just causes a recursive panic, not UB.
        let kernel_size = elf_header.e_shoff(NativeEndian) as usize
            + usize::from(elf_header.e_shnum(NativeEndian))
                * usize::from(elf_header.e_shentsize(NativeEndian));
        let kernel_slice = slice::from_raw_parts(kernel_ptr, kernel_size);

        let symbols = elf_header
            .sections(NativeEndian, kernel_slice)
            .unwrap()
            .symbols(NativeEndian, kernel_slice, elf::SHT_SYMTAB)
            .unwrap();

        let mut frame = StackTrace::start();

        //Maximum 64 frames
        for _ in 0..64 {
            let Some(frame_) = frame else {
                break;
            };
            let fp_virt = VirtualAddress::new(frame_.fp);
            let pc_virt = VirtualAddress::new(frame_.pc_ptr as usize);
            if !(fp_virt.data() >= USER_END_OFFSET
                && pc_virt.data() >= USER_END_OFFSET
                && (fp_virt.data() as *const usize).is_aligned()
                && (pc_virt.data() as *const usize).is_aligned()
                && mapper.translate(fp_virt).is_some()
                && mapper.translate(pc_virt).is_some())
            {
                println!("  {:>016x}: GUARD PAGE", frame_.fp);
                break;
            }

            let pc = *frame_.pc_ptr;
            if pc == 0 {
                println!(" {:>016x}: EMPTY RETURN", frame_.fp);
                break;
            }

            println!("  FP {:>016x}: PC {:>016x}", frame_.fp, pc);

            for sym in symbols.iter() {
                if sym.st_type() != elf::STT_FUNC {
                    continue;
                }
                let sym_addr = sym.st_value.get(NativeEndian) as usize;
                if !(pc >= sym_addr && pc < sym_addr + sym.st_size.get(NativeEndian) as usize) {
                    continue;
                }

                println!("    {:>016X}+{:>04X}", sym_addr, pc - sym_addr);

                if let Some(sym_name) = sym
                    .name(NativeEndian, symbols.strings())
                    .ok()
                    .and_then(|name| core::str::from_utf8(name).ok())
                {
                    println!("    {:#}", demangle(sym_name));
                }
            }
            frame = frame_.next();
        }
    }
}
