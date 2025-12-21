//! Intrinsics for panic handling

use core::{mem, panic::PanicInfo, slice};

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
    context, cpu_id,
    interrupt::{self, InterruptStack},
    memory::KernelMapper,
    sync::CleanLockToken,
    syscall::{self, usercopy::UserSliceRo},
};

/// Required to handle panics
#[cfg(not(test))]
#[panic_handler]
fn panic_handler(info: &PanicInfo) -> ! {
    panic_handler_inner(info)
}

#[cfg_attr(test, expect(dead_code))]
fn panic_handler_inner(info: &PanicInfo) -> ! {
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

    {
        // This could deadlock, but at this point we are going to halt anyways
        let mut token = unsafe { CleanLockToken::new() };
        let context = context_lock.read(token.token());
        println!("NAME: {}, DEBUG ID: {}", context.name, context.debug_id);

        if let Some([a, b, c, d, e, f, g]) = context.current_syscall() {
            println!(
                "SYSCALL: {}",
                syscall::debug::format_call(a, b, c, d, e, f, g)
            );
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

/// Get a user stack trace
#[inline(never)]
pub unsafe fn user_stack_trace(stack: &InterruptStack) {
    let mut fp = stack.frame_pointer();
    let sp = stack.stack_pointer();

    if fp < sp {
        println!("  <Unable to generate stack while frame pointers omitted>");
        return;
    }
    if fp >= crate::USER_END_OFFSET {
        return;
    }

    for _ in 0..64 {
        if fp == 0 || fp >= crate::USER_END_OFFSET {
            break;
        }
        let rip_addr = fp + size_of::<usize>();
        let rip = match UserSliceRo::new(rip_addr, mem::size_of::<usize>())
            .and_then(|x| x.read_usize())
        {
            Ok(val) => val,
            Err(err) => {
                println!("  <Failed to read RIP 0x{:>016x}>: {}", fp, err);
                break;
            }
        };
        println!("  FP {:>016x}: PC {:>016x}", fp, rip);
        if rip == 0 {
            break;
        }

        let next_fp =
            match UserSliceRo::new(fp, mem::size_of::<usize>()).and_then(|x| x.read_usize()) {
                Ok(val) => val,
                Err(_err) => break,
            };
        if next_fp <= fp {
            println!(
                "  <Invalid next frame pointer 0x{:>016x}; stack walk ended>",
                next_fp
            );
            break;
        }
        fp = next_fp;
    }
}
