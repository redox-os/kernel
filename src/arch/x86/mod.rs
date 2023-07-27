#[macro_use]
pub mod macros;

/// Constants like memory locations
pub mod consts;

/// CPUID wrapper
pub mod cpuid;

/// Debugging support
pub mod debug;

/// Devices
pub mod device;

/// Global descriptor table
pub mod gdt;

/// Interrupt instructions
#[macro_use]
pub mod interrupt;

/// Interrupt descriptor table
pub mod idt;

/// Inter-processor interrupts
pub mod ipi;

/// Paging
pub mod paging;

/// Page table isolation
pub mod pti;

pub mod rmm;

/// Initialization and start function
pub mod start;

/// Stop function
pub mod stop;

pub mod time;

pub use ::rmm::X86Arch as CurrentRmmArch;
use ::rmm::Arch;
use crate::{Bootstrap, memory::PAGE_SIZE};

// Flags
pub mod flags {
    pub const SHIFT_SINGLESTEP: usize = 8;
    pub const FLAG_SINGLESTEP: usize = 1 << SHIFT_SINGLESTEP;
    pub const FLAG_INTERRUPTS: usize = 1 << 9;
}
pub use arch_copy_to_user as arch_copy_from_user;

#[inline(always)]
pub unsafe fn arch_copy_to_user(dst: usize, src: usize, len: usize) -> u8 {
    arch_copy_to_user_inner(len, dst, src)
}

#[naked]
#[link_section = ".usercopy-fns"]
#[no_mangle]
pub unsafe extern "fastcall" fn arch_copy_to_user_inner(len: usize, dst: usize, src: usize) -> u8 {
    // Explicitly specified __fastcall ABI:
    //
    // ECX = len, EDX = dst, src is pushed to the stack (earlier than the CALL return address, of
    // course)
    core::arch::asm!("
        push edi
        push esi

        mov edi, edx
        mov esi, [esp+12]

        xor eax, eax
        rep movsb

        pop esi
        pop edi

        ret 4
    ", options(noreturn));
}
pub unsafe fn bootstrap_mem(bootstrap: &Bootstrap) -> &'static [u8] {
    core::slice::from_raw_parts(CurrentRmmArch::phys_to_virt(bootstrap.base.start_address()).data() as *const u8, bootstrap.page_count * PAGE_SIZE)
}
