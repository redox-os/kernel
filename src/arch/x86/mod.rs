pub use crate::arch::x86_shared::*;

#[macro_use]
pub mod macros;

/// Constants like memory locations
pub mod consts;

/// Global descriptor table
pub mod gdt;

/// Interrupt instructions
#[macro_use]
pub mod interrupt;

/// Interrupt descriptor table
pub mod idt;

/// Paging
pub mod paging;

pub mod rmm;

/// Initialization and start function
pub mod start;

use crate::{memory::PAGE_SIZE, Bootstrap};
use ::rmm::Arch;
pub use ::rmm::X86Arch as CurrentRmmArch;

// Flags
pub mod flags {
    pub const SHIFT_SINGLESTEP: usize = 8;
    pub const FLAG_SINGLESTEP: usize = 1 << SHIFT_SINGLESTEP;
    pub const FLAG_INTERRUPTS: usize = 1 << 9;
}

#[naked]
#[link_section = ".usercopy-fns"]
pub unsafe extern "C" fn arch_copy_to_user(dst: usize, src: usize, len: usize) -> u8 {
    core::arch::asm!(
        "
            push edi
            push esi

            mov edi, [esp + 12] # dst
            mov esi, [esp + 16] # src
            mov ecx, [esp + 20] # len
            rep movsb

            pop esi
            pop edi

            xor eax, eax
            ret
    ",
        options(noreturn)
    );
}
pub use arch_copy_to_user as arch_copy_from_user;

pub unsafe fn bootstrap_mem(bootstrap: &Bootstrap) -> &'static [u8] {
    core::slice::from_raw_parts(
        CurrentRmmArch::phys_to_virt(bootstrap.base.start_address()).data() as *const u8,
        bootstrap.page_count * PAGE_SIZE,
    )
}
pub const KFX_SIZE: usize = 512;

// This function exists as the KFX size is dynamic on x86_64.
pub fn kfx_size() -> usize {
    KFX_SIZE
}
