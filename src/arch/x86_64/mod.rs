use crate::Bootstrap;

use self::paging::PAGE_SIZE;

pub use crate::arch::x86_shared::*;

pub mod alternative;

#[macro_use]
pub mod macros;

/// Constants like memory locations
pub mod consts;

/// CPUID wrapper
pub mod cpuid;

/// Debugging support
pub mod debug;

/// Global descriptor table
pub mod gdt;

/// Interrupt instructions
#[macro_use]
pub mod interrupt;

/// Interrupt descriptor table
pub mod idt;

/// Inter-processor interrupts
pub mod ipi;

/// Miscellaneous processor features
pub mod misc;

/// Paging
pub mod paging;

/// Page table isolation
pub mod pti;

pub mod rmm;

/// Initialization and start function
pub mod start;

use ::rmm::Arch;
pub use ::rmm::X8664Arch as CurrentRmmArch;

// Flags
pub mod flags {
    pub const SHIFT_SINGLESTEP: usize = 8;
    pub const FLAG_SINGLESTEP: usize = 1 << SHIFT_SINGLESTEP;
    pub const FLAG_INTERRUPTS: usize = 1 << 9;
}

// TODO: Maybe support rewriting relocations (using LD's --emit-relocs) when working with entire
// functions?
#[naked]
#[link_section = ".usercopy-fns"]
pub unsafe extern "C" fn arch_copy_to_user(dst: usize, src: usize, len: usize) -> u8 {
    // TODO: spectre_v1

    core::arch::asm!(
        alternative!(
            feature: "smap",
            then: ["
            xor eax, eax
            mov rcx, rdx
            stac
            rep movsb
            clac
            ret
        "],
            default: ["
            xor eax, eax
            mov rcx, rdx
            rep movsb
            ret
        "]
        ),
        options(noreturn)
    );
}
pub use arch_copy_to_user as arch_copy_from_user;

// TODO: This doesn't need to be arch-specific, right?
pub unsafe fn bootstrap_mem(bootstrap: &Bootstrap) -> &'static [u8] {
    core::slice::from_raw_parts(
        CurrentRmmArch::phys_to_virt(bootstrap.base.start_address()).data() as *const u8,
        bootstrap.page_count * PAGE_SIZE,
    )
}

pub use alternative::kfx_size;
