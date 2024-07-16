pub use crate::arch::x86_shared::*;

pub mod alternative;

#[macro_use]
pub mod macros;

/// Constants like memory locations
pub mod consts;

/// CPUID wrapper
pub mod cpuid;

/// Global descriptor table
pub mod gdt;

/// Interrupt instructions
#[macro_use]
pub mod interrupt;

/// Miscellaneous processor features
pub mod misc;

/// Paging
pub mod paging;

pub mod rmm;

/// Initialization and start function
pub mod start;

pub use ::rmm::X8664Arch as CurrentRmmArch;

// Flags
pub mod flags {
    pub const SHIFT_SINGLESTEP: usize = 8;
    pub const FLAG_SINGLESTEP: usize = 1 << SHIFT_SINGLESTEP;
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

pub use alternative::kfx_size;
