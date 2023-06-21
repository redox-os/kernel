use crate::Bootstrap;

use self::paging::PAGE_SIZE;

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

/// Miscellaneous processor features
pub mod misc;

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

use ::rmm::Arch;
pub use ::rmm::X8664Arch as CurrentRmmArch;

// Flags
pub mod flags {
    pub const SHIFT_SINGLESTEP: usize = 8;
    pub const FLAG_SINGLESTEP: usize = 1 << SHIFT_SINGLESTEP;
    pub const FLAG_INTERRUPTS: usize = 1 << 9;
}

#[naked]
#[link_section = ".usercopy-fns"]
pub unsafe extern "C" fn arch_copy_to_user(dst: usize, src: usize, len: usize) -> u8 {
    // TODO: LFENCE (spectre_v1 mitigation)?

    #[cfg(not(feature = "x86_smap"))]
    core::arch::asm!("
        xor eax, eax
        mov rcx, rdx
        rep movsb
        ret
    ", options(noreturn));

    #[cfg(feature = "x86_smap")]
    core::arch::asm!("
        xor eax, eax
        mov rcx, rdx
        stac
        rep movsb
        clac
        ret
    ", options(noreturn));
}
pub use arch_copy_to_user as arch_copy_from_user;

pub unsafe fn bootstrap_mem(bootstrap: &Bootstrap) -> &'static [u8] {
    core::slice::from_raw_parts(CurrentRmmArch::phys_to_virt(bootstrap.base.start_address()).data() as *const u8, bootstrap.page_count * PAGE_SIZE)
}
