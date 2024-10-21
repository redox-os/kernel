#[macro_use]
pub mod macros;

/// Constants like memory locations
pub mod consts;

/// Debugging support
pub mod debug;

/// Devices
pub mod device;

/// Interrupt instructions
pub mod interrupt;

/// Inter-processor interrupts
pub mod ipi;

/// Miscellaneous
pub mod misc;

/// Paging
pub mod paging;

pub mod rmm;

/// Initialization and start function
pub mod start;

/// Stop function
pub mod stop;

// Interrupt vectors
pub mod vectors;

pub mod time;

pub use ::rmm::AArch64Arch as CurrentRmmArch;

pub use arch_copy_to_user as arch_copy_from_user;

#[naked]
#[link_section = ".usercopy-fns"]
pub unsafe extern "C" fn arch_copy_to_user(dst: usize, src: usize, len: usize) -> u8 {
    // x0, x1, x2
    core::arch::asm!(
        "
        mov x4, x0
        mov x0, 0
    2:
        cmp x2, 0
        b.eq 3f

        ldrb w3, [x1]
        strb w3, [x4]

        add x4, x4, 1
        add x1, x1, 1
        sub x2, x2, 1

        b 2b
    3:
        ret
    ",
        options(noreturn)
    );
}

pub const KFX_SIZE: usize = 1024;

// This function exists as the KFX size is dynamic on x86_64.
pub fn kfx_size() -> usize {
    KFX_SIZE
}
