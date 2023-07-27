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

/// Paging
pub mod paging;

pub mod rmm;

/// Initialization and start function
pub mod start;

/// Stop function
pub mod stop;

// Interrupt vectors
pub mod vectors;

/// Early init support
pub mod init;

pub mod time;

pub use ::rmm::AArch64Arch as CurrentRmmArch;

pub use arch_copy_to_user as arch_copy_from_user;

#[naked]
#[link_section = ".usercopy-fns"]
pub unsafe extern "C" fn arch_copy_to_user(dst: usize, src: usize, len: usize) -> u8 {
    // x0, x1, x2
    core::arch::asm!("
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
    ", options(noreturn));
}
pub unsafe fn bootstrap_mem(bootstrap: &crate::Bootstrap) -> &'static [u8] {
    use ::rmm::Arch;
    use crate::memory::PAGE_SIZE;

    core::slice::from_raw_parts(CurrentRmmArch::phys_to_virt(bootstrap.base.start_address()).data() as *const u8, bootstrap.page_count * PAGE_SIZE)
}
