/// CPUID wrapper
pub mod cpuid;

/// Debugging support
pub mod debug;

/// Devices
pub mod device;

/// Global descriptor table
pub mod gdt;

/// Interrupt descriptor table
pub mod idt;

/// Interrupt instructions
pub mod interrupt;

/// Inter-processor interrupts
pub mod ipi;

/// Paging
pub mod paging;

/// Initialization and start function
pub mod start;

/// Stop function
pub mod stop;

pub mod time;

#[cfg(target_arch = "x86")]
pub use ::rmm::x86::X86Arch as CurrentRmmArch;

#[cfg(target_arch = "x86_64")]
pub use ::rmm::x86_64::X8664Arch as CurrentRmmArch;

// Flags
pub mod flags {
    pub const FLAG_SINGLESTEP: usize = 1 << 8;
}

#[inline]
pub fn current_stack_ptr() -> *mut u8 {
    let ret: *mut u8;
    unsafe {
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!(
            "mov {}, rsp",
            out(reg) ret,
            options(nomem, preserves_flags, nostack),
        );
        #[cfg(target_arch = "x86")]
        core::arch::asm!(
            "mov {}, esp",
            out(reg) ret,
            options(nomem, preserves_flags, nostack),
        );
    }
    ret
}
