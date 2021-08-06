#[macro_use]
pub mod macros;

/// Constants like memory locations
pub mod consts;

/// Debugging support
pub mod debug;

/// Devices
pub mod device;

/// Global descriptor table
pub mod gdt;

/// Graphical debug
#[cfg(feature = "graphical_debug")]
mod graphical_debug;

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

pub use ::rmm::X8664Arch as CurrentRmmArch;

// Flags
pub mod flags {
    pub const SHIFT_SINGLESTEP: usize = 8;
    pub const FLAG_SINGLESTEP: usize = 1 << SHIFT_SINGLESTEP;
    pub const FLAG_INTERRUPTS: usize = 1 << 9;
}
