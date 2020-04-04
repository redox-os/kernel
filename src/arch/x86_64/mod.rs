#[macro_use]
pub mod macros;

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

/// Initialization and start function
pub mod start;

/// Stop function
pub mod stop;
