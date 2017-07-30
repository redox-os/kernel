#[macro_use]
pub mod macros;

/// Devices
pub mod device;

/// Global descriptor table
pub mod gdt;

/// Interrupt descriptor table
pub mod idt;

/// Interrupt instructions
pub mod interrupt;

/// Paging
pub mod paging;

/// Initialization and start function
pub mod start;

/// Stop function
pub mod stop;