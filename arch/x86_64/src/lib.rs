//! Architecture support for x86_64

//#![deny(warnings)]
#![deny(unused_must_use)]
#![feature(asm)]
#![feature(concat_idents)]
#![feature(const_fn)]
#![feature(core_intrinsics)]
#![feature(drop_types_in_const)]
#![feature(lang_items)]
#![feature(naked_functions)]
#![feature(thread_local)]
#![feature(unique)]
#![no_std]

extern crate alloc_kernel as allocator;
#[macro_use]
extern crate bitflags;
extern crate spin;
extern crate syscall;
pub extern crate x86;

pub use consts::*;

/// Macros like print, println, and interrupt
#[macro_use]
pub mod macros;

/// Constants like memory locations
pub mod consts;

/// ACPI table parsing
mod acpi;

/// Console handling
pub mod console;

/// Context switching
pub mod context;

/// Devices
pub mod device;

/// Global descriptor table
pub mod gdt;

/// Interrupt descriptor table
mod idt;

/// Interrupt instructions
pub mod interrupt;

/// Memory management
pub mod memory;

/// Paging
pub mod paging;

/// Panic
pub mod panic;

/// Initialization and start function
pub mod start;

/// Shutdown function
pub mod stop;

/// Time
pub mod time;
