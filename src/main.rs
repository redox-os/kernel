//! # The Redox OS Kernel, version 2
//!
//! The Redox OS Kernel is a microkernel that supports `x86_64` systems and
//! provides Unix-like syscalls for primarily Rust applications

#![feature(asm_cfg)] // Stabilized in 1.93
#![feature(if_let_guard)]
#![feature(int_roundings)]
#![feature(iter_next_chunk)]
#![feature(sync_unsafe_cell)]
#![feature(btree_cursors)]
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#![allow(clippy::new_without_default)]

#[macro_use]
extern crate alloc;

#[macro_use]
extern crate bitflags;

use core::sync::atomic::{AtomicU32, Ordering};

#[macro_use]
/// Shared data structures
mod common;

#[macro_use]
mod macros;

/// Architecture-dependent stuff
#[macro_use]
#[allow(dead_code)] // TODO
mod arch;
use crate::arch::{consts::*, ipi, stop, CurrentRmmArch};
/// Offset of physmap
#[cfg_attr(any(target_arch = "x86", target_arch = "x86_64"), expect(dead_code))]
const PHYS_OFFSET: usize = <arch::CurrentRmmArch as ::rmm::Arch>::PHYS_OFFSET;

/// Heap allocators
mod allocator;

/// ACPI table parsing
mod acpi;

mod dtb;

/// Logical CPU ID and bitset types
mod cpu_set;

/// Stats for the CPUs
mod cpu_stats;

/// Context management
mod context;

/// Debugger
#[cfg(feature = "debugger")]
mod debugger;

/// Architecture-independent devices
mod devices;

/// Event handling
mod event;

/// Logging
mod log;

/// Memory management
mod memory;

/// Panic
mod panic;

mod percpu;

/// Process tracing
mod ptrace;

/// Performance profiling of the kernel
mod profiling;

/// Schemes, filesystem handlers
mod scheme;

/// Early init
mod startup;

/// Synchronization primitives
mod sync;

/// Syscall handlers
mod syscall;

/// Time
mod time;

#[cfg_attr(not(test), global_allocator)]
static ALLOCATOR: allocator::Allocator = allocator::Allocator;

/// Get the current CPU's scheduling ID
#[inline(always)]
fn cpu_id() -> crate::cpu_set::LogicalCpuId {
    crate::percpu::PercpuBlock::current().cpu_id
}

/// The count of all CPUs that can have work scheduled
static CPU_COUNT: AtomicU32 = AtomicU32::new(1);

/// Get the number of CPUs currently active
#[inline(always)]
fn cpu_count() -> u32 {
    CPU_COUNT.load(Ordering::Relaxed)
}

macro_rules! linker_offsets(
    ($($name:ident),*) => {
        $(
        #[inline(always)]
        #[allow(non_snake_case)]
        pub fn $name() -> usize {
            unsafe extern "C" {
                // TODO: UnsafeCell?
                static $name: u8;
            }
            (&raw const $name) as usize
        }
        )*
    }
);
mod kernel_executable_offsets {
    linker_offsets!(
        KERNEL_OFFSET,
        __text_start,
        __text_end,
        __rodata_start,
        __rodata_end,
        __usercopy_start,
        __usercopy_end
    );

    #[cfg(target_arch = "x86_64")]
    linker_offsets!(__altrelocs_start, __altrelocs_end);
}
