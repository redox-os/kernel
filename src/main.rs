//! # The Redox OS Kernel, version 2
//!
//! The Redox OS Kernel is a microkernel that supports `x86_64` systems and
//! provides Unix-like syscalls for primarily Rust applications

// Useful for adding comments about different branches
#![allow(clippy::if_same_then_else)]
// Useful in the syscall function
#![allow(clippy::many_single_char_names)]
// Used for context::context
#![allow(clippy::module_inception)]
// Not implementing default is sometimes useful in the case something has significant cost
// to allocate. If you implement default, it can be allocated without evidence using the
// ..Default::default() syntax. Not fun in kernel space
#![allow(clippy::new_without_default)]
// Used to make it nicer to return errors, for example, .ok_or(Error::new(ESRCH))
#![allow(clippy::or_fun_call)]
// This is needed in some cases, like for syscall
#![allow(clippy::too_many_arguments)]
// There is no harm in this being done
#![allow(clippy::useless_format)]

// TODO: address ocurrances and then deny
#![warn(clippy::not_unsafe_ptr_arg_deref)]
// TODO: address ocurrances and then deny
#![warn(clippy::cast_ptr_alignment)]
// Indexing a slice can cause panics and that is something we always want to avoid
// in kernel code. Use .get and return an error instead
// TODO: address ocurrances and then deny
#![warn(clippy::indexing_slicing)]
// Overflows are very, very bad in kernel code as it may provide an attack vector for
// userspace applications, and it is only checked in debug builds
// TODO: address ocurrances and then deny
#![warn(clippy::integer_arithmetic)]
// Avoid panicking in the kernel without information about the panic. Use expect
// TODO: address ocurrances and then deny
#![warn(clippy::result_unwrap_used)]

// This is usually a serious issue - a missing import of a define where it is interpreted
// as a catch-all variable in a match, for example
#![deny(unreachable_patterns)]
// Ensure that all must_use results are used
#![deny(unused_must_use)]

#![feature(alloc_error_handler)]
#![feature(allocator_api)]
#![feature(array_chunks)]
#![feature(iter_array_chunks)]
#![feature(asm_const)] // TODO: Relax requirements of most asm invocations
#![feature(const_option)]
#![feature(const_refs_to_cell)]
#![feature(int_roundings)]
#![feature(let_chains)]
#![feature(naked_functions)]
#![feature(slice_ptr_get, slice_ptr_len)]
#![feature(sync_unsafe_cell)]
#![no_std]
#![no_main]

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub extern crate x86;

#[macro_use]
extern crate alloc;

#[macro_use]
extern crate bitflags;

use core::sync::atomic::{AtomicU32, Ordering};

use crate::scheme::SchemeNamespace;

pub use crate::consts::*;

#[macro_use]
/// Shared data structures
pub mod common;

/// Architecture-dependent stuff
#[macro_use]
pub mod arch;
pub use crate::arch::*;

use crate::log::info;

/// Heap allocators
pub mod allocator;

/// ACPI table parsing
#[cfg(all(feature = "acpi", any(target_arch = "x86", target_arch = "x86_64")))]
mod acpi;

#[cfg(all(any(target_arch = "aarch64")))]
mod dtb;

/// Context management
pub mod context;

/// Debugger
pub mod debugger;

/// Architecture-independent devices
pub mod devices;

/// ELF file parsing
#[cfg(not(feature="doc"))]
pub mod elf;

/// Event handling
pub mod event;

/// External functions
pub mod externs;

/// Logging
pub mod log;

/// Memory management
pub mod memory;

/// Panic
#[cfg(not(any(feature="doc", test)))]
pub mod panic;

pub mod percpu;

/// Process tracing
pub mod ptrace;

/// Schemes, filesystem handlers
pub mod scheme;

/// Synchronization primitives
pub mod sync;

/// Syscall handlers
pub mod syscall;

/// Time
pub mod time;

/// Tests
#[cfg(test)]
pub mod tests;

#[global_allocator]
static ALLOCATOR: allocator::Allocator = allocator::Allocator;

/// Get the current CPU's scheduling ID
#[inline(always)]
pub fn cpu_id() -> LogicalCpuId {
    crate::percpu::PercpuBlock::current().cpu_id
}

/// The count of all CPUs that can have work scheduled
static CPU_COUNT: AtomicU32 = AtomicU32::new(0);

/// Get the number of CPUs currently active
#[inline(always)]
pub fn cpu_count() -> u32 {
    CPU_COUNT.load(Ordering::Relaxed)
}

pub fn init_env() -> &'static [u8] {
    crate::BOOTSTRAP.get().expect("BOOTSTRAP was not set").env
}

pub extern "C" fn userspace_init() {
    let bootstrap = crate::BOOTSTRAP.get().expect("BOOTSTRAP was not set");
    unsafe { crate::syscall::process::usermode_bootstrap(bootstrap) }
}

pub struct Bootstrap {
    pub base: crate::memory::Frame,
    pub page_count: usize,
    pub entry: usize,
    pub env: &'static [u8],
}
static BOOTSTRAP: spin::Once<Bootstrap> = spin::Once::new();

/// This is the kernel entry point for the primary CPU. The arch crate is responsible for calling this
pub fn kmain(cpu_count: u32, bootstrap: Bootstrap) -> ! {
    CPU_COUNT.store(cpu_count, Ordering::SeqCst);

    //Initialize the first context, stored in kernel/src/context/mod.rs
    context::init();

    let pid = syscall::getpid();
    info!("BSP: {:?} {}", pid, cpu_count);
    info!("Env: {:?}", ::core::str::from_utf8(bootstrap.env));

    BOOTSTRAP.call_once(|| bootstrap);

    match context::contexts_mut().spawn(userspace_init) {
        Ok(context_lock) => {
            let mut context = context_lock.write();
            context.rns = SchemeNamespace::from(1);
            context.ens = SchemeNamespace::from(1);
            context.status = context::Status::Runnable;
            context.name = "bootstrap".into();
        },
        Err(err) => {
            panic!("failed to spawn userspace_init: {:?}", err);
        }
    }

    loop {
        unsafe {
            interrupt::disable();
            if context::switch() {
                interrupt::enable_and_nop();
            } else {
                // Enable interrupts, then halt CPU (to save power) until the next interrupt is actually fired.
                interrupt::enable_and_halt();
            }
        }
    }
}

/// This is the main kernel entry point for secondary CPUs
#[allow(unreachable_code, unused_variables)]
pub fn kmain_ap(cpu_id: LogicalCpuId) -> ! {
    if cfg!(feature = "multi_core") {
        context::init();

        let pid = syscall::getpid();
        info!("AP {}: {:?}", cpu_id, pid);

        loop {
            unsafe {
                interrupt::disable();
                if context::switch() {
                    interrupt::enable_and_nop();
                } else {
                    // Enable interrupts, then halt CPU (to save power) until the next interrupt is actually fired.
                    interrupt::enable_and_halt();
                }
            }
        }
    } else {
        info!("AP {}: Disabled", cpu_id);

        loop {
            unsafe {
                interrupt::disable();
                interrupt::halt();
            }
        }
    }
}

/// Allow exception handlers to send signal to arch-independant kernel
#[no_mangle]
pub extern fn ksignal(signal: usize) {
    info!("SIGNAL {}, CPU {}, PID {:?}", signal, cpu_id(), context::context_id());
    {
        let contexts = context::contexts();
        if let Some(context_lock) = contexts.current() {
            let context = context_lock.read();
            info!("NAME {}", context.name);
        }
    }

    // Try running kill(getpid(), signal), but fallback to exiting
    syscall::getpid()
        .and_then(|pid| syscall::kill(pid, signal).map(|_| ()))
        .unwrap_or_else(|_| {
            syscall::exit(signal & 0x7F);
        });
}

// TODO: Use this macro on aarch64 too.

macro_rules! linker_offsets(
    ($($name:ident),*) => {
        $(
        #[inline]
        pub fn $name() -> usize {
            extern "C" {
                // TODO: UnsafeCell?
                static $name: u8;
            }
            unsafe { &$name as *const u8 as usize }
        }
        )*
    }
);
pub mod kernel_executable_offsets {
    linker_offsets!(__text_start, __text_end, __rodata_start, __rodata_end, __data_start, __data_end, __bss_start, __bss_end, __usercopy_start, __usercopy_end);

    #[cfg(target_arch = "x86_64")]
    linker_offsets!(__altrelocs_start, __altrelocs_end);
}

/// A unique number used internally by the kernel to identify CPUs.
///
/// This is usually but not necessarily the same as the APIC ID.

// TODO: Differentiate between logical CPU IDs and hardware CPU IDs (e.g. APIC IDs)
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
// TODO: NonMaxUsize?
// TODO: Optimize away this type if not cfg!(feature = "multi_core")
pub struct LogicalCpuId(u32);

impl LogicalCpuId {
    pub const BSP: Self = Self::new(0);

    pub const fn new(inner: u32) -> Self { Self(inner) }
    pub const fn get(self) -> u32 { self.0 }
}

impl core::fmt::Debug for LogicalCpuId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "[logical cpu #{}]", self.0)
    }
}
impl core::fmt::Display for LogicalCpuId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "#{}", self.0)
    }
}

// TODO: Support more than 128 CPUs.
// The maximum number of CPUs on Linux is configurable, and the type for LogicalCpuSet and
// LogicalCpuId may be optimized accordingly. In that case, box the mask if it's larger than some
// base size (probably 256 bytes).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogicalCpuSet(u128);

impl LogicalCpuSet {
    pub const fn new(inner: u128) -> Self { Self(inner) }
    pub const fn get(self) -> u128 { self.0 }

    pub const fn empty() -> Self { Self::new(0) }
    pub const fn all() -> Self { Self::new(!0) }
    pub const fn single(id: LogicalCpuId) -> Self { Self::new(1 << id.get()) }
    pub const fn contains(&self, id: LogicalCpuId) -> bool {
        self.0 & (1 << id.get()) != 0
    }
}
