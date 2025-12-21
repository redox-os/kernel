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
// Used to allow stuff like 1 << 0 and 1 * 1024 * 1024
#![allow(clippy::identity_op)]
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
#![warn(clippy::arithmetic_side_effects)]
// Avoid panicking in the kernel without information about the panic. Use expect
// TODO: address ocurrances and then deny
#![warn(clippy::unwrap_used)]
// This is usually a serious issue - a missing import of a define where it is interpreted
// as a catch-all variable in a match, for example
#![deny(unreachable_patterns)]
// Ensure that all must_use results are used
#![deny(unused_must_use)]
#![warn(static_mut_refs)] // FIXME deny once all occurences are fixed
#![feature(if_let_guard)]
#![feature(int_roundings)]
#![feature(iter_next_chunk)]
#![feature(sync_unsafe_cell)]
#![feature(variant_count)]
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#[macro_use]
extern crate alloc;

#[macro_use]
extern crate bitflags;

use core::sync::atomic::{AtomicU32, Ordering};

use crate::{context::switch::SwitchResult, scheme::SchemeNamespace};

use crate::consts::*;

#[macro_use]
/// Shared data structures
mod common;

#[macro_use]
mod macros;

/// Architecture-dependent stuff
#[macro_use]
#[allow(dead_code)] // TODO
mod arch;
use crate::arch::*;

/// Heap allocators
mod allocator;

/// ACPI table parsing
#[cfg(feature = "acpi")]
#[allow(dead_code)] // TODO
mod acpi;

#[cfg(dtb)]
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
use sync::CleanLockToken;
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

fn init_env() -> &'static [u8] {
    crate::BOOTSTRAP.get().expect("BOOTSTRAP was not set").env
}

extern "C" fn userspace_init() {
    let mut token = unsafe { CleanLockToken::new() };
    let bootstrap = crate::BOOTSTRAP.get().expect("BOOTSTRAP was not set");
    unsafe { crate::syscall::process::usermode_bootstrap(bootstrap, &mut token) }
}

struct Bootstrap {
    base: crate::memory::Frame,
    page_count: usize,
    env: &'static [u8],
}
static BOOTSTRAP: spin::Once<Bootstrap> = spin::Once::new();

/// This is the kernel entry point for the primary CPU. The arch crate is responsible for calling this
fn kmain(bootstrap: Bootstrap) -> ! {
    let mut token = unsafe { CleanLockToken::new() };

    //Initialize the first context, stored in kernel/src/context/mod.rs
    context::init(&mut token);

    //Initialize global schemes, such as `acpi:`.
    scheme::init_globals();

    debug!("BSP: {} CPUs", cpu_count());
    debug!("Env: {:?}", ::core::str::from_utf8(bootstrap.env));

    BOOTSTRAP.call_once(|| bootstrap);

    profiling::ready_for_profiling();

    let owner = None; // kmain not owned by any fd
    match context::spawn(true, owner, userspace_init, &mut token) {
        Ok(context_lock) => {
            let mut context = context_lock.write(token.token());
            context.status = context::Status::Runnable;
            context.name.clear();
            context.name.push_str("[bootstrap]");

            // TODO: Remove these from kernel
            context.ens = SchemeNamespace::from(1);
            context.euid = 0;
            context.egid = 0;
        }
        Err(err) => {
            panic!("failed to spawn userspace_init: {:?}", err);
        }
    }

    run_userspace(&mut token)
}

/// This is the main kernel entry point for secondary CPUs
#[allow(unreachable_code, unused_variables, dead_code)]
fn kmain_ap(cpu_id: crate::cpu_set::LogicalCpuId) -> ! {
    let mut token = unsafe { CleanLockToken::new() };

    #[cfg(feature = "profiling")]
    profiling::maybe_run_profiling_helper_forever(cpu_id);

    if !cfg!(feature = "multi_core") {
        debug!("AP {}: Disabled", cpu_id);

        loop {
            unsafe {
                interrupt::disable();
                interrupt::halt();
            }
        }
    }

    context::init(&mut token);

    debug!("AP {}", cpu_id);

    profiling::ready_for_profiling();

    run_userspace(&mut token);
}
fn run_userspace(token: &mut CleanLockToken) -> ! {
    loop {
        unsafe {
            interrupt::disable();
            match context::switch(token) {
                SwitchResult::Switched => {
                    interrupt::enable_and_nop();
                }
                SwitchResult::AllContextsIdle => {
                    // Enable interrupts, then halt CPU (to save power) until the next interrupt is actually fired.
                    interrupt::enable_and_halt();
                }
            }
        }
    }
}

// TODO: Use this macro on aarch64 too.

macro_rules! linker_offsets(
    ($($name:ident),*) => {
        $(
        #[inline]
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
