//! # The Redox OS Kernel, version 2
//!
//! The Redox OS Kernel is a microkernel that supports `x86_64` systems and
//! provides Unix-like syscalls for primarily Rust applications

// Necessary for alternative! macro.
#![allow(unexpected_cfgs)]
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
#![feature(allocator_api)]
#![feature(asm_const)]
#![feature(core_intrinsics)]
#![allow(internal_features)]
#![feature(int_roundings)]
#![feature(iter_next_chunk)]
#![feature(let_chains)]
#![feature(naked_functions)]
#![feature(new_uninit)]
#![feature(sync_unsafe_cell)]
#![feature(variant_count)]
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#![feature(option_get_or_insert_default)]
#![feature(array_chunks)]
#![feature(if_let_guard)]

#[macro_use]
extern crate alloc;

#[macro_use]
extern crate bitflags;

use core::sync::atomic::{AtomicU32, Ordering};

use crate::{
    context::{
        process::{new_process, ProcessInfo, INIT},
        switch::SwitchResult,
    },
    scheme::SchemeNamespace,
};

use crate::consts::*;

#[macro_use]
/// Shared data structures
mod common;

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

/// Context management
mod context;

/// Debugger
#[cfg(feature = "debugger")]
mod debugger;

/// Architecture-independent devices
mod devices;

/// ELF file parsing
mod elf;

/// Event handling
mod event;

/// External functions
mod externs;

/// Logging
mod log;
use ::log::info;
use alloc::sync::Arc;
use spinning_top::RwSpinlock;

/// Memory management
mod memory;

/// Panic
mod panic;

mod percpu;

/// Process tracing
mod ptrace;

/// Performance profiling of the kernel
#[cfg(feature = "profiling")]
pub mod profiling;

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
static CPU_COUNT: AtomicU32 = AtomicU32::new(0);

/// Get the number of CPUs currently active
#[inline(always)]
fn cpu_count() -> u32 {
    CPU_COUNT.load(Ordering::Relaxed)
}

fn init_env() -> &'static [u8] {
    crate::BOOTSTRAP.get().expect("BOOTSTRAP was not set").env
}

extern "C" fn userspace_init() {
    let bootstrap = crate::BOOTSTRAP.get().expect("BOOTSTRAP was not set");
    unsafe { crate::syscall::process::usermode_bootstrap(bootstrap) }
}

struct Bootstrap {
    base: crate::memory::Frame,
    page_count: usize,
    env: &'static [u8],
}
static BOOTSTRAP: spin::Once<Bootstrap> = spin::Once::new();
static INIT_THREAD: spin::Once<Arc<RwSpinlock<crate::context::Context>>> = spin::Once::new();

/// This is the kernel entry point for the primary CPU. The arch crate is responsible for calling this
fn kmain(cpu_count: u32, bootstrap: Bootstrap) -> ! {
    CPU_COUNT.store(cpu_count, Ordering::SeqCst);

    //Initialize the first context, stored in kernel/src/context/mod.rs
    context::init();

    //Initialize global schemes, such as `acpi:`.
    scheme::init_globals();

    let pid = syscall::getpid();
    info!("BSP: {:?} {}", pid, cpu_count);
    info!("Env: {:?}", ::core::str::from_utf8(bootstrap.env));

    BOOTSTRAP.call_once(|| bootstrap);

    #[cfg(feature = "profiling")]
    profiling::ready_for_profiling();

    let process = new_process(|_| ProcessInfo {
        pid: INIT,
        ppid: INIT,
        pgid: INIT,
        session_id: INIT,
        ruid: 0,
        rgid: 0,
        euid: 0,
        egid: 0,
        rns: SchemeNamespace::new(0),
        ens: SchemeNamespace::new(0),
    })
    .expect("failed to create init process");

    match context::spawn(true, process, userspace_init) {
        Ok(context_lock) => {
            {
                let mut context = context_lock.write();
                context.status = context::Status::Runnable;
                context.name = "bootstrap".into();

                let mut process = context.process.write();
                process.rns = SchemeNamespace::from(1);
                process.ens = SchemeNamespace::from(1);
            }
            INIT_THREAD.call_once(move || context_lock);
        }
        Err(err) => {
            panic!("failed to spawn userspace_init: {:?}", err);
        }
    }

    run_userspace()
}

/// This is the main kernel entry point for secondary CPUs
#[allow(unreachable_code, unused_variables, dead_code)]
fn kmain_ap(cpu_id: crate::cpu_set::LogicalCpuId) -> ! {
    #[cfg(feature = "profiling")]
    profiling::maybe_run_profiling_helper_forever(cpu_id);

    //TODO: workaround for bug where an AP on MeteorLake has cpu_id 0
    if !cfg!(feature = "multi_core") || cpu_id == crate::cpu_set::LogicalCpuId::BSP {
        info!("AP {}: Disabled", cpu_id);

        loop {
            unsafe {
                interrupt::disable();
                interrupt::halt();
            }
        }
    }
    context::init();

    let pid = syscall::getpid();
    info!("AP {}: {:?}", cpu_id, pid);

    #[cfg(feature = "profiling")]
    profiling::ready_for_profiling();

    run_userspace();
}
fn run_userspace() -> ! {
    loop {
        unsafe {
            interrupt::disable();
            match context::switch() {
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

/// Allow exception handlers to send signal to arch-independent kernel
pub fn ksignal(signal: usize) {
    let current = context::current();

    info!("SIGNAL {signal}, CPU {}, PID {current:p}", cpu_id(),);
    {
        let context = current.read();
        info!("NAME {}", context.name);
    }
    crate::context::signal::excp_handler(signal);
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
mod kernel_executable_offsets {
    linker_offsets!(
        __text_start,
        __text_end,
        __rodata_start,
        __rodata_end,
        __data_start,
        __data_end,
        __bss_start,
        __bss_end,
        __usercopy_start,
        __usercopy_end
    );

    #[cfg(target_arch = "x86_64")]
    linker_offsets!(__altrelocs_start, __altrelocs_end);
}
