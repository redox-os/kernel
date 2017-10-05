//! # The Redox OS Kernel, version 2
//!
//! The Redox OS Kernel is a microkernel that supports X86_64 systems and
//! provides Unix-like syscalls for primarily Rust applications

//#![deny(warnings)]
#![feature(alloc)]
#![feature(allocator_api)]
#![feature(asm)]
#![feature(collections)]
#![feature(concat_idents)]
#![feature(conservative_impl_trait)]
#![feature(const_atomic_usize_new)]
#![feature(const_fn)]
#![feature(const_max_value)]
#![feature(core_intrinsics)]
#![feature(drop_types_in_const)]
#![feature(global_allocator)]
#![feature(integer_atomics)]
#![feature(lang_items)]
#![feature(naked_functions)]
#![feature(never_type)]
#![feature(thread_local)]
#![feature(unique)]
#![feature(const_size_of)]
#![no_std]

extern crate alloc_kernel as allocator;
pub extern crate x86;

extern crate alloc;
#[macro_use]
extern crate collections;

#[macro_use]
extern crate bitflags;
extern crate goblin;
extern crate spin;

use alloc::arc::Arc;
use core::sync::atomic::{AtomicUsize, ATOMIC_USIZE_INIT, Ordering};
use spin::Mutex;

use scheme::FileHandle;

pub use consts::*;

#[macro_use]
/// Shared data structures
pub mod common;

/// Architecture-dependent stuff
#[macro_use]
pub mod arch;
pub use arch::*;

/// Constants like memory locations
pub mod consts;

/// ACPI table parsing
mod acpi;

/// Context management
pub mod context;

/// Architecture-independent devices
pub mod devices;

/// ELF file parsing
#[cfg(not(feature="doc"))]
pub mod elf;

/// External functions
pub mod externs;

/// Memory management
pub mod memory;

/// Panic
#[cfg(not(any(feature="doc", test)))]
pub mod panic;

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

/// A unique number that identifies the current CPU - used for scheduling
#[thread_local]
static CPU_ID: AtomicUsize = ATOMIC_USIZE_INIT;

/// Get the current CPU's scheduling ID
#[inline(always)]
pub fn cpu_id() -> usize {
    CPU_ID.load(Ordering::Relaxed)
}

/// The count of all CPUs that can have work scheduled
static CPU_COUNT : AtomicUsize = ATOMIC_USIZE_INIT;

/// Get the number of CPUs currently active
#[inline(always)]
pub fn cpu_count() -> usize {
    CPU_COUNT.load(Ordering::Relaxed)
}

/// Initialize userspace by running the initfs:bin/init process
/// This function will also set the CWD to initfs:bin and open debug: as stdio
pub extern fn userspace_init() {
    assert_eq!(syscall::chdir(b"initfs:"), Ok(0));

    assert_eq!(syscall::open(b"debug:", syscall::flag::O_RDONLY).map(FileHandle::into), Ok(0));
    assert_eq!(syscall::open(b"debug:", syscall::flag::O_WRONLY).map(FileHandle::into), Ok(1));
    assert_eq!(syscall::open(b"debug:", syscall::flag::O_WRONLY).map(FileHandle::into), Ok(2));

    syscall::exec(b"/bin/init", &[]).expect("failed to execute init");

    panic!("init returned");
}

/// This is the kernel entry point for the primary CPU. The arch crate is responsible for calling this
pub fn kmain(cpus: usize, env: &[u8]) -> ! {
    CPU_ID.store(0, Ordering::SeqCst);
    CPU_COUNT.store(cpus, Ordering::SeqCst);

    context::init();

    let pid = syscall::getpid();
    println!("BSP: {:?} {}", pid, cpus);
    println!("Env: {:?}", ::core::str::from_utf8(env));

    match context::contexts_mut().spawn(userspace_init) {
        Ok(context_lock) => {
            let mut context = context_lock.write();
            context.status = context::Status::Runnable;

            let mut context_env = context.env.lock();
            for line in env.split(|b| *b == b'\n') {
                let mut parts = line.splitn(2, |b| *b == b'=');
                if let Some(name) = parts.next() {
                    if let Some(data) = parts.next() {
                        context_env.insert(
                            name.to_vec().into_boxed_slice(),
                            Arc::new(Mutex::new(data.to_vec()))
                        );
                    }
                }
            }
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
pub fn kmain_ap(id: usize) -> ! {
    CPU_ID.store(id, Ordering::SeqCst);

    if cfg!(feature = "multi_core"){
        context::init();

        let pid = syscall::getpid();
        println!("AP {}: {:?}", id, pid);

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
        println!("AP {}: Disabled", id);

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
    println!("SIGNAL {}, CPU {}, PID {:?}", signal, cpu_id(), context::context_id());
    {
        let contexts = context::contexts();
        if let Some(context_lock) = contexts.current() {
            let context = context_lock.read();
            println!("NAME {}", unsafe { ::core::str::from_utf8_unchecked(&context.name.lock()) });
        }
    }
    syscall::exit(signal & 0x7F);
}
