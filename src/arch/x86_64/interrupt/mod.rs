//! Interrupt instructions

pub use crate::arch::x86_shared::interrupt::*;

#[macro_use]
pub mod handler;

pub mod syscall;

pub use self::handler::InterruptStack;
