//! I/O functions

pub use self::{io::*, mmio::*, mmio_ptr::*};

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use self::pio::*;

mod io;
mod mmio;
mod mmio_ptr;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod pio;
