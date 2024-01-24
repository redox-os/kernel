#[cfg(target_arch = "aarch64")]
#[macro_use]
pub mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use self::aarch64::*;

#[cfg(target_arch = "x86")]
#[macro_use]
pub mod x86;
#[cfg(target_arch = "x86")]
pub use self::x86::*;

#[cfg(target_arch = "x86_64")]
#[macro_use]
pub mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use self::x86_64::*;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[macro_use]
mod x86_shared;
