mod context_switch;
mod support;
mod switch;

#[cfg(feature = "scheduler_round_robin")]
mod round_robin;
#[cfg(feature = "scheduler_round_robin")]
pub use round_robin::*;

#[cfg(feature = "scheduler_eevdf")]
mod eevdf;
#[cfg(feature = "scheduler_eevdf")]
pub use eevdf::*;

pub use context_switch::{ContextSwitchPercpu, SwitchResult};
pub use support::{switch_finish_hook, tick};
pub use switch::switch;

/// The number of CPU ticks allocated to a context
pub const QUANTUM_SIZE: usize = 3;

#[cfg(any(all(feature = "scheduler_round_robin", any(feature = "scheduler_eevdf"))))]
compile_error!("only one schduler feature can be activated at a time");

#[cfg(not(any(feature = "scheduler_round_robin", feature = "scheduler_eevdf")))]
compile_error!("at least one scheduler feature must be activated");

#[cfg(not(feature = "scheduler_eevdf"))]
pub fn context_join(_context: &mut super::Context, _context_ref: super::ContextRef) {}

#[cfg(not(feature = "scheduler_eevdf"))]
pub fn context_leave(_context: &mut super::Context, _context_ref: super::ContextRef) {}
