use core::fmt::Write as _;

use crate::{
    context::{contexts, get_contexts_stats, Status},
    cpu_stats::{get_context_switch_count, get_contexts_count, irq_counts},
    event::get_event_stat,
    percpu::get_all_stats,
    sync::CleanLockToken,
    syscall::error::Result,
    time::START,
};
use alloc::{string::String, vec::Vec};

/// Get the sys:stat data as displayed to the user.
pub fn resource(token: &mut CleanLockToken) -> Result<Vec<u8>> {
    let start_time_sec = *START.lock(token.token()) / 1_000_000_000;

    let (contexts_alive, contexts_running, contexts_blocked) = get_contexts_stats(token);
    let (event_keys, event_subs) = get_event_stat(token);
    let res = format!(
        "{}{}\n\
        boot_time: {start_time_sec}\n\
        context_switches: {}\n\
        contexts_created: {}\n\
        contexts_alive: {contexts_alive}\n\
        contexts_running: {contexts_running}\n\
        contexts_blocked: {contexts_blocked}\n\
        event_registries: {event_keys}\n\
        event_subcribers: {event_subs}\n",
        get_cpu_stats(),
        get_irq_stats(),
        get_context_switch_count(),
        get_contexts_count(),
    );

    Ok(res.into_bytes())
}

/// Formats CPU stats.
fn get_cpu_stats() -> String {
    let mut cpu_data = String::new();
    let stats = get_all_stats();

    let mut total_user = 0;
    let mut total_nice = 0;
    let mut total_kernel = 0;
    let mut total_idle = 0;
    let mut total_irq = 0;
    for (id, stat) in stats {
        total_user += stat.user;
        total_nice += stat.nice;
        total_kernel += stat.kernel;
        total_idle += stat.idle;
        total_irq += stat.irq;
        let _ = writeln!(&mut cpu_data, "cpu{} {}", id.get(), stat);
    }
    format!(
        "cpu  {total_user} {total_nice} {total_kernel} {total_idle} {total_irq}\n\
        {cpu_data}"
    )
}

/// Formats IRQ stats.
fn get_irq_stats() -> String {
    let irq = irq_counts();
    let mut irq_total = 0;
    let mut output = String::with_capacity(64);
    for &c in irq.iter() {
        irq_total += c;
    }
    let _ = write!(output, "IRQs {}", irq_total);
    for &c in irq.iter() {
        let _ = write!(output, " {}", c);
    }

    output
}
