use crate::{
    context::{contexts, ContextRef, Status},
    cpu_stats::{get_context_switch_count, get_contexts_count, irq_counts},
    percpu::get_all_stats,
    syscall::error::Result,
    time::START,
};
use alloc::{string::String, vec::Vec};

/// Get the sys:stat data as displayed to the user.
pub fn resource() -> Result<Vec<u8>> {
    let start_time_sec = *START.lock() / 1_000_000_000;

    let (contexts_running, contexts_blocked) = get_contexts_stats();
    let res = format!(
        "{}{}\n\
        boot_time: {start_time_sec}\n\
        context_switches: {}\n\
        contexts_created: {}\n\
        contexts_running: {contexts_running}\n\
        contexts_blocked: {contexts_blocked}",
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
        cpu_data += &format!("{}\n", stat.to_string(id));
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
    let per_irq = irq
        .iter()
        .map(|c| {
            irq_total += *c;
            format!("{c}")
        })
        .collect::<Vec<_>>()
        .join(" ");
    format!("IRQs {irq_total} {per_irq}")
}

/// Format contexts stats.
fn get_contexts_stats() -> (u64, u64) {
    let mut running = 0;
    let mut blocked = 0;

    let statuses = contexts()
        .iter()
        .filter_map(ContextRef::upgrade)
        .map(|context| context.read_arc().status.clone())
        .collect::<Vec<_>>();

    for status in statuses {
        if matches!(status, Status::Runnable) {
            running += 1;
        } else if !matches!(status, Status::Dead) {
            blocked += 1;
        }
    }
    (running, blocked)
}
