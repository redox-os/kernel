use alloc::{string::String, vec::Vec};

use crate::{
    context::{contexts, ContextRef, Status},
    cpu_stats::{self, get_context_switch_count, get_processes_count, irq_counts},
    syscall::error::Result,
    time::START,
};

pub fn resource() -> Result<Vec<u8>> {
    let mut cpu_stats = String::new();
    let stats = cpu_stats::get_all();

    let mut total_user = 0;
    let mut total_nice = 0;
    let mut total_kernel = 0;
    let mut total_idle = 0;
    let mut total_io_wait = 0;
    let mut total_irq = 0;
    let mut total_soft = 0;
    for stat in stats {
        total_user += stat.user;
        total_nice += stat.nice;
        total_kernel += stat.kernel;
        total_idle += stat.idle;
        total_io_wait += stat.io_wait;
        total_irq += stat.irq;
        total_soft += stat.irq_soft;
        cpu_stats += &format!("{stat}\n");
    }
    let start_time_sec = *START.lock() / 1_000_000_000;

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
    let irq_counts = format!("intr {irq_total} {per_irq}");

    let mut processes_running = 0;
    let mut processes_blocked = 0;
    let contexts = contexts();
    for context in contexts.iter() {
        let Some(context) = ContextRef::upgrade(context) else {
            continue;
        };
        let status = context.read().status.clone();
        if matches!(status, Status::Runnable) {
            processes_running += 1;
        } else if !matches!(status, Status::Dead) {
            processes_blocked += 1;
        }
    }

    let res = format!(
        "      user niced kernel idle iowait irq softirq\ncpu  {total_user} {total_nice} {total_kernel} {total_idle} {total_io_wait} {total_irq} {total_soft}\n{cpu_stats}{irq_counts}\nctxt: {}\nbtime: {start_time_sec}\nprocesses: {}\nprocs_running: {processes_running}\nprocs_blocked: {processes_blocked}",
        get_context_switch_count(),
        get_processes_count(),
    );

    Ok(res.into_bytes())
}
