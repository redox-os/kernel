use alloc::{string::String, vec::Vec};

use crate::{
    context::{contexts, ContextRef, Status},
    cpu_stats::{get_all, get_context_switch_count, get_processes_count, irq_counts},
    syscall::error::Result,
    time::START,
};

/// Get the /scheme/proc/stat data
pub fn resource() -> Result<Vec<u8>> {
    let start_time_sec = *START.lock() / 1_000_000_000;

    let (processes_running, processes_blocked) = get_processes_stats();
    let res = format!(
        "{}{}\n\
        ctxt: {}\n\
        btime: {start_time_sec}\n\
        processes: {}\n\
        procs_running: {processes_running}\n\
        procs_blocked: {processes_blocked}",
        get_cpu_stats(),
        get_irq_stats(),
        get_context_switch_count(),
        get_processes_count(),
    );

    Ok(res.into_bytes())
}

fn get_cpu_stats() -> String {
    let mut cpu_data = String::new();
    let stats = get_all();

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
        cpu_data += &format!("{stat}\n");
    }
    format!("cpu  {total_user} {total_nice} {total_kernel} {total_idle} {total_io_wait} {total_irq} {total_soft}\n{cpu_data}")
}

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
    format!("intr {irq_total} {per_irq}")
}

fn get_processes_stats() -> (u64, u64) {
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
