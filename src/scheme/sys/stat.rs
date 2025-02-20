use alloc::{string::String, vec::Vec};

use crate::{
    cpu_stats::{self, get_context_switch_count, irq_counts},
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
    let mut total_irq = 0;
    for stat in stats {
        total_user += stat.user;
        total_nice += stat.nice;
        total_kernel += stat.kernel;
        total_idle += stat.idle;
        total_irq += stat.irq;
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

    let res = format!(
        "      user niced kernel idle irq\ncpu  {total_user} {total_nice} {total_kernel} {total_idle} {total_irq}\n{cpu_stats}{irq_counts}\nctxt: {}\nbtime: {start_time_sec}",
        get_context_switch_count()
    );

    Ok(res.into_bytes())
}
