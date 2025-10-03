use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::fmt::Write;

use crate::{context, paging::PAGE_SIZE, sync::CleanLockToken, syscall::error::Result};

pub fn resource(token: &mut CleanLockToken) -> Result<Vec<u8>> {
    let mut string = format!(
        "{:<6}{:<6}{:<6}{:<6}{:<6}{:<6}{:<11}{:<12}{:<8}{}\n",
        "PID", "EUID", "EGID", "ENS", "STAT", "CPU", "AFFINITY", "TIME", "MEM", "NAME"
    );

    let mut rows = Vec::new();
    {
        let mut contexts = context::contexts(token.token());
        let (contexts, mut token) = contexts.token_split();
        for context_ref in contexts.iter().filter_map(|r| r.upgrade()) {
            let context = context_ref.read(token.token());

            let mut stat_string = String::new();
            // TODO: All user programs must have some grant in order for executable memory to even
            // exist, but is this a good indicator of whether it is user or kernel?
            stat_string.push(match context.addr_space() {
                Ok(addr_space) => {
                    if addr_space.acquire_read().grants.is_empty() {
                        'K'
                    } else {
                        'U'
                    }
                }
                _ => 'R',
            });
            match context.status {
                context::Status::Runnable => {
                    stat_string.push('R');
                }
                context::Status::Blocked | context::Status::HardBlocked { .. } => {
                    if context.wake.is_some() {
                        stat_string.push('S');
                    } else {
                        stat_string.push('B');
                    }
                }
                context::Status::Dead { .. } => {
                    stat_string.push('Z');
                }
            }
            if context.running {
                stat_string.push('+');
            }

            let cpu_string = match context.cpu_id {
                Some(cpu_id) => {
                    format!("{}", cpu_id)
                }
                _ => {
                    format!("?")
                }
            };
            let affinity = context.sched_affinity.to_string();

            let cpu_time_s = context.cpu_time / crate::time::NANOS_PER_SEC;
            let cpu_time_ns = context.cpu_time % crate::time::NANOS_PER_SEC;
            let cpu_time_string = format!(
                "{:02}:{:02}:{:02}.{:02}",
                cpu_time_s / 3600,
                (cpu_time_s / 60) % 60,
                cpu_time_s % 60,
                cpu_time_ns / 10_000_000
            );

            let mut memory = context.kfx.len();
            if let Some(ref kstack) = context.kstack {
                memory += kstack.len();
            }
            if let Ok(addr_space) = context.addr_space() {
                for (_base, info) in addr_space.acquire_read().grants.iter() {
                    // TODO: method
                    if matches!(info.provider, context::memory::Provider::Allocated { .. }) {
                        memory += info.page_count() * PAGE_SIZE;
                    }
                }
            }

            let memory_string = if memory >= 1024 * 1024 * 1024 {
                format!("{} GB", memory / 1024 / 1024 / 1024)
            } else if memory >= 1024 * 1024 {
                format!("{} MB", memory / 1024 / 1024)
            } else if memory >= 1024 {
                format!("{} KB", memory / 1024)
            } else {
                format!("{} B", memory)
            };

            rows.push((
                context.pid,
                context.euid,
                context.egid,
                context.ens.get(),
                stat_string,
                cpu_string,
                affinity,
                cpu_time_string,
                memory_string,
                context.name,
            ));
        }
    }
    rows.sort_by_key(|row| row.0);

    for (
        pid,
        euid,
        egid,
        ens,
        stat_string,
        cpu_string,
        affinity,
        cpu_time_string,
        memory_string,
        name,
    ) in rows
    {
        let _ = writeln!(
            string,
            "{:<6}{:<6}{:<6}{:<6}{:<6}{:<6}{:<11}{:<12}{:<8}{}",
            pid,
            euid,
            egid,
            ens,
            stat_string,
            cpu_string,
            affinity,
            cpu_time_string,
            memory_string,
            name,
        );
    }

    Ok(string.into_bytes())
}
