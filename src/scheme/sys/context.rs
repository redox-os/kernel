use alloc::{
    borrow::ToOwned,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt::Write;

use crate::{context, percpu, sync::CleanLockToken, syscall::error::Result};

pub fn resource(token: &mut CleanLockToken) -> Result<Vec<u8>> {
    let mut string = format!(
        "{:<6}{:<6}{:<6}{:<6}{:<6}{:<11}{:<12}{:<8}{}\n",
        "PID", "EUID", "EGID", "STAT", "CPU", "AFFINITY", "TIME", "MEM", "NAME"
    );

    let mut rows = Vec::new();
    {
        let mut contexts = percpu::get_all_contexts(token.downgrade());
        for context_ref in contexts {
            let context = context_ref.read(token.token());
            let addr_space = context.addr_space().map(|a| a.clone());

            let affinity = context.sched_affinity.to_string();
            let cpu_time_s = context.cpu_time / crate::time::NANOS_PER_SEC;
            let cpu_time_ns = context.cpu_time % crate::time::NANOS_PER_SEC;
            let mut memory = context.kfx.len();
            if let Some(ref kstack) = context.kstack {
                memory += kstack.len();
            }
            let (status, cpuid) = (context.status.clone(), context.cpu_id);
            let (pid, euid, egid) = (context.pid, context.euid, context.egid);
            let (running, is_awake) = (context.running, context.wake.is_some());
            let name = context.name;
            drop(context);

            let heap = match addr_space {
                Ok(addr_space) => {
                    let addr_space_guard = addr_space.acquire_read(token.downgrade());
                    let mut memory = 0;
                    // TODO: All user programs must have some grant in order for executable memory to even
                    // exist, but is this a good indicator of whether it is user or kernel?
                    let is_kernel = addr_space_guard.grants.is_empty();
                    for (_base, info) in addr_space_guard.grants.iter() {
                        // TODO: shared memory? wrap as method?
                        if matches!(info.provider, context::memory::Provider::Allocated { .. }) {
                            memory += info.page_count() * crate::memory::PAGE_SIZE;
                        }
                    }
                    Some((memory, is_kernel))
                }
                Err(_) => None,
            };

            let mut stat_string = String::new();
            stat_string.push(match heap {
                Some((pages, is_kernel)) => {
                    if is_kernel {
                        'K'
                    } else {
                        'U'
                    }
                }
                _ => 'R',
            });
            match status {
                context::Status::Runnable => {
                    stat_string.push('R');
                }
                context::Status::Blocked | context::Status::HardBlocked { .. } => {
                    if is_awake {
                        stat_string.push('S');
                    } else {
                        stat_string.push('B');
                    }
                }
                context::Status::Dead { .. } => {
                    stat_string.push('Z');
                }
            }
            if running {
                stat_string.push('+');
            }

            let cpu_string = match cpuid {
                Some(cpu_id) => {
                    format!("{cpu_id}")
                }
                _ => "?".to_owned(),
            };
            let cpu_time_string = format!(
                "{:02}:{:02}:{:02}.{:02}",
                cpu_time_s / 3600,
                (cpu_time_s / 60) % 60,
                cpu_time_s % 60,
                cpu_time_ns / 10_000_000
            );

            if let Some((heap, _)) = heap {
                memory += heap;
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
                pid,
                euid,
                egid,
                stat_string,
                cpu_string,
                affinity,
                cpu_time_string,
                memory_string,
                name,
            ));
        }
    }
    rows.sort_by_key(|row| row.0);

    for (
        pid,
        euid,
        egid,
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
            "{:<6}{:<6}{:<6}{:<6}{:<6}{:<11}{:<12}{:<8}{}",
            pid,
            euid,
            egid,
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
