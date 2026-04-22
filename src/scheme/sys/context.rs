use alloc::{
    borrow::ToOwned,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt::Write;
use lfll::List;

use crate::{context, context::contexts, sync::CleanLockToken, syscall::error::Result};

pub fn resource(token: &mut CleanLockToken) -> Result<Vec<u8>> {
    let mut string = format!(
        "{:<6}{:<6}{:<6}{:<6}{:<6}{:<11}{:<12}{:<8}{:<8}{}\n",
        "PID", "EUID", "EGID", "STAT", "CPU", "AFFINITY", "TIME", "PRIVATE", "SHARED", "NAME"
    );

    let mut rows = Vec::new();
    {
        let mut contexts = contexts();
        for context_ref in contexts.iter().filter_map(|(_, x)| x.upgrade()) {
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
                    let mut private_memory = 0;
                    let mut shared_memory = 0;
                    // TODO: All user programs must have some grant in order for executable memory to even
                    // exist, but is this a good indicator of whether it is user or kernel?
                    let is_kernel = addr_space_guard.grants.is_empty();
                    for (_base, info) in addr_space_guard.grants.iter() {
                        // wrap as method?
                        match info.provider {
                            context::memory::Provider::Allocated { .. } => {
                                private_memory += info.page_count() * crate::memory::PAGE_SIZE
                            }
                            // Excluded because it is not allocable by user, whether
                            // this region is counted toward usable memory remain unknown
                            context::memory::Provider::PhysBorrowed { .. } => {}
                            _ => shared_memory += info.page_count() * crate::memory::PAGE_SIZE,
                        }
                    }
                    Some((private_memory, shared_memory, is_kernel))
                }
                Err(_) => None,
            };

            let mut stat_string = String::new();
            stat_string.push(match heap {
                Some((_, _, is_kernel)) => {
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

            let (priv_memory, shared_memory) = if let Some((privm, shrdm, _)) = heap {
                (memory + privm, shrdm)
            } else {
                (memory, 0)
            };

            rows.push((
                pid,
                euid,
                egid,
                stat_string,
                cpu_string,
                affinity,
                cpu_time_string,
                format_bytes(priv_memory),
                format_bytes(shared_memory),
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
        priv_memory_string,
        shared_memory_string,
        name,
    ) in rows
    {
        let _ = writeln!(
            string,
            "{:<6}{:<6}{:<6}{:<6}{:<6}{:<11}{:<12}{:<8}{:<8}{}",
            pid,
            euid,
            egid,
            stat_string,
            cpu_string,
            affinity,
            cpu_time_string,
            priv_memory_string,
            shared_memory_string,
            name,
        );
    }

    Ok(string.into_bytes())
}

fn format_bytes(memory: usize) -> String {
    const GB: usize = 1024 * 1024 * 1024;
    const MB: usize = 1024 * 1024;
    const KB: usize = 1024;

    if memory > GB {
        format_bytes_inner(memory, GB, "GB")
    } else if memory > MB {
        format_bytes_inner(memory, MB, "MB")
    } else if memory > KB {
        format_bytes_inner(memory, KB, "KB")
    } else {
        format!("{memory} B")
    }
}

fn format_bytes_inner(memory: usize, divisor: usize, suffix: &'static str) -> String {
    let mut s = format!("{}", memory / divisor);
    if s.len() == 1 {
        let _ = write!(s, ".{:02}", (memory % divisor) / (divisor / 100));
    } else if s.len() == 2 {
        let _ = write!(s, ".{:01}", (memory % divisor) / (divisor / 10));
    }

    let _ = write!(s, " {suffix}");
    s
}
