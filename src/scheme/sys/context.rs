use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crate::{context, paging::PAGE_SIZE, syscall::error::Result};

pub fn resource() -> Result<Vec<u8>> {
    let mut string = format!(
        "{:<6}{:<6}{:<6}{:<6}{:<6}{:<6}{:<6}{:<6}{:<6}{:<6}{:<6}{:<6}{:<11}{:<12}{:<8}{}\n",
        "PID",
        "PGID",
        "PPID",
        "SID",
        "RUID",
        "RGID",
        "RNS",
        "EUID",
        "EGID",
        "ENS",
        "STAT",
        "CPU",
        "AFFINITY",
        "TIME",
        "MEM",
        "NAME"
    );
    {
        let contexts = context::contexts();
        for context_ref in contexts.iter().filter_map(|r| r.upgrade()) {
            let context = context_ref.read();

            let mut stat_string = String::new();
            // TODO: All user programs must have some grant in order for executable memory to even
            // exist, but is this a good indicator of whether it is user or kernel?
            stat_string.push(if let Ok(addr_space) = context.addr_space() {
                if addr_space.acquire_read().grants.is_empty() {
                    'K'
                } else {
                    'U'
                }
            } else {
                'R'
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
                context::Status::Dead => {
                    stat_string.push('Z');
                }
            }
            if context.running {
                stat_string.push('+');
            }

            let cpu_string = if let Some(cpu_id) = context.cpu_id {
                format!("{}", cpu_id)
            } else {
                format!("?")
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
            let process = context.process.read();

            string.push_str(&format!(
                "{:<6}{:<6}{:<6}{:<6}{:<6}{:<6}{:<6}{:<6}{:<6}{:<6}{:<6}{:<6}{:<11}{:<12}{:<8}{}\n",
                context.pid.get(),
                process.pgid.get(),
                process.ppid.get(),
                process.session_id.get(),
                process.ruid,
                process.rgid,
                process.rns.get(),
                process.euid,
                process.egid,
                process.ens.get(),
                stat_string,
                cpu_string,
                affinity,
                cpu_time_string,
                memory_string,
                context.name,
            ));
        }
    }

    Ok(string.into_bytes())
}
