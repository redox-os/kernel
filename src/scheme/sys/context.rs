use alloc::string::String;
use alloc::vec::Vec;

use crate::context;
use crate::syscall::error::Result;

pub fn resource() -> Result<Vec<u8>> {
    let mut string = format!("{:<6}{:<6}{:<6}{:<6}{:<6}{:<6}{:<6}{:<6}{:<6}{:<6}{:<6}{:<8}{:<8}{}\n",
                             "PID",
                             "PGID",
                             "PPID",
                             "RUID",
                             "RGID",
                             "RNS",
                             "EUID",
                             "EGID",
                             "ENS",
                             "STAT",
                             "CPU",
                             "TICKS",
                             "MEM",
                             "NAME");
    {
        let contexts = context::contexts();
        for (_id, context_lock) in contexts.iter() {
            let context = context_lock.read();

            let mut stat_string = String::new();
            // TODO: All user programs must have some grant in order for executable memory to even
            // exist, but is this a good indicator of whether it is user or kernel?
            stat_string.push(if let Ok(addr_space) = context.addr_space() {
                if addr_space.read().grants.is_empty() {
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
                },
                context::Status::Blocked => if context.wake.is_some() {
                    stat_string.push('S');
                } else {
                    stat_string.push('B');
                },
                context::Status::Stopped(_sig) => {
                    stat_string.push('T');
                }
                context::Status::Exited(_status) => {
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

            let cpu_time = context.cpu_time / crate::time::NANOS_PER_SEC;
            let cpu_time_string = format!(
                "{:02}:{:02}:{:02}",
                cpu_time / 3600,
                (cpu_time / 60) % 60,
                cpu_time % 60
            );

            let mut memory = context.kfx.len();
            if let Some(ref kstack) = context.kstack {
                memory += kstack.len();
            }
            if let Ok(addr_space) = context.addr_space() {
                for grant in addr_space.read().grants.iter() {
                    if grant.is_owned() {
                        memory += grant.size();
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

            string.push_str(&format!("{:<6}{:<6}{:<6}{:<6}{:<6}{:<6}{:<6}{:<6}{:<6}{:<6}{:<6}{:<9}{:<8}{}\n",
                               context.id.into(),
                               context.pgid.into(),
                               context.ppid.into(),
                               context.ruid,
                               context.rgid,
                               context.rns.into(),
                               context.euid,
                               context.egid,
                               context.ens.into(),
                               stat_string,
                               cpu_string,
                               cpu_time_string,
                               memory_string,
                               *context.name.read()));
        }
    }

    Ok(string.into_bytes())
}
