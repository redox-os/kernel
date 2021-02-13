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
            if context.stack.is_some() {
                stat_string.push('U');
            } else {
                stat_string.push('K');
            }
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

            let ticks = context.ticks;
            let ticks_string = if ticks >= 1000 * 1000 * 1000 * 1000 {
                format!("{} T", ticks / 1000 / 1000 / 1000 / 1000)
            } else if ticks >= 1000 * 1000 * 1000 {
                format!("{} G", ticks / 1000 / 1000 / 1000)
            } else if ticks >= 1000 * 1000 {
                format!("{} M", ticks / 1000 / 1000)
            } else if ticks >= 1000 {
                format!("{} K", ticks / 1000)
            } else {
                format!("{}", ticks)
            };

            let mut memory = 0;
            if let Some(ref kfx) = context.kstack {
                memory += kfx.len();
            }
            if let Some(ref kstack) = context.kstack {
                memory += kstack.len();
            }
            for shared_mem in context.image.iter() {
                shared_mem.with(|mem| {
                    memory += mem.size();
                });
            }
            if let Some(ref stack) = context.stack {
                stack.with(|stack| {
                    memory += stack.size();
                });
            }
            if let Some(ref sigstack) = context.sigstack {
                memory += sigstack.size();
            }
            for grant in context.grants.read().iter() {
                if grant.is_owned() {
                    memory += grant.size();
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

            string.push_str(&format!("{:<6}{:<6}{:<6}{:<6}{:<6}{:<6}{:<6}{:<6}{:<6}{:<6}{:<6}{:<8}{:<8}{}\n",
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
                               ticks_string,
                               memory_string,
                               *context.name.read()));
        }
    }

    Ok(string.into_bytes())
}
