use alloc::{string::String, vec::Vec};
use core::{ascii, mem};

use super::{
    copy_path_to_buf,
    data::{Map, Stat, TimeSpec},
    flag::*,
    number::*,
    usercopy::UserSlice,
};

use crate::syscall::error::Result;

struct ByteStr<'a>(&'a [u8]);

impl<'a> ::core::fmt::Debug for ByteStr<'a> {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "\"")?;
        for i in self.0 {
            for ch in ascii::escape_default(*i) {
                write!(f, "{}", ch as char)?;
            }
        }
        write!(f, "\"")?;
        Ok(())
    }
}
fn debug_path(ptr: usize, len: usize) -> Result<String> {
    // TODO: PATH_MAX
    UserSlice::ro(ptr, len).and_then(|slice| copy_path_to_buf(slice, 4096))
}
fn debug_buf(ptr: usize, len: usize) -> Result<Vec<u8>> {
    UserSlice::ro(ptr, len).and_then(|user| {
        let mut buf = vec![0_u8; 4096];
        let count = user.copy_common_bytes_to_slice(&mut buf)?;
        buf.truncate(count);
        Ok(buf)
    })
}
unsafe fn read_struct<T>(ptr: usize) -> Result<T> {
    UserSlice::ro(ptr, mem::size_of::<T>()).and_then(|slice| slice.read_exact::<T>())
}

//TODO: calling format_call with arguments from another process space will not work
pub fn format_call(a: usize, b: usize, c: usize, d: usize, e: usize, f: usize) -> String {
    match a {
        SYS_OPEN => format!(
            "open({:?}, {:#X})",
            debug_path(b, c).as_ref().map(|p| ByteStr(p.as_bytes())),
            d
        ),
        SYS_RMDIR => format!(
            "rmdir({:?})",
            debug_path(b, c).as_ref().map(|p| ByteStr(p.as_bytes())),
        ),
        SYS_UNLINK => format!(
            "unlink({:?})",
            debug_path(b, c).as_ref().map(|p| ByteStr(p.as_bytes())),
        ),
        SYS_CLOSE => format!("close({})", b),
        SYS_DUP => format!(
            "dup({}, {:?})",
            b,
            debug_buf(c, d).as_ref().map(|b| ByteStr(&*b)),
        ),
        SYS_DUP2 => format!(
            "dup2({}, {}, {:?})",
            b,
            c,
            debug_buf(d, e).as_ref().map(|b| ByteStr(&*b)),
        ),
        SYS_SENDFD => format!("sendfd({}, {}, {:#0x} {:#0x} {:#0x})", b, c, d, e, f,),
        SYS_READ => format!("read({}, {:#X}, {})", b, c, d),
        SYS_READ2 => format!(
            "read2({}, {:#X}, {}, {}, {:?})",
            b,
            c,
            d,
            e,
            (f != usize::MAX).then_some(RwFlags::from_bits_retain(f as u32))
        ),
        SYS_WRITE => format!("write({}, {:#X}, {})", b, c, d),
        SYS_WRITE2 => format!(
            "write2({}, {:#X}, {}, {}, {:?})",
            b,
            c,
            d,
            e,
            (f != usize::MAX).then_some(RwFlags::from_bits_retain(f as u32))
        ),
        SYS_LSEEK => format!(
            "lseek({}, {}, {} ({}))",
            b,
            c as isize,
            match d {
                SEEK_SET => "SEEK_SET",
                SEEK_CUR => "SEEK_CUR",
                SEEK_END => "SEEK_END",
                _ => "UNKNOWN",
            },
            d
        ),
        SYS_FCHMOD => format!("fchmod({}, {:#o})", b, c),
        SYS_FCHOWN => format!("fchown({}, {}, {})", b, c, d),
        SYS_FCNTL => format!(
            "fcntl({}, {} ({}), {:#X})",
            b,
            match c {
                F_DUPFD => "F_DUPFD",
                F_GETFD => "F_GETFD",
                F_SETFD => "F_SETFD",
                F_SETFL => "F_SETFL",
                F_GETFL => "F_GETFL",
                _ => "UNKNOWN",
            },
            c,
            d
        ),
        SYS_FMAP => format!(
            "fmap({}, {:?})",
            b,
            UserSlice::ro(c, d).and_then(|buf| unsafe { buf.read_exact::<Map>() }),
        ),
        SYS_FUNMAP => format!("funmap({:#X}, {:#X})", b, c,),
        SYS_FPATH => format!("fpath({}, {:#X}, {})", b, c, d),
        SYS_FRENAME => format!("frename({}, {:?})", b, debug_path(c, d),),
        SYS_FSTAT => format!(
            "fstat({}, {:?})",
            b,
            UserSlice::ro(c, d).and_then(|buf| unsafe { buf.read_exact::<Stat>() }),
        ),
        SYS_FSTATVFS => format!("fstatvfs({}, {:#X}, {})", b, c, d),
        SYS_FSYNC => format!("fsync({})", b),
        SYS_FTRUNCATE => format!("ftruncate({}, {})", b, c),
        SYS_FUTIMENS => format!(
            "futimens({}, {:?})",
            b,
            UserSlice::ro(c, d).and_then(|buf| {
                let mut times = vec![unsafe { buf.read_exact::<TimeSpec>()? }];

                // One or two timespecs
                if let Some(second) = buf.advance(mem::size_of::<TimeSpec>()) {
                    times.push(unsafe { second.read_exact::<TimeSpec>()? });
                }
                Ok(times)
            }),
        ),

        SYS_CLOCK_GETTIME => format!("clock_gettime({}, {:?})", b, unsafe {
            read_struct::<TimeSpec>(c)
        }),
        SYS_EXIT => format!("exit({})", b),
        SYS_FUTEX => format!(
            "futex({:#X} [{:?}], {}, {}, {}, {})",
            b,
            UserSlice::ro(b, 4).and_then(|buf| buf.read_u32()),
            c,
            d,
            e,
            f
        ),
        SYS_GETEGID => format!("getegid()"),
        SYS_GETENS => format!("getens()"),
        SYS_GETEUID => format!("geteuid()"),
        SYS_GETGID => format!("getgid()"),
        SYS_GETNS => format!("getns()"),
        SYS_GETPGID => format!("getpgid()"),
        SYS_GETPID => format!("getpid()"),
        SYS_GETPPID => format!("getppid()"),
        SYS_GETUID => format!("getuid()"),
        SYS_IOPL => format!("iopl({})", b),
        SYS_KILL => format!("kill({}, {})", b, c),
        SYS_MKNS => format!(
            "mkns({:p} len: {})",
            // TODO: Print out all scheme names?

            // Simply printing out simply the pointers and lengths may not provide that much useful
            // debugging information, so only print the raw args.
            b as *const u8,
            c,
        ),
        SYS_MPROTECT => format!("mprotect({:#X}, {}, {:?})", b, c, MapFlags::from_bits(d)),
        SYS_NANOSLEEP => format!(
            "nanosleep({:?}, ({}, {}))",
            unsafe { read_struct::<TimeSpec>(b) },
            c,
            d
        ),
        SYS_VIRTTOPHYS => format!("virttophys({:#X})", b),
        SYS_SETREGID => format!("setregid({}, {})", b, c),
        SYS_SETRENS => format!("setrens({}, {})", b, c),
        SYS_SETREUID => format!("setreuid({}, {})", b, c),
        SYS_WAITPID => format!("waitpid({}, {:#X}, {:?})", b, c, WaitFlags::from_bits(d)),
        SYS_YIELD => format!("yield()"),
        _ => format!(
            "UNKNOWN{} {:#X}({:#X}, {:#X}, {:#X}, {:#X}, {:#X})",
            a, a, b, c, d, e, f
        ),
    }
}

#[derive(Clone, Copy, Debug, Default)]
#[cfg(feature = "syscall_debug")]
pub struct SyscallDebugInfo {
    this_switch_time: u128,
    accumulated_time: u128,
    do_debug: bool,
}
#[cfg(feature = "syscall_debug")]
impl SyscallDebugInfo {
    pub fn on_switch_from(&mut self) {
        let now = crate::time::monotonic();
        self.accumulated_time += now - core::mem::replace(&mut self.this_switch_time, now);
    }
    pub fn on_switch_to(&mut self) {
        self.this_switch_time = crate::time::monotonic();
    }
}
#[cfg(feature = "syscall_debug")]
pub fn debug_start([a, b, c, d, e, f]: [usize; 6]) {
    let do_debug = if false && crate::context::current().read().name.contains("acpid") {
        if a == SYS_CLOCK_GETTIME || a == SYS_YIELD || a == SYS_FUTEX {
            false
        } else if (a == SYS_WRITE || a == SYS_FSYNC) && (b == 1 || b == 2) {
            false
        } else {
            true
        }
    } else {
        false
    };

    let debug_start = if do_debug {
        let context_lock = crate::context::current();
        {
            let context = context_lock.read();
            print!(
                "{} ({}/{:p}): ",
                context.name,
                context.pid.get(),
                context_lock,
            );
        }

        // Do format_call outside print! so possible exception handlers cannot reentrantly
        // deadlock.
        let string = format_call(a, b, c, d, e, f);
        println!("{}", string);

        crate::time::monotonic()
    } else {
        0
    };

    crate::percpu::PercpuBlock::current()
        .syscall_debug_info
        .set(SyscallDebugInfo {
            accumulated_time: 0,
            this_switch_time: debug_start,
            do_debug,
        });
}
#[cfg(feature = "syscall_debug")]
pub fn debug_end([a, b, c, d, e, f]: [usize; 6], result: Result<usize>) {
    let debug_info = crate::percpu::PercpuBlock::current()
        .syscall_debug_info
        .take();

    if !debug_info.do_debug {
        return;
    }
    let debug_duration =
        debug_info.accumulated_time + (crate::time::monotonic() - debug_info.this_switch_time);

    let context_lock = crate::context::current();
    {
        let context = context_lock.read();
        print!(
            "{} ({}/{:p}): ",
            context.name,
            context.pid.get(),
            context_lock,
        );
    }

    // Do format_call outside print! so possible exception handlers cannot reentrantly
    // deadlock.
    let string = format_call(a, b, c, d, e, f);
    print!("{} = ", string);

    match result {
        Ok(ref ok) => {
            print!("Ok({} ({:#X}))", ok, ok);
        }
        Err(ref err) => {
            print!("Err({} ({:#X}))", err, err.errno);
        }
    }

    println!(" in {} ns", debug_duration);
}
