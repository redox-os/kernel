use core::mem;
use core::ops::Range;
use alloc::string::String;
use alloc::vec::Vec;

use super::data::{Map, Stat, TimeSpec};
use super::flag::*;
use super::number::*;
use super::validate::*;

// Copied from std
pub struct EscapeDefault {
    range: Range<usize>,
    data: [u8; 4],
}

pub fn escape_default(c: u8) -> EscapeDefault {
    let (data, len) = match c {
        b'\t' => ([b'\\', b't', 0, 0], 2),
        b'\r' => ([b'\\', b'r', 0, 0], 2),
        b'\n' => ([b'\\', b'n', 0, 0], 2),
        b'\\' => ([b'\\', b'\\', 0, 0], 2),
        b'\'' => ([b'\\', b'\'', 0, 0], 2),
        b'"' => ([b'\\', b'"', 0, 0], 2),
        b'\x20' ... b'\x7e' => ([c, 0, 0, 0], 1),
        _ => ([b'\\', b'x', hexify(c >> 4), hexify(c & 0xf)], 4),
    };

    return EscapeDefault { range: (0.. len), data: data };

    fn hexify(b: u8) -> u8 {
        match b {
            0 ... 9 => b'0' + b,
            _ => b'a' + b - 10,
        }
    }
}

impl Iterator for EscapeDefault {
    type Item = u8;
    fn next(&mut self) -> Option<u8> { self.range.next().map(|i| self.data[i]) }
    fn size_hint(&self) -> (usize, Option<usize>) { self.range.size_hint() }
}

struct ByteStr<'a>(&'a[u8]);

impl<'a> ::core::fmt::Debug for ByteStr<'a> {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "\"")?;
        for i in self.0 {
            for ch in escape_default(*i) {
                write!(f, "{}", ch as char)?;
            }
        }
        write!(f, "\"")?;
        Ok(())
    }
}


pub fn format_call(a: usize, b: usize, c: usize, d: usize, e: usize, f: usize) -> String {
    match a {
        SYS_OPEN => format!(
            "open({:?}, {:#X})",
            validate_slice(b as *const u8, c).map(ByteStr),
            d
        ),
        SYS_CHMOD => format!(
            "chmod({:?}, {:#o})",
            validate_slice(b as *const u8, c).map(ByteStr),
            d
        ),
        SYS_RMDIR => format!(
            "rmdir({:?})",
            validate_slice(b as *const u8, c).map(ByteStr)
        ),
        SYS_UNLINK => format!(
            "unlink({:?})",
            validate_slice(b as *const u8, c).map(ByteStr)
        ),
        SYS_CLOSE => format!(
            "close({})", b
        ),
        SYS_DUP => format!(
            "dup({}, {:?})",
            b,
            validate_slice(c as *const u8, d).map(ByteStr)
        ),
        SYS_DUP2 => format!(
            "dup2({}, {}, {:?})",
            b,
            c,
            validate_slice(d as *const u8, e).map(ByteStr)
        ),
        SYS_READ => format!(
            "read({}, {:#X}, {})",
            b,
            c,
            d
        ),
        SYS_WRITE => format!(
            "write({}, {:#X}, {})",
            b,
            c,
            d
        ),
        SYS_LSEEK => format!(
            "lseek({}, {}, {} ({}))",
            b,
            c as isize,
            match d {
                SEEK_SET => "SEEK_SET",
                SEEK_CUR => "SEEK_CUR",
                SEEK_END => "SEEK_END",
                _ => "UNKNOWN"
            },
            d
        ),
        SYS_FCNTL => format!(
            "fcntl({}, {} ({}), {:#X})",
            b,
            match c {
                F_DUPFD => "F_DUPFD",
                F_GETFD => "F_GETFD",
                F_SETFD => "F_SETFD",
                F_SETFL => "F_SETFL",
                F_GETFL => "F_GETFL",
                _ => "UNKNOWN"
            },
            c,
            d
        ),
        SYS_FMAP => format!(
            "fmap({}, {:?})",
            b,
            validate_slice(
                c as *const Map,
                d/mem::size_of::<Map>()
            ),
        ),
        SYS_FUNMAP => format!(
            "funmap({:#X})",
            b
        ),
        SYS_FPATH => format!(
            "fpath({}, {:#X}, {})",
            b,
            c,
            d
        ),
        SYS_FSTAT => format!(
            "fstat({}, {:?})",
            b,
            validate_slice(
                c as *const Stat,
                d/mem::size_of::<Stat>()
            ),
        ),
        SYS_FSTATVFS => format!(
            "fstatvfs({}, {:#X}, {})",
            b,
            c,
            d
        ),
        SYS_FSYNC => format!(
            "fsync({})",
            b
        ),
        SYS_FTRUNCATE => format!(
            "ftruncate({}, {})",
            b,
            c
        ),

        SYS_BRK => format!(
            "brk({:#X})",
            b
        ),
        SYS_CHDIR => format!(
            "chdir({:?})",
            validate_slice(b as *const u8, c).map(ByteStr)
        ),
        SYS_CLOCK_GETTIME => format!(
            "clock_gettime({}, {:?})",
            b,
            validate_slice_mut(c as *mut TimeSpec, 1)
        ),
        SYS_CLONE => format!(
            "clone({})",
            b
        ),
        SYS_EXIT => format!(
            "exit({})",
            b
        ),
        //TODO: Cleanup, do not allocate
        SYS_FEXEC => format!(
            "fexec({}, {:?}, {:?})",
            b,
            validate_slice(
                c as *const [usize; 2],
                d
            ).map(|slice| {
                slice.iter().map(|a|
                    validate_slice(a[0] as *const u8, a[1]).ok()
                    .and_then(|s| ::core::str::from_utf8(s).ok())
                ).collect::<Vec<Option<&str>>>()
            }),
            validate_slice(
                e as *const [usize; 2],
                f
            ).map(|slice| {
                slice.iter().map(|a|
                    validate_slice(a[0] as *const u8, a[1]).ok()
                    .and_then(|s| ::core::str::from_utf8(s).ok())
                ).collect::<Vec<Option<&str>>>()
            })
        ),
        SYS_FUTEX => format!(
            "futex({:#X} [{:?}], {}, {}, {}, {})",
            b,
            validate_slice_mut(b as *mut i32, 1).map(|uaddr| &mut uaddr[0]),
            c,
            d,
            e,
            f
        ),
        SYS_GETCWD => format!(
            "getcwd({:#X}, {})",
            b,
            c
        ),
        SYS_GETEGID => format!("getegid()"),
        SYS_GETENS => format!("getens()"),
        SYS_GETEUID => format!("geteuid()"),
        SYS_GETGID => format!("getgid()"),
        SYS_GETNS => format!("getns()"),
        SYS_GETPID => format!("getpid()"),
        SYS_GETUID => format!("getuid()"),
        SYS_IOPL => format!(
            "iopl({})",
            b
        ),
        SYS_KILL => format!(
            "kill({}, {})",
            b,
            c
        ),
        SYS_SIGRETURN => format!("sigreturn()"),
        SYS_SIGACTION => format!(
            "sigaction({}, {:#X}, {:#X}, {:#X})",
            b,
            c,
            d,
            e
        ),
        SYS_SIGPROCMASK => format!(
            "sigprocmask({}, {:?}, {:?})",
            b,
            validate_slice(c as *const [u64; 2], 1),
            validate_slice(d as *const [u64; 2], 1)
        ),
        SYS_MKNS => format!(
            "mkns({:?})",
            validate_slice(b as *const [usize; 2], c)
        ),
        SYS_NANOSLEEP => format!(
            "nanosleep({:?}, ({}, {}))",
            validate_slice(b as *const TimeSpec, 1),
            c,
            d
        ),
        SYS_PHYSALLOC => format!(
            "physalloc({})",
            b
        ),
        SYS_PHYSFREE => format!(
            "physfree({:#X}, {})",
            b,
            c
        ),
        SYS_PHYSMAP => format!(
            "physmap({:#X}, {}, {:#X})",
            b,
            c,
            d
        ),
        SYS_PHYSUNMAP => format!(
            "physunmap({:#X})",
            b
        ),
        SYS_VIRTTOPHYS => format!(
            "virttophys({:#X})",
            b
        ),
        SYS_PIPE2 => format!(
            "pipe2({:?}, {})",
            validate_slice_mut(b as *mut usize, 2),
            c
        ),
        SYS_SETREGID => format!(
            "setregid({}, {})",
            b,
            c
        ),
        SYS_SETRENS => format!(
            "setrens({}, {})",
            b,
            c
        ),
        SYS_SETREUID => format!(
            "setreuid({}, {})",
            b,
            c
        ),
        SYS_UMASK => format!(
            "umask({:#o}",
            b
        ),
        SYS_WAITPID => format!(
            "waitpid({}, {:#X}, {})",
            b,
            c,
            d
        ),
        SYS_YIELD => format!("yield()"),
        _ => format!(
            "UNKNOWN{} {:#X}({:#X}, {:#X}, {:#X}, {:#X}, {:#X})",
            a, a,
            b,
            c,
            d,
            e,
            f
        )
    }
}
