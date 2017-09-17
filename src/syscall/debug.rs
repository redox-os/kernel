use core::mem;
use core::ops::Range;
use collections::Vec;

use super::data::{Stat, TimeSpec};
use super::error::Result;
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


pub fn print_call(a: usize, b: usize, c: usize, d: usize, e: usize, f: usize) -> Result<()> {
    match a {
        SYS_OPEN => print!(
            "open({:?}, {:#X})",
            validate_slice(b as *const u8, c).map(ByteStr),
            d
        ),
        SYS_CHMOD => print!(
            "chmod({:?}, {:#o})",
            validate_slice(b as *const u8, c).map(ByteStr),
            d
        ),
        SYS_RMDIR => print!(
            "rmdir({:?})",
            validate_slice(b as *const u8, c).map(ByteStr)
        ),
        SYS_UNLINK => print!(
            "unlink({:?})",
            validate_slice(b as *const u8, c).map(ByteStr)
        ),
        SYS_CLOSE => print!(
            "close({})", b
        ),
        SYS_DUP => print!(
            "dup({}, {:?})",
            b,
            validate_slice(c as *const u8, d).map(ByteStr)
        ),
        SYS_DUP2 => print!(
            "dup2({}, {}, {:?})",
            b,
            c,
            validate_slice(d as *const u8, e).map(ByteStr)
        ),
        SYS_READ => print!(
            "read({}, {:#X}, {})",
            b,
            c,
            d
        ),
        SYS_WRITE => print!(
            "write({}, {:#X}, {})",
            b,
            c,
            d
        ),
        SYS_LSEEK => print!(
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
        SYS_FCNTL => print!(
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
        SYS_FEVENT => print!(
            "fevent({}, {:#X})",
            b,
            c
        ),
        SYS_FMAP => print!(
            "fmap({}, {:#X}, {})",
            b,
            c,
            d
        ),
        SYS_FUNMAP => print!(
            "funmap({:#X})",
            b
        ),
        SYS_FPATH => print!(
            "fpath({}, {:#X}, {})",
            b,
            c,
            d
        ),
        SYS_FSTAT => print!(
            "fstat({}, {:?})",
            b,
            validate_slice(
                c as *const Stat,
                d/mem::size_of::<Stat>()
            ),
        ),
        SYS_FSTATVFS => print!(
            "fstatvfs({}, {:#X}, {})",
            b,
            c,
            d
        ),
        SYS_FSYNC => print!(
            "fsync({})",
            b
        ),
        SYS_FTRUNCATE => print!(
            "ftruncate({}, {})",
            b,
            c
        ),

        SYS_BRK => print!(
            "brk({:#X})",
            b
        ),
        SYS_CHDIR => print!(
            "chdir({:?})",
            validate_slice(b as *const u8, c).map(ByteStr)
        ),
        SYS_CLOCK_GETTIME => print!(
            "clock_gettime({}, {:?})",
            b,
            validate_slice_mut(c as *mut TimeSpec, 1)
        ),
        SYS_CLONE => print!(
            "clone({})",
            b
        ),
        //TODO: Cleanup, do not allocate
        SYS_EXECVE => print!(
            "execve({:?}, {:?})",
            validate_slice(b as *const u8, c).map(ByteStr),
            validate_slice(
                d as *const [usize; 2],
                e
            )?
            .iter()
            .map(|a|
                validate_slice(a[0] as *const u8, a[1]).ok()
                .and_then(|s| ::core::str::from_utf8(s).ok())
            ).collect::<Vec<Option<&str>>>()
        ),
        SYS_EXIT => print!(
            "exit({})",
            b
        ),
        SYS_FUTEX => print!(
            "futex({:#X} [{:?}], {}, {}, {}, {})",
            b,
            validate_slice_mut(b as *mut i32, 1).map(|uaddr| &mut uaddr[0]),
            c,
            d,
            e,
            f
        ),
        SYS_GETCWD => print!(
            "getcwd({:#X}, {})",
            b,
            c
        ),
        SYS_GETEGID => print!("getgid()"),
        SYS_GETENS => print!("getens()"),
        SYS_GETEUID => print!("geteuid()"),
        SYS_GETGID => print!("getgid()"),
        SYS_GETNS => print!("getns()"),
        SYS_GETPID => print!("getpid()"),
        SYS_GETUID => print!("getuid()"),
        SYS_IOPL => print!(
            "iopl({})",
            b
        ),
        SYS_KILL => print!(
            "kill({}, {})",
            b,
            c
        ),
        SYS_SIGRETURN => print!("sigreturn()"),
        SYS_SIGACTION => print!(
            "sigaction({}, {:#X}, {:#X}, {:#X})",
            b,
            c,
            d,
            e
        ),
        SYS_MKNS => print!(
            "mkns({:?})",
            validate_slice(b as *const [usize; 2], c)
        ),
        SYS_NANOSLEEP => print!(
            "nanosleep({:?}, ({}, {}))",
            validate_slice(b as *const TimeSpec, 1),
            c,
            d
        ),
        SYS_PHYSALLOC => print!(
            "physalloc({})",
            b
        ),
        SYS_PHYSFREE => print!(
            "physfree({:#X}, {})",
            b,
            c
        ),
        SYS_PHYSMAP => print!(
            "physmap({:#X}, {}, {:#X})",
            b,
            c,
            d
        ),
        SYS_PHYSUNMAP => print!(
            "physunmap({:#X})",
            b
        ),
        SYS_VIRTTOPHYS => print!(
            "virttophys({:#X})",
            b
        ),
        SYS_PIPE2 => print!(
            "pipe2({:?}, {})",
            validate_slice_mut(b as *mut usize, 2),
            c
        ),
        SYS_SETREGID => print!(
            "setregid({}, {})",
            b,
            c
        ),
        SYS_SETRENS => print!(
            "setrens({}, {})",
            b,
            c
        ),
        SYS_SETREUID => print!(
            "setreuid({}, {})",
            b,
            c
        ),
        SYS_WAITPID => print!(
            "waitpid({}, {}, {})",
            b,
            c,
            d
        ),
        SYS_YIELD => print!("yield()"),
        _ => print!(
            "UNKNOWN{} {:#X}({:#X}, {:#X}, {:#X}, {:#X}, {:#X})",
            a, a,
            b,
            c,
            d,
            e,
            f
        )
    }

    Ok(())
}
