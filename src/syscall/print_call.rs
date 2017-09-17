use core::ops::Range;
use super::data::{Stat, TimeSpec};
use super::error::Result;
pub use super::validate::*;
use collections::Vec;
use super::syscall;


// Coppied from std
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
        //syscall::SYS_LINK =>
        SYS_OPEN => print!("open({:?}, 0x{:x})",
                             ByteStr(validate_slice(b as *const u8, c)?),
                             d),
        SYS_CHMOD => print!("chmod({:?}, {})",
                              ByteStr(validate_slice(b as *const u8, c)?),
                              d),
        SYS_RMDIR => print!("rmdir({:?})",
                              ByteStr(validate_slice(b as *const u8, c)?)),
        SYS_UNLINK => print!("unlink({:?})",
                               ByteStr(validate_slice(b as *const u8, c)?)),
        SYS_CLOSE => print!("close({})", b),
        SYS_DUP => print!("dup({}, {:?})",
                            b,
                            ByteStr(validate_slice(c as *const u8, d)?)),
        SYS_DUP2 => print!("dup2({}, {}, {:?})",
                             b,
                             c,
                             ByteStr(validate_slice(d as *const u8, e)?)),
        // How to format second argument?
        SYS_READ => print!("read({}, {:?})",
                              b,
                              (c, d)),
        SYS_WRITE => print!("write({}, {:?})",
                              b,
                              (c, d)),
        SYS_LSEEK => print!("lseek({}, {}, {})", b, c as isize,
                            match d {
                                syscall::SEEK_SET => "SEEK_SET",
                                syscall::SEEK_CUR => "SEEK_CUR",
                                syscall::SEEK_END => "SEEK_END",
                                _ => "UNKNOWN"
                            }
                            ),
        SYS_FCNTL => print!("fcntl({}, {}, 0x{:x})", b,
                            match c {
                                syscall::F_DUPFD => "F_DUPFD",
                                syscall::F_GETFD => "F_GETFD",
                                syscall::F_SETFD => "F_SETFD",
                                syscall::F_SETFL => "F_SETFL",
                                syscall::F_GETFL => "F_GETFL",
                                _ => "UNKNOWN"
                            }
                            , d),
        SYS_FEVENT => print!("fevent({}, {})", b, c),
        SYS_FMAP => print!("fmap({}, {}, {})", b, c, d),
        SYS_FUNMAP => print!("funmap({})", b),
        // How to format second argument?
        SYS_FPATH => print!("fpath({}, ({}, {}))", b, c, d),
        // How to format second argument?
        SYS_FSTAT => print!("fstat({}, {:?}, {})", b,
                            validate_slice(c as *const Stat, 1).map(|st| &st[0])?, d),
        // How to format second argument?
        SYS_FSTATVFS => print!("fstatvfs({}, ({}, {}))", b, c, d),
        SYS_FSYNC => print!("fsync({})", b),
        SYS_FTRUNCATE => print!("ftruncate({}, {})", b, c),

        SYS_BRK => print!("brk({})", b),
        SYS_CHDIR => print!("chdir({:?})",
                              ByteStr(validate_slice(b as *const u8, c)?)),
        SYS_CLOCK_GETTIME => print!("clock_gettime({}, {:?})",
                                      b,
                                      validate_slice_mut(c as *mut TimeSpec, 1).map(|time| &mut time[0])?),
        SYS_CLONE => print!("clone({})", b),
        SYS_EXECVE => print!("execve({:?}, {:?})",
                               ByteStr(validate_slice(b as *const u8, c)?),
                               validate_slice(
                                   d as *const [usize; 2],
                                   e)?
                               .iter()
                               .map(|a|
                                   validate_slice(a[0] as *const u8, a[1]).ok()
                                   .and_then(|s| ::core::str::from_utf8(s).ok()))
                               .collect::<Vec<Option<&str>>>()),
        SYS_EXIT => print!("exit({})", b),
        SYS_FUTEX => print!("futex(0x{:x} [{}], {}, {}, {}, {})", b, validate_slice_mut(b as *mut i32, 1).map(|uaddr| &mut uaddr[0])?, c, d, e, f),
        // How to format argument?
        SYS_GETCWD => print!("getcwd({:?})", b),
        SYS_GETEGID => print!("getgid()"),
        SYS_GETENS => print!("getens()"),
        SYS_GETEUID => print!("geteuid()"),
        SYS_GETGID => print!("getgid()"),
        SYS_GETNS => print!("getns()"),
        SYS_GETPID => print!("getpid()"),
        SYS_GETUID => print!("getuid()"),
        SYS_IOPL => print!("iopl({})", b),
        SYS_KILL => print!("kill({}, {})", b, c),
        SYS_SIGRETURN => print!("sigreturn()"),
        SYS_SIGACTION => print!("sigaction({}, 0x{:x}, 0x{:x}, 0x{:x})", b, c, d, e),
        SYS_MKNS => print!("mkns({:?})",
                             validate_slice(b as *const [usize; 2], c)?),
        SYS_NANOSLEEP => print!("nanosleep({:?}, ({}, {}))",
                                   validate_slice(b as *const TimeSpec, 1),
                                   c,
                                   d),
        SYS_PHYSALLOC => print!("physalloc({})", b),
        SYS_PHYSFREE => print!("physfree({}, {})", b, c),
        SYS_PHYSMAP => print!("physmap({}, {}, {})", b, c, d),
        SYS_PHYSUNMAP => print!("physunmap({})", b),
        SYS_VIRTTOPHYS => print!("virttophys({})", b),
        SYS_PIPE2 => print!("pipe2({:?}, {})",
                              validate_slice_mut(b as *mut usize, 2)?,
                              c),
        SYS_SETREGID => print!("setregid({}, {})", b, c),
        SYS_SETRENS => print!("setrens({}, {})", b, c),
        SYS_SETREUID => print!("setreuid({}, {})", b, c),
        SYS_WAITPID => print!("waitpid({}, {}, {})", b, c, d),
        SYS_YIELD => print!("yield()"),
        _ => print!("INVALID CALL")
    }

    Ok(())
}
