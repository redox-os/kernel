//!
//! This module provides syscall definitions and the necessary resources to parse incoming
//! syscalls

extern crate syscall;

use core::mem::size_of;

use syscall::{dirent::DirentHeader, RtSigInfo, RwFlags, EINVAL, SIGKILL};

pub use self::syscall::{
    data, error, flag, io, number, ptrace_event, EnvRegisters, FloatRegisters, IntRegisters,
};

pub use self::{
    driver::*, fs::*, futex::futex, privilege::*, process::*, time::*, usercopy::validate_region,
};

use self::{
    data::{Map, TimeSpec},
    error::{Error, Result, ENOSYS, EOVERFLOW},
    flag::{EventFlags, MapFlags, WaitFlags},
    number::*,
    usercopy::UserSlice,
};

use crate::percpu::PercpuBlock;

use crate::{
    context::{memory::AddrSpace, process::ProcessId},
    scheme::{memory::MemoryScheme, FileHandle, SchemeNamespace},
};

/// Debug
pub mod debug;

#[cfg(feature = "syscall_debug")]
use self::debug::{debug_end, debug_start};

/// Driver syscalls
pub mod driver;

/// Filesystem syscalls
pub mod fs;

/// Fast userspace mutex
pub mod futex;

/// Privilege syscalls
pub mod privilege;

/// Process syscalls
pub mod process;

/// Time syscalls
pub mod time;

/// Safely copying memory between user and kernel memory
pub mod usercopy;

/// This function is the syscall handler of the kernel, it is composed of an inner function that returns a `Result<usize>`. After the inner function runs, the syscall
/// function calls [`Error::mux`] on it.
#[must_use]
pub fn syscall(a: usize, b: usize, c: usize, d: usize, e: usize, f: usize) -> usize {
    #[inline(always)]
    fn inner(a: usize, b: usize, c: usize, d: usize, e: usize, f: usize) -> Result<usize> {
        let fd = FileHandle::from(b);
        //SYS_* is declared in kernel/syscall/src/number.rs
        match a {
            SYS_WRITE2 => file_op_generic_ext(fd, |scheme, _, desc| {
                let flags = if f == usize::MAX {
                    None
                } else {
                    Some(
                        u32::try_from(f)
                            .ok()
                            .and_then(RwFlags::from_bits)
                            .ok_or(Error::new(EINVAL))?,
                    )
                };
                scheme.kwriteoff(
                    desc.number,
                    UserSlice::ro(c, d)?,
                    e as u64,
                    flags.map_or(desc.flags, |f| desc.rw_flags(f)),
                    desc.flags,
                )
            }),
            SYS_WRITE => sys_write(fd, UserSlice::ro(c, d)?),
            SYS_FMAP => {
                let addrspace = AddrSpace::current()?;
                let map = unsafe { UserSlice::ro(c, d)?.read_exact::<Map>()? };
                if b == !0 {
                    MemoryScheme::fmap_anonymous(&addrspace, &map, false)
                } else {
                    file_op_generic(fd, |scheme, number| {
                        scheme.kfmap(number, &addrspace, &map, false)
                    })
                }
            }
            SYS_GETDENTS => {
                let header_size = u16::try_from(e).map_err(|_| Error::new(EINVAL))?;

                if usize::from(header_size) != size_of::<DirentHeader>() {
                    // TODO: allow? If so, zero_out must be implemented for UserSlice
                    return Err(Error::new(EINVAL));
                }

                file_op_generic(fd, |scheme, number| {
                    scheme.getdents(number, UserSlice::wo(c, d)?, header_size, f as u64)
                })
            }
            SYS_FUTIMENS => file_op_generic(fd, |scheme, number| {
                scheme.kfutimens(number, UserSlice::ro(c, d)?)
            }),

            SYS_READ2 => file_op_generic_ext(fd, |scheme, _, desc| {
                let flags = if f == usize::MAX {
                    None
                } else {
                    Some(
                        u32::try_from(f)
                            .ok()
                            .and_then(RwFlags::from_bits)
                            .ok_or(Error::new(EINVAL))?,
                    )
                };
                scheme.kreadoff(
                    desc.number,
                    UserSlice::wo(c, d)?,
                    e as u64,
                    flags.map_or(desc.flags, |f| desc.rw_flags(f)),
                    desc.flags,
                )
            }),
            SYS_READ => sys_read(fd, UserSlice::wo(c, d)?),
            SYS_FPATH => file_op_generic(fd, |scheme, number| {
                scheme.kfpath(number, UserSlice::wo(c, d)?)
            }),
            SYS_FSTAT => fstat(fd, UserSlice::wo(c, d)?).map(|()| 0),
            SYS_FSTATVFS => file_op_generic(fd, |scheme, number| {
                scheme.kfstatvfs(number, UserSlice::wo(c, d)?).map(|()| 0)
            }),

            SYS_DUP => dup(fd, UserSlice::ro(c, d)?).map(FileHandle::into),
            SYS_DUP2 => dup2(fd, FileHandle::from(c), UserSlice::ro(d, e)?).map(FileHandle::into),

            #[cfg(target_pointer_width = "32")]
            SYS_SENDFD => sendfd(fd, FileHandle::from(c), d, e as u64 | ((f as u64) << 32)),

            #[cfg(target_pointer_width = "64")]
            SYS_SENDFD => sendfd(fd, FileHandle::from(c), d, e as u64),

            SYS_LSEEK => lseek(fd, c as i64, d),
            SYS_FCHMOD => file_op_generic(fd, |scheme, number| {
                scheme.fchmod(number, c as u16).map(|()| 0)
            }),
            SYS_FCHOWN => file_op_generic(fd, |scheme, number| {
                scheme.fchown(number, c as u32, d as u32).map(|()| 0)
            }),
            SYS_FCNTL => fcntl(fd, c, d),
            SYS_FEVENT => file_op_generic(fd, |scheme, number| {
                Ok(scheme
                    .fevent(number, EventFlags::from_bits_truncate(c))?
                    .bits())
            }),
            SYS_FRENAME => frename(fd, UserSlice::ro(c, d)?).map(|()| 0),
            SYS_FUNMAP => funmap(b, c),

            SYS_FSYNC => file_op_generic(fd, |scheme, number| scheme.fsync(number).map(|()| 0)),
            // TODO: 64-bit lengths on 32-bit platforms
            SYS_FTRUNCATE => {
                file_op_generic(fd, |scheme, number| scheme.ftruncate(number, c).map(|()| 0))
            }

            SYS_CLOSE => close(fd).map(|()| 0),

            SYS_OPEN => open(UserSlice::ro(b, c)?, d).map(FileHandle::into),
            SYS_RMDIR => rmdir(UserSlice::ro(b, c)?).map(|()| 0),
            SYS_UNLINK => unlink(UserSlice::ro(b, c)?).map(|()| 0),
            SYS_YIELD => sched_yield().map(|()| 0),
            SYS_NANOSLEEP => nanosleep(
                UserSlice::ro(b, core::mem::size_of::<TimeSpec>())?,
                UserSlice::wo(c, core::mem::size_of::<TimeSpec>())?.none_if_null(),
            )
            .map(|()| 0),
            SYS_CLOCK_GETTIME => {
                clock_gettime(b, UserSlice::wo(c, core::mem::size_of::<TimeSpec>())?).map(|()| 0)
            }
            SYS_FUTEX => futex(b, c, d, e, f),
            SYS_GETPID => getpid().map(ProcessId::into),
            SYS_GETPGID => getpgid(ProcessId::from(b)).map(ProcessId::into),
            SYS_GETPPID => getppid().map(ProcessId::into),

            SYS_EXIT => exit(b),
            SYS_KILL => kill(ProcessId::from(b), c, KillMode::Idempotent),
            SYS_SIGENQUEUE => kill(
                ProcessId::from(b),
                c,
                KillMode::Queued(unsafe {
                    UserSlice::ro(d, size_of::<RtSigInfo>())?.read_exact()?
                }),
            ),
            SYS_SIGDEQUEUE => {
                sigdequeue(UserSlice::wo(b, size_of::<RtSigInfo>())?, c as u32).map(|()| 0)
            }
            SYS_WAITPID => waitpid(
                ProcessId::from(b),
                if c == 0 {
                    None
                } else {
                    Some(UserSlice::wo(c, core::mem::size_of::<usize>())?)
                },
                WaitFlags::from_bits_truncate(d),
            )
            .map(ProcessId::into),
            SYS_IOPL => iopl(b),
            SYS_GETEGID => getegid(),
            SYS_GETENS => getens(),
            SYS_GETEUID => geteuid(),
            SYS_GETGID => getgid(),
            SYS_GETNS => getns(),
            SYS_GETUID => getuid(),
            SYS_MPROTECT => mprotect(b, c, MapFlags::from_bits_truncate(d)).map(|()| 0),
            SYS_MKNS => mkns(UserSlice::ro(
                b,
                c.checked_mul(core::mem::size_of::<[usize; 2]>())
                    .ok_or(Error::new(EOVERFLOW))?,
            )?),
            SYS_SETPGID => setpgid(ProcessId::from(b), ProcessId::from(c)).map(|()| 0),
            SYS_SETREUID => setreuid(b as u32, c as u32).map(|()| 0),
            SYS_SETRENS => setrens(SchemeNamespace::from(b), SchemeNamespace::from(c)).map(|()| 0),
            SYS_SETREGID => setregid(b as u32, c as u32).map(|()| 0),
            SYS_VIRTTOPHYS => virttophys(b),

            SYS_MREMAP => mremap(b, c, d, e, f),

            _ => return Err(Error::new(ENOSYS)),
        }
    }

    PercpuBlock::current().inside_syscall.set(true);

    #[cfg(feature = "syscall_debug")]
    debug_start([a, b, c, d, e, f]);

    let result = inner(a, b, c, d, e, f);

    #[cfg(feature = "syscall_debug")]
    debug_end([a, b, c, d, e, f], result);

    let percpu = PercpuBlock::current();
    percpu.inside_syscall.set(false);

    if percpu.switch_internals.being_sigkilled.get() {
        exit(SIGKILL);
    }

    // errormux turns Result<usize> into -errno
    Error::mux(result)
}
