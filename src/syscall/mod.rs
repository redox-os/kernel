//!
//! This module provides syscall definitions and the necessary resources to parse incoming
//! syscalls

extern crate syscall;

use core::mem::size_of;

use syscall::{dirent::DirentHeader, CallFlags, RwFlags, EINVAL};

pub use self::syscall::{
    data, error, flag, io, number, ptrace_event, EnvRegisters, FloatRegisters, IntRegisters,
};

pub use self::{fs::*, futex::futex, privilege::*, process::*, time::*, usercopy::validate_region};

use self::{
    data::{Map, TimeSpec},
    debug::{debug_end, debug_start},
    error::{Error, Result, ENOSYS, EOVERFLOW},
    flag::{EventFlags, MapFlags},
    number::*,
    usercopy::UserSlice,
};

use crate::{
    context::memory::AddrSpace,
    percpu::PercpuBlock,
    scheme::{memory::MemoryScheme, FileHandle},
    sync::CleanLockToken,
};

/// Debug
pub mod debug;

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
pub fn syscall(
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    e: usize,
    f: usize,
    g: usize,
    token: &mut CleanLockToken,
) -> usize {
    #[inline(always)]
    fn inner(
        a: usize,
        b: usize,
        c: usize,
        d: usize,
        e: usize,
        f: usize,
        g: usize,
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        let fd = FileHandle::from(b);
        //SYS_* is declared in kernel/syscall/src/number.rs
        match a {
            SYS_WRITE2 => file_op_generic_ext(fd, token, |scheme, _, desc, token| {
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
                    token,
                )
            }),
            SYS_WRITE => sys_write(fd, UserSlice::ro(c, d)?, token),
            SYS_FMAP => {
                let addrspace = AddrSpace::current()?;
                let map = unsafe { UserSlice::ro(c, d)?.read_exact::<Map>()? };
                if b == !0 {
                    MemoryScheme::fmap_anonymous(&addrspace, &map, false, token)
                } else {
                    file_op_generic(fd, token, |scheme, number, token| {
                        scheme.kfmap(number, &addrspace, &map, false, token)
                    })
                }
            }
            SYS_GETDENTS => {
                let header_size = u16::try_from(e).map_err(|_| Error::new(EINVAL))?;

                if usize::from(header_size) != size_of::<DirentHeader>() {
                    // TODO: allow? If so, zero_out must be implemented for UserSlice
                    return Err(Error::new(EINVAL));
                }

                file_op_generic(fd, token, |scheme, number, token| {
                    scheme.getdents(number, UserSlice::wo(c, d)?, header_size, f as u64, token)
                })
            }
            SYS_FUTIMENS => file_op_generic(fd, token, |scheme, number, token| {
                scheme.kfutimens(number, UserSlice::ro(c, d)?, token)
            }),

            SYS_READ2 => file_op_generic_ext(fd, token, |scheme, _, desc, token| {
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
                    token,
                )
            }),
            SYS_READ => sys_read(fd, UserSlice::wo(c, d)?, token),
            SYS_FPATH => file_op_generic(fd, token, |scheme, number, token| {
                scheme.kfpath(number, UserSlice::wo(c, d)?, token)
            }),
            SYS_FSTAT => fstat(fd, UserSlice::wo(c, d)?, token).map(|()| 0),
            SYS_FSTATVFS => file_op_generic(fd, token, |scheme, number, token| {
                scheme
                    .kfstatvfs(number, UserSlice::wo(c, d)?, token)
                    .map(|()| 0)
            }),

            SYS_DUP => dup(fd, UserSlice::ro(c, d)?, token).map(FileHandle::into),
            SYS_DUP2 => {
                dup2(fd, FileHandle::from(c), UserSlice::ro(d, e)?, token).map(FileHandle::into)
            }

            #[cfg(target_pointer_width = "32")]
            SYS_SENDFD => sendfd(
                fd,
                FileHandle::from(c),
                d,
                e as u64 | ((f as u64) << 32),
                token,
            ),

            #[cfg(target_pointer_width = "64")]
            SYS_SENDFD => sendfd(fd, FileHandle::from(c), d, e as u64, token),

            SYS_LSEEK => lseek(fd, c as i64, d, token),
            SYS_FCHMOD => file_op_generic(fd, token, |scheme, number, token| {
                scheme.fchmod(number, c as u16, token).map(|()| 0)
            }),
            SYS_FCHOWN => file_op_generic(fd, token, |scheme, number, token| {
                scheme.fchown(number, c as u32, d as u32, token).map(|()| 0)
            }),
            SYS_FCNTL => fcntl(fd, c, d, token),
            SYS_FEVENT => file_op_generic(fd, token, |scheme, number, token| {
                Ok(scheme
                    .fevent(number, EventFlags::from_bits_truncate(c), token)?
                    .bits())
            }),
            SYS_FLINK => flink(fd, UserSlice::ro(c, d)?, token).map(|()| 0),
            SYS_FRENAME => frename(fd, UserSlice::ro(c, d)?, token).map(|()| 0),
            SYS_FUNMAP => funmap(b, c, token),

            SYS_FSYNC => file_op_generic(fd, token, |scheme, number, token| {
                scheme.fsync(number, token).map(|()| 0)
            }),
            // TODO: 64-bit lengths on 32-bit platforms
            SYS_FTRUNCATE => file_op_generic(fd, token, |scheme, number, token| {
                scheme.ftruncate(number, c, token).map(|()| 0)
            }),

            SYS_CLOSE => close(fd, token).map(|()| 0),
            SYS_CALL => call(
                fd,
                UserSlice::rw(c, d)?,
                CallFlags::from_bits(e & !0xff).ok_or(Error::new(EINVAL))?,
                UserSlice::ro(f, (e & 0xff) * 8)?,
                token,
            ),
            SYS_OPEN => open(UserSlice::ro(b, c)?, d, token).map(FileHandle::into),
            SYS_OPENAT => {
                openat(fd, UserSlice::ro(c, d)?, e, f as _, 0, 0, token).map(FileHandle::into)
            }
            SYS_OPENAT_WITH_FILTER => openat(
                fd,
                UserSlice::ro(c, d)?,
                e,
                (e & syscall::O_FCNTL_MASK) as _,
                f as _,
                g as _,
                token,
            )
            .map(FileHandle::into),
            SYS_UNLINKAT => unlinkat(fd, UserSlice::ro(c, d)?, e, 0, 0, token).map(|()| 0),
            SYS_UNLINKAT_WITH_FILTER => {
                unlinkat(fd, UserSlice::ro(c, d)?, e, f as _, g as _, token).map(|()| 0)
            }
            SYS_YIELD => sched_yield(token).map(|()| 0),
            SYS_NANOSLEEP => nanosleep(
                UserSlice::ro(b, core::mem::size_of::<TimeSpec>())?,
                UserSlice::wo(c, core::mem::size_of::<TimeSpec>())?.none_if_null(),
                token,
            )
            .map(|()| 0),
            SYS_CLOCK_GETTIME => {
                clock_gettime(b, UserSlice::wo(c, core::mem::size_of::<TimeSpec>())?).map(|()| 0)
            }
            SYS_FUTEX => futex(b, c, d, e, f, token),

            SYS_MPROTECT => mprotect(b, c, MapFlags::from_bits_truncate(d)).map(|()| 0),
            SYS_MKNS => mkns(
                UserSlice::ro(
                    b,
                    c.checked_mul(core::mem::size_of::<[usize; 2]>())
                        .ok_or(Error::new(EOVERFLOW))?,
                )?,
                token,
            ),
            SYS_MREMAP => mremap(b, c, d, e, f, token),

            _ => Err(Error::new(ENOSYS)),
        }
    }

    PercpuBlock::current().inside_syscall.set(true);

    debug_start([a, b, c, d, e, f, g], token);

    let result = inner(a, b, c, d, e, f, g, token);

    debug_end([a, b, c, d, e, f, g], result, token);

    let percpu = PercpuBlock::current();
    percpu.inside_syscall.set(false);

    if percpu.switch_internals.being_sigkilled.get() {
        exit_this_context(None, token);
    }

    // errormux turns Result<usize> into -errno
    Error::mux(result)
}
