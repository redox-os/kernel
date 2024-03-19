//!
//! This module provides syscall definitions and the necessary resources to parse incoming
//! syscalls

extern crate syscall;

pub use self::syscall::{
    data, error, flag, io, number, ptrace_event, EnvRegisters, FloatRegisters, IntRegisters,
};

pub use self::{
    driver::*, fs::*, futex::futex, privilege::*, process::*, time::*, usercopy::validate_region,
};

use self::{
    data::{Map, SigAction, TimeSpec},
    error::{Error, Result, EINTR, EOVERFLOW, ENOSYS},
    flag::{EventFlags, MapFlags, WaitFlags},
    number::*,
    usercopy::UserSlice,
};

use crate::interrupt::InterruptStack;
use crate::percpu::PercpuBlock;

use crate::{
    context::{memory::AddrSpace, ContextId},
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
pub fn syscall(
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    e: usize,
    f: usize,
    stack: &mut InterruptStack,
) {
    #[inline(always)]
    fn inner(
        a: usize,
        b: usize,
        c: usize,
        d: usize,
        e: usize,
        f: usize,
    ) -> Result<usize> {
        //SYS_* is declared in kernel/syscall/src/number.rs
        match a & SYS_CLASS {
            SYS_CLASS_FILE => {
                let fd = FileHandle::from(b);
                match a & SYS_ARG {
                    SYS_ARG_SLICE => match a {
                        SYS_WRITE => file_op_generic(fd, |scheme, number| {
                            scheme.kwrite(number, UserSlice::ro(c, d)?)
                        }),
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
                        // SYS_FMAP_OLD is ignored
                        SYS_FUTIMENS => file_op_generic(fd, |scheme, number| {
                            scheme.kfutimens(number, UserSlice::ro(c, d)?)
                        }),

                        _ => return Err(Error::new(ENOSYS)),
                    },
                    SYS_ARG_MSLICE => match a {
                        SYS_READ => file_op_generic(fd, |scheme, number| {
                            scheme.kread(number, UserSlice::wo(c, d)?)
                        }),
                        SYS_FPATH => file_op_generic(fd, |scheme, number| {
                            scheme.kfpath(number, UserSlice::wo(c, d)?)
                        }),
                        SYS_FSTAT => fstat(fd, UserSlice::wo(c, d)?).map(|()| 0),
                        SYS_FSTATVFS => file_op_generic(fd, |scheme, number| {
                            scheme.kfstatvfs(number, UserSlice::wo(c, d)?).map(|()| 0)
                        }),

                        _ => return Err(Error::new(ENOSYS)),
                    },
                    _ => match a {
                        SYS_DUP => dup(fd, UserSlice::ro(c, d)?).map(FileHandle::into),
                        SYS_DUP2 => dup2(fd, FileHandle::from(c), UserSlice::ro(d, e)?)
                            .map(FileHandle::into),

                        #[cfg(target_pointer_width = "32")]
                        SYS_SENDFD => {
                            sendfd(fd, FileHandle::from(c), d, e as u64 | ((f as u64) << 32))
                        }

                        #[cfg(target_pointer_width = "64")]
                        SYS_SENDFD => sendfd(fd, FileHandle::from(c), d, e as u64),

                        SYS_LSEEK => {
                            file_op_generic(fd, |scheme, number| scheme.seek(number, c as isize, d))
                        }
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

                        SYS_FSYNC => {
                            file_op_generic(fd, |scheme, number| scheme.fsync(number).map(|()| 0))
                        }
                        // TODO: 64-bit lengths on 32-bit platforms
                        SYS_FTRUNCATE => file_op_generic(fd, |scheme, number| {
                            scheme.ftruncate(number, c).map(|()| 0)
                        }),

                        SYS_CLOSE => close(fd).map(|()| 0),

                        _ => return Err(Error::new(ENOSYS)),
                    },
                }
            }
            SYS_CLASS_PATH => match a {
                SYS_OPEN => open(UserSlice::ro(b, c)?, d).map(FileHandle::into),
                SYS_RMDIR => rmdir(UserSlice::ro(b, c)?).map(|()| 0),
                SYS_UNLINK => unlink(UserSlice::ro(b, c)?).map(|()| 0),
                _ => Err(Error::new(ENOSYS)),
            },
            _ => match a {
                SYS_YIELD => sched_yield().map(|()| 0),
                SYS_NANOSLEEP => nanosleep(
                    UserSlice::ro(b, core::mem::size_of::<TimeSpec>())?,
                    UserSlice::wo(c, core::mem::size_of::<TimeSpec>())?.none_if_null(),
                )
                .map(|()| 0),
                SYS_CLOCK_GETTIME => {
                    clock_gettime(b, UserSlice::wo(c, core::mem::size_of::<TimeSpec>())?)
                        .map(|()| 0)
                }
                SYS_FUTEX => futex(b, c, d, e, f),
                SYS_GETPID => getpid().map(ContextId::into),
                SYS_GETPGID => getpgid(ContextId::from(b)).map(ContextId::into),
                SYS_GETPPID => getppid().map(ContextId::into),

                SYS_EXIT => exit((b & 0xFF) << 8),
                SYS_KILL => kill(ContextId::from(b), c),
                SYS_WAITPID => waitpid(
                    ContextId::from(b),
                    if c == 0 {
                        None
                    } else {
                        Some(UserSlice::wo(c, core::mem::size_of::<usize>())?)
                    },
                    WaitFlags::from_bits_truncate(d),
                )
                .map(ContextId::into),
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
                SYS_SETPGID => setpgid(ContextId::from(b), ContextId::from(c)),
                SYS_SETREUID => setreuid(b as u32, c as u32),
                SYS_SETRENS => setrens(SchemeNamespace::from(b), SchemeNamespace::from(c)),
                SYS_SETREGID => setregid(b as u32, c as u32),
                SYS_SIGACTION => sigaction(
                    b,
                    UserSlice::ro(c, core::mem::size_of::<SigAction>())?.none_if_null(),
                    UserSlice::wo(d, core::mem::size_of::<SigAction>())?.none_if_null(),
                    e,
                )
                .map(|()| 0),
                SYS_SIGPROCMASK => sigprocmask(
                    b,
                    UserSlice::ro(c, 8)?.none_if_null(),
                    UserSlice::wo(d, 8)?.none_if_null(),
                ).map(|()| 0),
                SYS_SIGRETURN => sigreturn().map(|()| 0),
                SYS_UMASK => umask(b),
                SYS_VIRTTOPHYS => virttophys(b),

                SYS_MREMAP => mremap(b, c, d, e, f),

                _ => Err(Error::new(ENOSYS)),
            },
        }
    }

    PercpuBlock::current().inside_syscall.set(true);

    #[cfg(feature = "syscall_debug")]
    debug_start([a, b, c, d, e, f]);

    let result = inner(a, b, c, d, e, f);

    #[cfg(feature = "syscall_debug")]
    debug_end([a, b, c, d, e, f], result);

    PercpuBlock::current().inside_syscall.set(false);

    if a != SYS_SIGRETURN {
        // errormux turns Result<usize> into -errno
        stack.set_syscall_ret_reg(Error::mux(result));

        if result == Err(Error::new(EINTR)) {
            // Although it would be cleaner to simply run the signal trampoline right after switching
            // back to any given context, where the signal set/queue is nonempty, syscalls need to
            // complete *before* any signal is delivered. Otherwise the return value would probably be
            // overwritten.
            crate::context::signal::signal_handler();
        }
    }
}
