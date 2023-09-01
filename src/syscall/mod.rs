//!
//! This module provides syscall definitions and the necessary resources to parse incoming
//! syscalls

extern crate syscall;

use syscall::{EventFlags, EOVERFLOW};

pub use self::syscall::{
    FloatRegisters,
    IntRegisters,
    EnvRegisters,
    data,
    error,
    flag,
    io,
    number,
    ptrace_event,
};

pub use self::driver::*;
pub use self::fs::*;
pub use self::futex::futex;
pub use self::privilege::*;
pub use self::process::*;
pub use self::time::*;
pub use self::usercopy::validate_region;

use self::data::{Map, SigAction, TimeSpec};
use self::error::{Error, Result, ENOSYS};
use self::flag::{MapFlags, PhysmapFlags, WaitFlags};
use self::number::*;

use crate::context::ContextId;
use crate::context::memory::AddrSpace;
use crate::interrupt::InterruptStack;
use crate::scheme::{FileHandle, SchemeNamespace, memory::MemoryScheme};
use crate::syscall::usercopy::UserSlice;

/// Debug
pub mod debug;

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
pub fn syscall(a: usize, b: usize, c: usize, d: usize, e: usize, f: usize, stack: &mut InterruptStack) -> usize {
    #[inline(always)]
    fn inner(a: usize, b: usize, c: usize, d: usize, e: usize, f: usize, stack: &mut InterruptStack) -> Result<usize> {
        //SYS_* is declared in kernel/syscall/src/number.rs
        match a & SYS_CLASS {
            SYS_CLASS_FILE => {
                let fd = FileHandle::from(b);
                match a & SYS_ARG {
                    SYS_ARG_SLICE => match a {
                        SYS_WRITE => file_op_generic(fd, |scheme, _, number| scheme.kwrite(number, UserSlice::ro(c, d)?)),
                        SYS_FMAP => {
                            let addrspace = AddrSpace::current()?;
                            let map = unsafe { UserSlice::ro(c, d)?.read_exact::<Map>()? };
                            if b == !0 {
                                MemoryScheme::fmap_anonymous(&addrspace, &map, false)
                            } else {
                                file_op_generic(fd, |scheme, _, number| scheme.kfmap(number, &addrspace, &map, false))
                            }
                        },
                        // SYS_FMAP_OLD is ignored
                        SYS_FUTIMENS => file_op_generic(fd, |scheme, _, number| scheme.kfutimens(number, UserSlice::ro(c, d)?)),

                        _ => return Err(Error::new(ENOSYS)),
                    }
                    SYS_ARG_MSLICE => match a {
                        SYS_READ => file_op_generic(fd, |scheme, _, number| scheme.kread(number, UserSlice::wo(c, d)?)),
                        SYS_FPATH => file_op_generic(fd, |scheme, _, number| scheme.kfpath(number, UserSlice::wo(c, d)?)),
                        SYS_FSTAT => fstat(fd, UserSlice::wo(c, d)?).map(|()| 0),
                        SYS_FSTATVFS => file_op_generic(fd, |scheme, _, number| scheme.kfstatvfs(number, UserSlice::wo(c, d)?).map(|()| 0)),

                        _ => return Err(Error::new(ENOSYS)),
                    },
                    _ => match a {
                        SYS_DUP => dup(fd, UserSlice::ro(c, d)?).map(FileHandle::into),
                        SYS_DUP2 => dup2(fd, FileHandle::from(c), UserSlice::ro(d, e)?).map(FileHandle::into),

                        #[cfg(target_pointer_width = "32")]
                        SYS_SENDFD => sendfd(fd, FileHandle::from(c), d, e as u64 | ((f as u64) << 32)),

                        #[cfg(target_pointer_width = "64")]
                        SYS_SENDFD => sendfd(fd, FileHandle::from(c), d, e as u64),

                        SYS_LSEEK => file_op_generic(fd, |scheme, _, number| scheme.seek(number, c as isize, d)),
                        SYS_FCHMOD => file_op_generic(fd, |scheme, _, number| scheme.fchmod(number, c as u16).map(|()| 0)),
                        SYS_FCHOWN => file_op_generic(fd, |scheme, _, number| scheme.fchown(number, c as u32, d as u32).map(|()| 0)),
                        SYS_FCNTL => fcntl(fd, c, d),
                        SYS_FEVENT => file_op_generic(fd, |scheme, _, number| Ok(scheme.fevent(number, EventFlags::from_bits_truncate(c))?.bits())),
                        SYS_FRENAME => frename(fd, UserSlice::ro(c, d)?).map(|()| 0),
                        SYS_FUNMAP => funmap(b, c),

                        SYS_FSYNC => file_op_generic(fd, |scheme, _, number| scheme.fsync(number).map(|()| 0)),
                        // TODO: 64-bit lengths on 32-bit platforms
                        SYS_FTRUNCATE => file_op_generic(fd, |scheme, _, number| scheme.ftruncate(number, c).map(|()| 0)),

                        SYS_CLOSE => close(fd).map(|()| 0),

                        _ => return Err(Error::new(ENOSYS)),
                    }
                }
            },
            SYS_CLASS_PATH => match a {
                SYS_OPEN => open(UserSlice::ro(b, c)?, d).map(FileHandle::into),
                SYS_RMDIR => rmdir(UserSlice::ro(b, c)?).map(|()| 0),
                SYS_UNLINK => unlink(UserSlice::ro(b, c)?).map(|()| 0),
                _ => Err(Error::new(ENOSYS))
            },
            _ => match a {
                SYS_YIELD => sched_yield().map(|()| 0),
                SYS_NANOSLEEP => nanosleep(
                    UserSlice::ro(b, core::mem::size_of::<TimeSpec>())?,
                    UserSlice::wo(c, core::mem::size_of::<TimeSpec>())?.none_if_null(),
                ).map(|()| 0),
                SYS_CLOCK_GETTIME => clock_gettime(b, UserSlice::wo(c, core::mem::size_of::<TimeSpec>())?).map(|()| 0),
                SYS_FUTEX => futex(b, c, d, e, f),
                SYS_GETPID => getpid().map(ContextId::into),
                SYS_GETPGID => getpgid(ContextId::from(b)).map(ContextId::into),
                SYS_GETPPID => getppid().map(ContextId::into),

                SYS_EXIT => exit((b & 0xFF) << 8),
                SYS_KILL => kill(ContextId::from(b), c),
                SYS_WAITPID => waitpid(ContextId::from(b), if c == 0 { None } else { Some(UserSlice::wo(c, core::mem::size_of::<usize>())?) }, WaitFlags::from_bits_truncate(d)).map(ContextId::into),
                SYS_IOPL => iopl(b, stack),
                SYS_GETEGID => getegid(),
                SYS_GETENS => getens(),
                SYS_GETEUID => geteuid(),
                SYS_GETGID => getgid(),
                SYS_GETNS => getns(),
                SYS_GETUID => getuid(),
                SYS_MPROTECT => mprotect(b, c, MapFlags::from_bits_truncate(d)),
                SYS_MKNS => mkns(UserSlice::ro(b, c.checked_mul(core::mem::size_of::<[usize; 2]>()).ok_or(Error::new(EOVERFLOW))?)?),
                SYS_SETPGID => setpgid(ContextId::from(b), ContextId::from(c)),
                SYS_SETREUID => setreuid(b as u32, c as u32),
                SYS_SETRENS => setrens(SchemeNamespace::from(b), SchemeNamespace::from(c)),
                SYS_SETREGID => setregid(b as u32, c as u32),
                SYS_SIGACTION => sigaction(
                    b,
                    UserSlice::ro(c, core::mem::size_of::<SigAction>())?.none_if_null(),
                    UserSlice::wo(d, core::mem::size_of::<SigAction>())?.none_if_null(),
                    e,
                ).map(|()| 0),
                SYS_SIGPROCMASK => sigprocmask(
                    b,
                    UserSlice::ro(c, 16)?.none_if_null(),
                    UserSlice::wo(d, 16)?.none_if_null(),
                ).map(|()| 0),
                SYS_SIGRETURN => sigreturn(),
                SYS_PHYSALLOC => physalloc(b),
                SYS_PHYSALLOC3 => physalloc3(b, c, UserSlice::rw(d, core::mem::size_of::<usize>())?),
                SYS_PHYSFREE => physfree(b, c),
                SYS_PHYSMAP => physmap(b, c, PhysmapFlags::from_bits_truncate(d)),
                SYS_UMASK => umask(b),
                SYS_VIRTTOPHYS => virttophys(b),

                SYS_MREMAP => mremap(b, c, d, e, f),

                _ => Err(Error::new(ENOSYS))
            }
        }
    }

    let mut debug = false;

    debug = debug && {
        let contexts = crate::context::contexts();
        if let Some(context_lock) = contexts.current() {
            let context = context_lock.read();
            if context.name.contains("acid") {
                if a == SYS_CLOCK_GETTIME || a == SYS_YIELD {
                    false
                } else if (a == SYS_WRITE || a == SYS_FSYNC) && (b == 1 || b == 2) {
                    false
                } else {
                    true
                }
            } else {
                false
            }
        } else {
            false
        }
    };

    let debug_start = if debug {
        let contexts = crate::context::contexts();
        if let Some(context_lock) = contexts.current() {
            let context = context_lock.read();
            print!("{} ({}): ", context.name, context.id.get());
        }

        // Do format_call outside print! so possible exception handlers cannot reentrantly
        // deadlock.
        let string = debug::format_call(a, b, c, d, e, f);
        println!("{}", string);

        crate::time::monotonic()
    } else {
        0
    };

    // The next lines set the current syscall in the context struct, then once the inner() function
    // completes, we set the current syscall to none.
    //
    // When the code below falls out of scope it will release the lock
    // see the spin crate for details
    {
        let contexts = crate::context::contexts();
        if let Some(context_lock) = contexts.current() {
            let mut context = context_lock.write();
            context.syscall = Some((a, b, c, d, e, f));
        }
    }

    let result = inner(a, b, c, d, e, f, stack);

    {
        let contexts = crate::context::contexts();
        if let Some(context_lock) = contexts.current() {
            let mut context = context_lock.write();
            context.syscall = None;
        }
    }

    if debug {
        let debug_duration = crate::time::monotonic() - debug_start;

        let contexts = crate::context::contexts();
        if let Some(context_lock) = contexts.current() {
            let context = context_lock.read();
            print!("{} ({}): ", context.name, context.id.get());
        }

        // Do format_call outside print! so possible exception handlers cannot reentrantly
        // deadlock.
        let string = debug::format_call(a, b, c, d, e, f);
        print!("{} = ", string);

        match result {
            Ok(ref ok) => {
                print!("Ok({} ({:#X}))", ok, ok);
            },
            Err(ref err) => {
                print!("Err({} ({:#X}))", err, err.errno);
            }
        }

        println!(" in {} ns", debug_duration);
    }

    // errormux turns Result<usize> into -errno
    Error::mux(result)
}
