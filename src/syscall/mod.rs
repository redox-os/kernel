//!
//! This module provides syscall definitions and the necessary resources to parse incoming
//! syscalls

extern crate syscall;

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
    scheme,
};

pub use self::driver::*;
pub use self::fs::*;
pub use self::futex::futex;
pub use self::privilege::*;
pub use self::process::*;
pub use self::time::*;
pub use self::validate::*;

use self::data::{Map, SigAction, Stat, TimeSpec};
use self::error::{Error, Result, ENOSYS};
use self::flag::{CloneFlags, MapFlags, PhysmapFlags, WaitFlags};
use self::number::*;

use crate::context::ContextId;
use crate::interrupt::InterruptStack;
use crate::scheme::{FileHandle, SchemeNamespace, memory::MemoryScheme};

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

/// Validate input
pub mod validate;

/// This function is the syscall handler of the kernel, it is composed of an inner function that returns a `Result<usize>`. After the inner function runs, the syscall
/// function calls [`Error::mux`] on it.
pub fn syscall(a: usize, b: usize, c: usize, d: usize, e: usize, f: usize, bp: usize, stack: &mut InterruptStack) -> usize {
    #[inline(always)]
    fn inner(a: usize, b: usize, c: usize, d: usize, e: usize, f: usize, bp: usize, stack: &mut InterruptStack) -> Result<usize> {
        //SYS_* is declared in kernel/syscall/src/number.rs
        match a & SYS_CLASS {
            SYS_CLASS_FILE => {
                let fd = FileHandle::from(b);
                match a & SYS_ARG {
                    SYS_ARG_SLICE => match a {
                        SYS_FMAP if b == !0 => {
                            MemoryScheme::fmap_anonymous(unsafe { validate_ref(c as *const Map, d)? })
                        },
                        _ => file_op_slice(a, fd, validate_slice(c as *const u8, d)?),
                    }
                    SYS_ARG_MSLICE => match a {
                        SYS_FSTAT => fstat(fd, unsafe { validate_ref_mut(c as *mut Stat, d)? }),
                        _ => file_op_mut_slice(a, fd, validate_slice_mut(c as *mut u8, d)?),
                    },
                    _ => match a {
                        SYS_CLOSE => close(fd),
                        SYS_DUP => dup(fd, validate_slice(c as *const u8, d)?).map(FileHandle::into),
                        SYS_DUP2 => dup2(fd, FileHandle::from(c), validate_slice(d as *const u8, e)?).map(FileHandle::into),
                        SYS_FCNTL => fcntl(fd, c, d),
                        SYS_FEXEC => fexec(fd, validate_slice(c as *const [usize; 2], d)?, validate_slice(e as *const [usize; 2], f)?),
                        SYS_FRENAME => frename(fd, validate_str(c as *const u8, d)?),
                        SYS_FUNMAP => funmap(b, c),
                        SYS_FMAP_OLD => {
                            {
                                let contexts = crate::context::contexts();
                                let current = contexts.current().unwrap();
                                let current = current.read();
                                println!("{:?} using deprecated fmap(...) call", *current.name.read());
                            }
                            file_op(a, fd, c, d)
                        },
                        SYS_FUNMAP_OLD => {
                            {
                                let contexts = crate::context::contexts();
                                let current = contexts.current().unwrap();
                                let current = current.read();
                                println!("{:?} using deprecated funmap(...) call", *current.name.read());
                            }
                            funmap_old(b)
                        },
                        _ => file_op(a, fd, c, d)
                    }
                }
            },
            SYS_CLASS_PATH => match a {
                SYS_OPEN => open(validate_str(b as *const u8, c)?, d).map(FileHandle::into),
                SYS_CHMOD => chmod(validate_str(b as *const u8, c)?, d as u16),
                SYS_RMDIR => rmdir(validate_str(b as *const u8, c)?),
                SYS_UNLINK => unlink(validate_str(b as *const u8, c)?),
                _ => Err(Error::new(ENOSYS))
            },
            _ => match a {
                SYS_YIELD => sched_yield(),
                SYS_NANOSLEEP => nanosleep(
                    validate_slice(b as *const TimeSpec, 1).map(|req| &req[0])?,
                    if c == 0 {
                        None
                    } else {
                        Some(validate_slice_mut(c as *mut TimeSpec, 1).map(|rem| &mut rem[0])?)
                    }
                ),
                SYS_CLOCK_GETTIME => clock_gettime(b, validate_slice_mut(c as *mut TimeSpec, 1).map(|time| &mut time[0])?),
                SYS_FUTEX => futex(b, c, d, e, f),
                SYS_GETPID => getpid().map(ContextId::into),
                SYS_GETPGID => getpgid(ContextId::from(b)).map(ContextId::into),
                SYS_GETPPID => getppid().map(ContextId::into),
                SYS_CLONE => {
                    let b = CloneFlags::from_bits_truncate(b);

                    #[cfg(not(target_arch = "x86_64"))]
                    {
                        //TODO: CLONE_STACK
                        let ret = clone(b, bp).map(ContextId::into);
                        ret
                    }

                    #[cfg(target_arch = "x86_64")]
                    {
                        let old_rsp = stack.iret.rsp;
                        if b.contains(flag::CLONE_STACK) {
                            stack.iret.rsp = c;
                        }
                        let ret = clone(b, bp).map(ContextId::into);
                        stack.iret.rsp = old_rsp;
                        ret
                    }
                },
                SYS_EXIT => exit((b & 0xFF) << 8),
                SYS_KILL => kill(ContextId::from(b), c),
                SYS_WAITPID => waitpid(ContextId::from(b), c, WaitFlags::from_bits_truncate(d)).map(ContextId::into),
                SYS_CHDIR => chdir(validate_str(b as *const u8, c)?),
                SYS_IOPL => iopl(b, stack),
                SYS_GETCWD => getcwd(validate_slice_mut(b as *mut u8, c)?),
                SYS_GETEGID => getegid(),
                SYS_GETENS => getens(),
                SYS_GETEUID => geteuid(),
                SYS_GETGID => getgid(),
                SYS_GETNS => getns(),
                SYS_GETUID => getuid(),
                SYS_MPROTECT => mprotect(b, c, MapFlags::from_bits_truncate(d)),
                SYS_MKNS => mkns(validate_slice(b as *const [usize; 2], c)?),
                SYS_SETPGID => setpgid(ContextId::from(b), ContextId::from(c)),
                SYS_SETREUID => setreuid(b as u32, c as u32),
                SYS_SETRENS => setrens(SchemeNamespace::from(b), SchemeNamespace::from(c)),
                SYS_SETREGID => setregid(b as u32, c as u32),
                SYS_SIGACTION => sigaction(
                    b,
                    if c == 0 {
                        None
                    } else {
                        Some(validate_slice(c as *const SigAction, 1).map(|act| &act[0])?)
                    },
                    if d == 0 {
                        None
                    } else {
                        Some(validate_slice_mut(d as *mut SigAction, 1).map(|oldact| &mut oldact[0])?)
                    },
                    e
                ),
                SYS_SIGPROCMASK => sigprocmask(
                    b,
                    if c == 0 {
                        None
                    } else {
                        Some(validate_slice(c as *const [u64; 2], 1).map(|s| &s[0])?)
                    },
                    if d == 0 {
                        None
                    } else {
                        Some(validate_slice_mut(d as *mut [u64; 2], 1).map(|s| &mut s[0])?)
                    }
                ),
                SYS_SIGRETURN => sigreturn(),
                SYS_PIPE2 => pipe2(validate_slice_mut(b as *mut usize, 2)?, c),
                SYS_PHYSALLOC => physalloc(b),
                SYS_PHYSALLOC3 => physalloc3(b, c, &mut validate_slice_mut(d as *mut usize, 1)?[0]),
                SYS_PHYSFREE => physfree(b, c),
                SYS_PHYSMAP => physmap(b, c, PhysmapFlags::from_bits_truncate(d)),
                SYS_PHYSUNMAP => physunmap(b),
                SYS_UMASK => umask(b),
                SYS_VIRTTOPHYS => virttophys(b),
                _ => Err(Error::new(ENOSYS))
            }
        }
    }

    /*
    let debug = {
        let contexts = crate::context::contexts();
        if let Some(context_lock) = contexts.current() {
            let context = context_lock.read();
            let name = context.name.read();
            if name.contains("redoxfs") {
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

    if debug {
        let contexts = crate::context::contexts();
        if let Some(context_lock) = contexts.current() {
            let context = context_lock.read();
            print!("{} ({}): ", *context.name.read(), context.id.into());
        }

        println!("{}", debug::format_call(a, b, c, d, e, f));
    }
    */

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

    let result = inner(a, b, c, d, e, f, bp, stack);

    {
        let contexts = crate::context::contexts();
        if let Some(context_lock) = contexts.current() {
            let mut context = context_lock.write();
            context.syscall = None;
        }
    }

    /*
    if debug {
        let contexts = crate::context::contexts();
        if let Some(context_lock) = contexts.current() {
            let context = context_lock.read();
            print!("{} ({}): ", *context.name.read(), context.id.into());
        }

        print!("{} = ", debug::format_call(a, b, c, d, e, f));

        match result {
            Ok(ref ok) => {
                println!("Ok({} ({:#X}))", ok, ok);
            },
            Err(ref err) => {
                println!("Err({} ({:#X}))", err, err.errno);
            }
        }
    }
    */

    // errormux turns Result<usize> into -errno
    Error::mux(result)
}
