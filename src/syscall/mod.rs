//!
//! This module provides syscall definitions and the necessary resources to parse incoming
//! syscalls

extern crate syscall;

pub use self::syscall::{
    data, error, flag, io, number, ptrace_event, EnvRegisters, FloatRegisters, IntRegisters,
};

pub use self::{fs::*, futex::futex, process::*, time::*, usercopy::validate_region};

use self::{
    data::{Map, TimeSpec},
    debug::{debug_end, debug_start},
    error::{Error, Result, EINVAL, ENOSYS},
    flag::{CallFlags, EventFlags, MapFlags, RwFlags},
    number::*,
    usercopy::UserSlice,
};

use crate::{
    context::memory::AddrSpace,
    percpu::PercpuBlock,
    scheme::{
        memory::{MemoryScheme, MemoryType},
        FileHandle,
    },
    sync::CleanLockToken,
};

/// Debug
pub mod debug;

/// Filesystem syscalls
pub mod fs;

/// Fast userspace mutex
pub mod futex;

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
                    MemoryScheme::fmap_anonymous(
                        &addrspace,
                        &map,
                        false,
                        MemoryType::Writeback,
                        token,
                    )
                } else {
                    file_op_generic(fd, token, |scheme, number, token| {
                        scheme.kfmap(number, &addrspace, &map, false, token)
                    })
                }
            }
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

            // TODO: Can't replace yet with std_fs_call, as fstat overrides device ID, but that can
            // be moved to UserScheme.
            SYS_FSTAT => fstat(fd, UserSlice::wo(c, d)?, token).map(|()| 0),

            SYS_DUP_INTO => {
                dup_into(fd, FileHandle::from(e), UserSlice::ro(c, d)?, token).map(FileHandle::into)
            }
            SYS_DUP2 => {
                dup2(fd, FileHandle::from(c), UserSlice::ro(d, e)?, token).map(FileHandle::into)
            }

            SYS_LSEEK => lseek(fd, c as i64, d, token),
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

            // TODO: This can't be removed yet, since the pre-libredox softbuffer crate is a blocker.
            SYS_FSYNC => {
                //let ctxt_name = crate::context::current().read(token.token()).name;
                //warn!("Context `{ctxt_name}` is using deprecated SYS_FSYNC");

                file_op_generic(fd, token, |scheme, number, token| {
                    scheme.fsync(number, token).map(|()| 0)
                })
            }

            SYS_CLOSE => close(fd, token).map(|()| 0),
            SYS_CALL => {
                let flags = CallFlags::from_bits(e & !0xff).ok_or(Error::new(EINVAL))?;
                if flags.contains(CallFlags::MULTIPLE_FDS) {
                    if g / core::mem::size_of::<usize>() > 16 {
                        return Err(Error::new(EINVAL));
                    };
                    let mut fds = [0_usize; 16];
                    let fds_slice = UserSlice::ro(b, g)?;

                    // TODO: bytemuck/plain
                    let copied = fds_slice.copy_common_bytes_to_slice(unsafe {
                        core::slice::from_raw_parts_mut(
                            fds.as_mut_ptr().cast(),
                            fds.len() * core::mem::size_of::<usize>(),
                        )
                    })?;
                    call(
                        &fds[..copied / core::mem::size_of::<usize>()],
                        UserSlice::rw(c, d)?,
                        flags,
                        UserSlice::ro(f, (e & 0xff) * 8)?,
                        token,
                    )
                } else {
                    call(
                        &[b],
                        UserSlice::rw(c, d)?,
                        flags,
                        UserSlice::ro(f, (e & 0xff) * 8)?,
                        token,
                    )
                }
            }
            SYS_OPENAT_INTO => openat_into(
                fd,
                UserSlice::ro(c, d)?,
                e,
                f as _,
                FileHandle::from(g),
                token,
            )
            .map(FileHandle::into),
            SYS_UNLINKAT => unlinkat(fd, UserSlice::ro(c, d)?, e, token).map(|()| 0),
            SYS_YIELD => sched_yield(token).map(|()| 0),
            SYS_NANOSLEEP => nanosleep(
                UserSlice::ro(b, size_of::<TimeSpec>())?,
                UserSlice::wo(c, size_of::<TimeSpec>())?.none_if_null(),
                token,
            )
            .map(|()| 0),
            SYS_CLOCK_GETTIME => {
                clock_gettime(b, UserSlice::wo(c, size_of::<TimeSpec>())?, token).map(|()| 0)
            }
            SYS_FUTEX => futex(b, c, d, e, f, token),

            SYS_MPROTECT => mprotect(b, c, MapFlags::from_bits_truncate(d), token).map(|()| 0),
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
