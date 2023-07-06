//! Filesystem syscalls
use alloc::sync::Arc;
use spin::RwLock;

use crate::context::file::{FileDescriptor, FileDescription};
use crate::context;
use crate::memory::PAGE_SIZE;
use crate::scheme::{self, FileHandle, OpenResult, current_caller_ctx, KernelScheme, SchemeId};
use crate::syscall::data::Stat;
use crate::syscall::error::*;
use crate::syscall::flag::*;
use crate::syscall::scheme::CallerCtx;

use super::usercopy::{UserSlice, UserSliceWo, UserSliceRo};

/*pub fn file_op(a: usize, fd: FileHandle, c: usize, d: usize) -> Result<usize> {
    let (file, pid, uid, gid) = {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();
        let file = context.get_file(fd).ok_or(Error::new(EBADF))?;
        (file, context.id, context.euid, context.egid)
    };

    let scheme = {
        let schemes = scheme::schemes();
        let scheme = schemes.get(file.description.read().scheme).ok_or(Error::new(EBADF))?;
        Arc::clone(scheme)
    };

    let mut packet = Packet {
        id: 0,
        pid: pid.into(),
        uid,
        gid,
        a,
        b: file.description.read().number,
        c,
        d
    };

    scheme.handle(&mut packet);

    Error::demux(packet.a)
}*/

pub fn file_op_generic<T>(fd: FileHandle, op: impl FnOnce(&dyn KernelScheme, &CallerCtx, usize) -> Result<T>) -> Result<T> {
    file_op_generic_ext(fd, |s, _, ctx, no| op(s, ctx, no))
}
pub fn file_op_generic_ext<T>(fd: FileHandle, op: impl FnOnce(&dyn KernelScheme, SchemeId, &CallerCtx, usize) -> Result<T>) -> Result<T> {
    let (ctx, file) = match context::current()?.read() {
        ref context => (CallerCtx { pid: context.id.into(), uid: context.euid, gid: context.egid }, context.get_file(fd).ok_or(Error::new(EBADF))?),
    };
    let FileDescription { scheme: scheme_id, number, .. } = *file.description.read();

    let scheme = Arc::clone(scheme::schemes().get(scheme_id).ok_or(Error::new(EBADF))?);

    op(&*scheme, scheme_id, &ctx, number)
}
pub fn copy_path_to_buf(raw_path: UserSliceRo, max_len: usize) -> Result<alloc::string::String> {
    let mut path_buf = vec! [0_u8; max_len];
    if raw_path.len() > path_buf.len() {
        return Err(Error::new(ENAMETOOLONG));
    }
    let path_len = raw_path.copy_common_bytes_to_slice(&mut path_buf)?;
    path_buf.truncate(path_len);
    alloc::string::String::from_utf8(path_buf).map_err(|_| Error::new(EINVAL))
    //core::str::from_utf8(&path_buf[..path_len]).map_err(|_| Error::new(EINVAL))
}
// TODO: Define elsewhere
const PATH_MAX: usize = PAGE_SIZE;

/// Open syscall
pub fn open(raw_path: UserSliceRo, flags: usize) -> Result<FileHandle> {
    let (pid, uid, gid, scheme_ns, umask) = match context::current()?.read() {
        ref context => (context.id.into(), context.euid, context.egid, context.ens, context.umask),
    };

    let flags = (flags & (!0o777)) | ((flags & 0o777) & (!(umask & 0o777)));

    // TODO: BorrowedHtBuf!

    /*
    let mut path_buf = BorrowedHtBuf::head()?;
    let path = path_buf.use_for_string(raw_path)?;
    */
    let path = copy_path_to_buf(raw_path, PATH_MAX)?;

    let mut parts = path.splitn(2, ':');
    let scheme_name = parts.next().ok_or(Error::new(EINVAL))?;
    let reference = parts.next().unwrap_or("");

    let description = {
        let (scheme_id, scheme) = {
            let schemes = scheme::schemes();
            let (scheme_id, scheme) = schemes.get_name(scheme_ns, scheme_name).ok_or(Error::new(ENODEV))?;
            (scheme_id, Arc::clone(scheme))
        };

        match scheme.kopen(reference, flags, CallerCtx { uid, gid, pid })? {
            OpenResult::SchemeLocal(number) => Arc::new(RwLock::new(FileDescription {
                namespace: scheme_ns,
                scheme: scheme_id,
                number,
                flags: flags & !O_CLOEXEC,
            })),
            OpenResult::External(desc) => desc,
        }
    };
    //drop(path_buf);

    context::current()?.read().add_file(FileDescriptor {
        description,
        cloexec: flags & O_CLOEXEC == O_CLOEXEC,
    }).ok_or(Error::new(EMFILE))
}

pub fn pipe2(fds: UserSliceWo, flags: usize) -> Result<()> {
    let scheme_id = crate::scheme::pipe::pipe_scheme_id();
    let (read_id, write_id) = crate::scheme::pipe::pipe(flags)?;

    let context_lock = context::current()?;
    let context = context_lock.read();

    //log::warn!("Context {} used deprecated pipe2.", context.name);

    let read_fd = context.add_file(FileDescriptor {
        description: Arc::new(RwLock::new(FileDescription {
            namespace: context.ens,
            scheme: scheme_id,
            number: read_id,
            flags: O_RDONLY | flags & !O_ACCMODE & !O_CLOEXEC,
        })),
        cloexec: flags & O_CLOEXEC == O_CLOEXEC,
    }).ok_or(Error::new(EMFILE))?;

    let write_fd = context.add_file(FileDescriptor {
        description: Arc::new(RwLock::new(FileDescription {
            namespace: context.ens,
            scheme: scheme_id,
            number: write_id,
            flags: O_WRONLY | flags & !O_ACCMODE & !O_CLOEXEC,
        })),
        cloexec: flags & O_CLOEXEC == O_CLOEXEC,
    }).ok_or(Error::new(EMFILE))?;

    let (read_outptr, write_outptr) = fds.split_at(core::mem::size_of::<usize>()).ok_or(Error::new(EINVAL))?;
    read_outptr.write_usize(read_fd.into())?;
    write_outptr.write_usize(write_fd.into())
}

/// rmdir syscall
pub fn rmdir(raw_path: UserSliceRo) -> Result<usize> {
    let (uid, gid, scheme_ns) = match context::current()?.read() {
        ref context => (context.euid, context.egid, context.ens),
    };

    /*
    let mut path_buf = BorrowedHtBuf::head()?;
    let path = path_buf.use_for_string(raw_path)?;
    */
    let path = copy_path_to_buf(raw_path, PATH_MAX)?;

    let mut parts = path.splitn(2, ':');
    let scheme_name = parts.next().ok_or(Error::new(EINVAL))?;
    let reference = parts.next().unwrap_or("");

    let scheme = {
        let schemes = scheme::schemes();
        let (_scheme_id, scheme) = schemes.get_name(scheme_ns, scheme_name).ok_or(Error::new(ENODEV))?;
        Arc::clone(scheme)
    };
    scheme.rmdir(reference, uid, gid)
}

/// Unlink syscall
pub fn unlink(raw_path: UserSliceRo) -> Result<usize> {
    let (uid, gid, scheme_ns) = match context::current()?.read() {
        ref context => (context.euid, context.egid, context.ens),
    };
    /*
    let mut path_buf = BorrowedHtBuf::head()?;
    let path = path_buf.use_for_string(raw_path)?;
    */
    let path = copy_path_to_buf(raw_path, PATH_MAX)?;

    let mut parts = path.splitn(2, ':');
    let scheme_name = parts.next().ok_or(Error::new(EINVAL))?;
    let reference = parts.next().unwrap_or("");

    let scheme = {
        let schemes = scheme::schemes();
        let (_scheme_id, scheme) = schemes.get_name(scheme_ns, scheme_name).ok_or(Error::new(ENODEV))?;
        Arc::clone(scheme)
    };
    scheme.unlink(reference, uid, gid)
}

/// Close syscall
pub fn close(fd: FileHandle) -> Result<usize> {
    let file = {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();
        context.remove_file(fd).ok_or(Error::new(EBADF))?
    };

    file.close()
}

fn duplicate_file(fd: FileHandle, user_buf: UserSliceRo) -> Result<FileDescriptor> {
    let file = context::current()?.read()
        .get_file(fd).ok_or(Error::new(EBADF))?;

    if user_buf.is_empty() {
        Ok(FileDescriptor {
            description: Arc::clone(&file.description),
            cloexec: false,
        })
    } else {
        let description = file.description.read();

        let new_description = {
            let scheme = {
                let schemes = scheme::schemes();
                let scheme = schemes.get(description.scheme).ok_or(Error::new(EBADF))?;
                Arc::clone(scheme)
            };

            match scheme.kdup(description.number, user_buf, current_caller_ctx()?)? {
                OpenResult::SchemeLocal(number) => Arc::new(RwLock::new(FileDescription {
                    namespace: description.namespace,
                    scheme: description.scheme,
                    number,
                    flags: description.flags,
                })),
                OpenResult::External(desc) => desc,
            }
        };

        Ok(FileDescriptor {
            description: new_description,
            cloexec: false,
        })
    }
}

/// Duplicate file descriptor
pub fn dup(fd: FileHandle, buf: UserSliceRo) -> Result<FileHandle> {
    let new_file = duplicate_file(fd, buf)?;

    context::current()?.read().add_file(new_file).ok_or(Error::new(EMFILE))
}

/// Duplicate file descriptor, replacing another
pub fn dup2(fd: FileHandle, new_fd: FileHandle, buf: UserSliceRo) -> Result<FileHandle> {
    if fd == new_fd {
        Ok(new_fd)
    } else {
        let _ = close(new_fd);
        let new_file = duplicate_file(fd, buf)?;

        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();

        context.insert_file(new_fd, new_file).ok_or(Error::new(EMFILE))
    }
}

/// File descriptor controls
pub fn fcntl(fd: FileHandle, cmd: usize, arg: usize) -> Result<usize> {
    let file = {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();
        context.get_file(fd).ok_or(Error::new(EBADF))?
    };

    let description = file.description.read();

    // Communicate fcntl with scheme
    if cmd != F_DUPFD && cmd != F_GETFD && cmd != F_SETFD {
        let scheme = {
            let schemes = scheme::schemes();
            let scheme = schemes.get(description.scheme).ok_or(Error::new(EBADF))?;
            Arc::clone(scheme)
        };
        scheme.fcntl(description.number, cmd, arg)?;
    };

    // Perform kernel operation if scheme agrees
    {
        if cmd == F_DUPFD {
            // Not in match because 'files' cannot be locked
            let new_file = duplicate_file(fd, UserSlice::empty())?;

            let contexts = context::contexts();
            let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
            let context = context_lock.read();

            return context.add_file_min(new_file, arg)
                .ok_or(Error::new(EMFILE))
                .map(FileHandle::into);
        }

        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();

        let mut files = context.files.write();
        match *files.get_mut(fd.into()).ok_or(Error::new(EBADF))? {
            Some(ref mut file) => match cmd {
                F_GETFD => {
                    if file.cloexec {
                        Ok(O_CLOEXEC)
                    } else {
                        Ok(0)
                    }
                },
                F_SETFD => {
                    file.cloexec = arg & O_CLOEXEC == O_CLOEXEC;
                    Ok(0)
                },
                F_GETFL => {
                    Ok(description.flags)
                },
                F_SETFL => {
                    let new_flags = (description.flags & O_ACCMODE) | (arg & ! O_ACCMODE);
                    drop(description);
                    file.description.write().flags = new_flags;
                    Ok(0)
                },
                _ => {
                    Err(Error::new(EINVAL))
                }
            },
            None => Err(Error::new(EBADF))
        }
    }
}

pub fn frename(fd: FileHandle, raw_path: UserSliceRo) -> Result<usize> {
    let (file, uid, gid, scheme_ns) = match context::current()?.read() {
        ref context => (context.get_file(fd).ok_or(Error::new(EBADF))?, context.euid, context.egid, context.ens),
    };

    /*
    let mut path_buf = BorrowedHtBuf::head()?;
    let path = path_buf.use_for_string(raw_path)?;
    */
    let path = copy_path_to_buf(raw_path, PATH_MAX)?;

    let mut parts = path.splitn(2, ':');
    let scheme_name = parts.next().ok_or(Error::new(ENOENT))?;
    let reference = parts.next().unwrap_or("");

    let (scheme_id, scheme) = {
        let schemes = scheme::schemes();
        let (scheme_id, scheme) = schemes.get_name(scheme_ns, scheme_name).ok_or(Error::new(ENODEV))?;
        (scheme_id, scheme.clone())
    };

    let description = file.description.read();

    if scheme_id == description.scheme {
        scheme.frename(description.number, reference, uid, gid)
    } else {
        Err(Error::new(EXDEV))
    }
}

/// File status
pub fn fstat(fd: FileHandle, user_buf: UserSliceWo) -> Result<usize> {
    file_op_generic_ext(fd, |scheme, scheme_id, _, number| {
        scheme.kfstat(number, user_buf)?;

        // TODO: Ensure only the kernel can access the stat when st_dev is set, or use another API
        // for retrieving the scheme ID from a file descriptor.
        // TODO: Less hacky method.
        let st_dev = scheme_id.into().try_into().map_err(|_| Error::new(EOVERFLOW))?;
        user_buf.advance(memoffset::offset_of!(Stat, st_dev)).and_then(|b| b.limit(8)).ok_or(Error::new(EIO))?.copy_from_slice(&u64::to_ne_bytes(st_dev))?;

        Ok(0)
    })
}

pub fn funmap(virtual_address: usize, length: usize) -> Result<usize> {
    let length_aligned = length.next_multiple_of(PAGE_SIZE);
    if length != length_aligned {
        log::warn!("funmap passed length {:#x} instead of {:#x}", length, length_aligned);
    }

    let (page, page_count) = crate::syscall::validate_region(virtual_address, length_aligned)?;

    let addr_space = Arc::clone(context::current()?.read().addr_space()?);
    addr_space.write().munmap(page, page_count);

    Ok(0)
}
