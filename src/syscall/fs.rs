//! Filesystem syscalls
use alloc::sync::Arc;
use syscall::CallerCtx;
use core::str;
use spin::RwLock;

use crate::context::file::{FileDescriptor, FileDescription};
use crate::context;
use crate::memory::PAGE_SIZE;
use crate::scheme::{self, FileHandle, OpenResult, current_caller_ctx};
use crate::syscall::data::{Packet, Stat};
use crate::syscall::error::*;
use crate::syscall::flag::*;


pub fn file_op(a: usize, fd: FileHandle, c: usize, d: usize) -> Result<usize> {
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
}

pub fn file_op_slice(a: usize, fd: FileHandle, slice: &[u8]) -> Result<usize> {
    file_op(a, fd, slice.as_ptr() as usize, slice.len())
}

pub fn file_op_mut_slice(a: usize, fd: FileHandle, slice: &mut [u8]) -> Result<usize> {
    file_op(a, fd, slice.as_mut_ptr() as usize, slice.len())
}

/// Open syscall
pub fn open(path: &str, flags: usize) -> Result<FileHandle> {
    let (pid, uid, gid, scheme_ns, umask) = match context::current()?.read() {
        ref context => (context.id.into(), context.euid, context.egid, context.ens, context.umask),
    };

    let flags = (flags & (!0o777)) | ((flags & 0o777) & (!(umask & 0o777)));


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

    context::current()?.read().add_file(FileDescriptor {
        description,
        cloexec: flags & O_CLOEXEC == O_CLOEXEC,
    }).ok_or(Error::new(EMFILE))
}

pub fn pipe2(fds: &mut [usize], flags: usize) -> Result<usize> {
    if fds.len() < 2 {
        return Err(Error::new(EFAULT));
    }

    let scheme_id = crate::scheme::pipe::pipe_scheme_id().ok_or(Error::new(ENODEV))?;
    let (read_id, write_id) = crate::scheme::pipe::pipe(flags);

    let contexts = context::contexts();
    let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
    let context = context_lock.read();

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

    fds[0] = read_fd.into();
    fds[1] = write_fd.into();

    Ok(0)
}

/// rmdir syscall
pub fn rmdir(path: &str) -> Result<usize> {
    let (uid, gid, scheme_ns) = {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();
        (context.euid, context.egid, context.ens)
    };

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
pub fn unlink(path: &str) -> Result<usize> {
    let (uid, gid, scheme_ns) = {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();
        (context.euid, context.egid, context.ens)
    };

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

fn duplicate_file(fd: FileHandle, buf: &[u8]) -> Result<FileDescriptor> {
    let file = {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();
        context.get_file(fd).ok_or(Error::new(EBADF))?
    };

    if buf.is_empty() {
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
            match scheme.kdup(description.number, buf, current_caller_ctx()?)? {
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
pub fn dup(fd: FileHandle, buf: &[u8]) -> Result<FileHandle> {
    let new_file = duplicate_file(fd, buf)?;

    let contexts = context::contexts();
    let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
    let context = context_lock.read();

    context.add_file(new_file).ok_or(Error::new(EMFILE))
}

/// Duplicate file descriptor, replacing another
pub fn dup2(fd: FileHandle, new_fd: FileHandle, buf: &[u8]) -> Result<FileHandle> {
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
            let new_file = duplicate_file(fd, &[])?;

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

pub fn frename(fd: FileHandle, path: &str) -> Result<usize> {
    let (file, uid, gid, scheme_ns) = match context::current()?.read() {
        ref context => (context.get_file(fd).ok_or(Error::new(EBADF))?, context.euid, context.egid, context.ens),
    };

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
pub fn fstat(fd: FileHandle, stat: &mut Stat) -> Result<usize> {
    let file = {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();
        context.get_file(fd).ok_or(Error::new(EBADF))?
    };

    let description = file.description.read();

    let scheme = {
        let schemes = scheme::schemes();
        let scheme = schemes.get(description.scheme).ok_or(Error::new(EBADF))?;
        Arc::clone(scheme)
    };
    // Fill in scheme number as device number
    stat.st_dev = description.scheme.into() as u64;
    scheme.fstat(description.number, stat)
}

pub fn funmap(virtual_address: usize, length: usize) -> Result<usize> {
    let length_aligned = ((length + (PAGE_SIZE - 1))/PAGE_SIZE) * PAGE_SIZE;
    if length != length_aligned {
        log::warn!("funmap passed length {:#x} instead of {:#x}", length, length_aligned);
    }

    let (page, page_count) = crate::syscall::validate::validate_region(virtual_address, length_aligned)?;

    let addr_space = Arc::clone(context::current()?.read().addr_space()?);
    addr_space.write().munmap(page, page_count);

    Ok(0)
}
