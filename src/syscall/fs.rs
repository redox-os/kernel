//! Filesystem syscalls
use core::sync::atomic::Ordering;
use alloc::arc::Arc;
use spin::RwLock;

use context;
use scheme::{self, FileHandle};
use syscall;
use syscall::data::{Packet, Stat};
use syscall::error::*;
use syscall::flag::{F_GETFD, F_SETFD, F_GETFL, F_SETFL, F_DUPFD, O_ACCMODE, O_DIRECTORY, O_RDONLY, O_WRONLY, MODE_DIR, MODE_FILE, O_CLOEXEC};
use context::file::{FileDescriptor, FileDescription};

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
        Arc::clone(&scheme)
    };

    let mut packet = Packet {
        id: 0,
        pid: pid.into(),
        uid: uid,
        gid: gid,
        a: a,
        b: file.description.read().number,
        c: c,
        d: d
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

/// Change the current working directory
pub fn chdir(path: &[u8]) -> Result<usize> {
    let fd = open(path, O_RDONLY | O_DIRECTORY)?;
    let mut stat = Stat::default();
    let stat_res = file_op_mut_slice(syscall::number::SYS_FSTAT, fd, &mut stat);
    let _ = close(fd);
    stat_res?;
    if stat.st_mode & (MODE_FILE | MODE_DIR) == MODE_DIR {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();
        let canonical = context.canonicalize(path);
        *context.cwd.lock() = canonical;
        Ok(0)
    } else {
        Err(Error::new(ENOTDIR))
    }
}

/// Get the current working directory
pub fn getcwd(buf: &mut [u8]) -> Result<usize> {
    let contexts = context::contexts();
    let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
    let context = context_lock.read();
    let cwd = context.cwd.lock();
    let mut i = 0;
    while i < buf.len() && i < cwd.len() {
        buf[i] = cwd[i];
        i += 1;
    }
    Ok(i)
}

/// Open syscall
pub fn open(path: &[u8], flags: usize) -> Result<FileHandle> {
    let (path_canon, uid, gid, scheme_ns) = {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();
        (context.canonicalize(path), context.euid, context.egid, context.ens)
    };

    //println!("open {}", unsafe { ::core::str::from_utf8_unchecked(&path_canon) });

    let mut parts = path_canon.splitn(2, |&b| b == b':');
    let scheme_name_opt = parts.next();
    let reference_opt = parts.next();

    let (scheme_id, file_id) = {
        let scheme_name = scheme_name_opt.ok_or(Error::new(ENODEV))?;
        let (scheme_id, scheme) = {
            let schemes = scheme::schemes();
            let (scheme_id, scheme) = schemes.get_name(scheme_ns, scheme_name).ok_or(Error::new(ENODEV))?;
            (scheme_id, Arc::clone(&scheme))
        };
        let file_id = scheme.open(reference_opt.unwrap_or(b""), flags, uid, gid)?;
        (scheme_id, file_id)
    };

    let contexts = context::contexts();
    let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
    let context = context_lock.read();
    context.add_file(FileDescriptor {
        description: Arc::new(RwLock::new(FileDescription {
            scheme: scheme_id,
            number: file_id,
            flags: flags & !O_CLOEXEC,
        })),
        cloexec: flags & O_CLOEXEC == O_CLOEXEC,
    }).ok_or(Error::new(EMFILE))
}

pub fn pipe2(fds: &mut [usize], flags: usize) -> Result<usize> {
    if fds.len() >= 2 {
        let scheme_id = ::scheme::pipe::PIPE_SCHEME_ID.load(Ordering::SeqCst);
        let (read_id, write_id) = ::scheme::pipe::pipe(flags);

        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();

        let read_fd = context.add_file(FileDescriptor {
            description: Arc::new(RwLock::new(FileDescription {
                scheme: scheme_id,
                number: read_id,
                flags: O_RDONLY | flags & !O_ACCMODE & !O_CLOEXEC,
            })),
            cloexec: flags & O_CLOEXEC == O_CLOEXEC,
        }).ok_or(Error::new(EMFILE))?;

        let write_fd = context.add_file(FileDescriptor {
            description: Arc::new(RwLock::new(FileDescription {
                scheme: scheme_id,
                number: write_id,
                flags: O_WRONLY | flags & !O_ACCMODE & !O_CLOEXEC,
            })),
            cloexec: flags & O_CLOEXEC == O_CLOEXEC,
        }).ok_or(Error::new(EMFILE))?;

        fds[0] = read_fd.into();
        fds[1] = write_fd.into();

        Ok(0)
    } else {
        Err(Error::new(EFAULT))
    }
}

/// chmod syscall
pub fn chmod(path: &[u8], mode: u16) -> Result<usize> {
    let (path_canon, uid, gid, scheme_ns) = {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();
        (context.canonicalize(path), context.euid, context.egid, context.ens)
    };

    let mut parts = path_canon.splitn(2, |&b| b == b':');
    let scheme_name_opt = parts.next();
    let reference_opt = parts.next();

    let scheme_name = scheme_name_opt.ok_or(Error::new(ENODEV))?;
    let scheme = {
        let schemes = scheme::schemes();
        let (_scheme_id, scheme) = schemes.get_name(scheme_ns, scheme_name).ok_or(Error::new(ENODEV))?;
        Arc::clone(&scheme)
    };
    scheme.chmod(reference_opt.unwrap_or(b""), mode, uid, gid)
}

/// rmdir syscall
pub fn rmdir(path: &[u8]) -> Result<usize> {
    let (path_canon, uid, gid, scheme_ns) = {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();
        (context.canonicalize(path), context.euid, context.egid, context.ens)
    };

    let mut parts = path_canon.splitn(2, |&b| b == b':');
    let scheme_name_opt = parts.next();
    let reference_opt = parts.next();

    let scheme_name = scheme_name_opt.ok_or(Error::new(ENODEV))?;
    let scheme = {
        let schemes = scheme::schemes();
        let (_scheme_id, scheme) = schemes.get_name(scheme_ns, scheme_name).ok_or(Error::new(ENODEV))?;
        Arc::clone(&scheme)
    };
    scheme.rmdir(reference_opt.unwrap_or(b""), uid, gid)
}

/// Unlink syscall
pub fn unlink(path: &[u8]) -> Result<usize> {
    let (path_canon, uid, gid, scheme_ns) = {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();
        (context.canonicalize(path), context.euid, context.egid, context.ens)
    };

    let mut parts = path_canon.splitn(2, |&b| b == b':');
    let scheme_name_opt = parts.next();
    let reference_opt = parts.next();

    let scheme_name = scheme_name_opt.ok_or(Error::new(ENODEV))?;
    let scheme = {
        let schemes = scheme::schemes();
        let (_scheme_id, scheme) = schemes.get_name(scheme_ns, scheme_name).ok_or(Error::new(ENODEV))?;
        Arc::clone(&scheme)
    };
    scheme.unlink(reference_opt.unwrap_or(b""), uid, gid)
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

        let new_id = {
            let scheme = {
                let schemes = scheme::schemes();
                let scheme = schemes.get(description.scheme).ok_or(Error::new(EBADF))?;
                Arc::clone(&scheme)
            };
            scheme.dup(description.number, buf)?
        };

        Ok(FileDescriptor {
            description: Arc::new(RwLock::new(FileDescription {
                scheme: description.scheme,
                number: new_id,
                flags: description.flags,
            })),
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
            Arc::clone(&scheme)
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

        let mut files = context.files.lock();
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

/// Register events for file
pub fn fevent(fd: FileHandle, flags: usize) -> Result<usize> {
    Err(Error::new(ENOSYS))
}

pub fn frename(fd: FileHandle, path: &[u8]) -> Result<usize> {
    let file = {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();
        let file = context.get_file(fd).ok_or(Error::new(EBADF))?;
        file
    };

    let (path_canon, uid, gid, scheme_ns) = {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();
        (context.canonicalize(path), context.euid, context.egid, context.ens)
    };

    let mut parts = path_canon.splitn(2, |&b| b == b':');
    let scheme_name_opt = parts.next();
    let reference_opt = parts.next();

    let scheme_name = scheme_name_opt.ok_or(Error::new(ENODEV))?;
    let (scheme_id, scheme) = {
        let schemes = scheme::schemes();
        let (scheme_id, scheme) = schemes.get_name(scheme_ns, scheme_name).ok_or(Error::new(ENODEV))?;
        (scheme_id, scheme.clone())
    };

    let description = file.description.read();

    if scheme_id == description.scheme {
        scheme.frename(description.number, reference_opt.unwrap_or(b""), uid, gid)
    } else {
        Err(Error::new(EXDEV))
    }
}

pub fn funmap(virtual_address: usize) -> Result<usize> {
    if virtual_address == 0 {
        Ok(0)
    } else {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();

        let mut grants = context.grants.lock();

        for i in 0 .. grants.len() {
            let start = grants[i].start_address().get();
            let end = start + grants[i].size();
            if virtual_address >= start && virtual_address < end {
                grants.remove(i).unmap();

                return Ok(0);
            }
        }

        Err(Error::new(EFAULT))
    }
}
