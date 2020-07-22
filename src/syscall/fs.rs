//! Filesystem syscalls
use core::sync::atomic::Ordering;
use alloc::sync::Arc;
use spin::RwLock;

use crate::context;
use crate::scheme::{self, FileHandle};
use crate::syscall;
use crate::syscall::data::{Packet, Stat};
use crate::syscall::error::*;
use crate::syscall::flag::*;
use crate::context::file::{FileDescriptor, FileDescription};

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
    let (mut path_canon, uid, gid, scheme_ns, umask) = {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();
        (context.canonicalize(path), context.euid, context.egid, context.ens, context.umask)
    };

    let flags = (flags & (!0o777)) | ((flags & 0o777) & (!(umask & 0o777)));

    //println!("open {}", unsafe { ::core::str::from_utf8_unchecked(&path_canon) });

    for _level in 0..32 { // XXX What should the limit be?
        //println!("  level {} = {:?}", _level, ::core::str::from_utf8(&path_canon));

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
            let reference = reference_opt.unwrap_or(b"");
            let file_id = match scheme.open(reference, flags, uid, gid) {
                Ok(ok) => ok,
                Err(err) => if err.errno == EXDEV {
                    let resolve_flags = O_CLOEXEC | O_SYMLINK | O_RDONLY;
                    let resolve_id = scheme.open(reference, resolve_flags, uid, gid)?;

                    let mut buf = [0; 4096];
                    let res = scheme.read(resolve_id, &mut buf);

                    let _ = scheme.close(resolve_id);

                    let count = res?;

                    let contexts = context::contexts();
                    let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
                    let context = context_lock.read();
                    path_canon = context.canonicalize(&buf[..count]);

                    continue;
                } else {
                    return Err(err);
                }
            };
            (scheme_id, file_id)
        };

        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();
        return context.add_file(FileDescriptor {
            description: Arc::new(RwLock::new(FileDescription {
                namespace: scheme_ns,
                scheme: scheme_id,
                number: file_id,
                flags: flags & !O_CLOEXEC,
            })),
            cloexec: flags & O_CLOEXEC == O_CLOEXEC,
        }).ok_or(Error::new(EMFILE));
    }
    Err(Error::new(ELOOP))
}

pub fn pipe2(fds: &mut [usize], flags: usize) -> Result<usize> {
    if fds.len() >= 2 {
        let scheme_id = crate::scheme::pipe::PIPE_SCHEME_ID.load(Ordering::SeqCst);
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
                namespace: description.namespace,
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

pub fn frename(fd: FileHandle, path: &[u8]) -> Result<usize> {
    let file = {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();
        context.get_file(fd).ok_or(Error::new(EBADF))?
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
        let mut desc_opt = None;

        {
            let contexts = context::contexts();
            let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
            let context = context_lock.read();

            let mut grants = context.grants.lock();

            // TODO: Make BTreeSet roll around at the speed of sound,
            // I mean, its got places to go, gotta follow its rainbow.
            // Can't keep around, gotta moving on.
            // Guess what lies ahead, only one way to find oooouuuut.

            let grant = grants.iter().map(|grant| grant.region()).find(|grant| {
                let start = grant.start_address().get();
                let end = start + grant.size();

                virtual_address >= start && virtual_address < end
            });

            if let Some(grant) = grant {
                let mut grant = grants.take(&grant).unwrap();
                desc_opt = grant.desc_opt.take();
                grant.unmap();
            }
        }

        if let Some(desc) = desc_opt {
            let scheme_id = {
                let description = desc.description.read();
                description.scheme
            };

            let scheme = {
                let schemes = scheme::schemes();
                let scheme = schemes.get(scheme_id).ok_or(Error::new(EBADF))?;
                scheme.clone()
            };
            let res = scheme.funmap(virtual_address);

            let _ = desc.close();

            res
        } else {
            Err(Error::new(EFAULT))
        }
    }
}
