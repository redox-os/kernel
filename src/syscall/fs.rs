//! Filesystem syscalls
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::str;
use core::sync::atomic::Ordering;
use spin::RwLock;

use crate::context::file::{FileDescriptor, FileDescription};
use crate::context::memory::Region;
use crate::context;
use crate::memory::PAGE_SIZE;
use crate::paging::VirtualAddress;
use crate::scheme::{self, FileHandle};
use crate::syscall::data::{Packet, Stat};
use crate::syscall::error::*;
use crate::syscall::flag::*;
use crate::syscall;

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
pub fn chdir(path: &str) -> Result<usize> {
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
        *context.cwd.write() = canonical;
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
    let cwd = context.cwd.read();
    let cwd_bytes = cwd.as_bytes();
    let mut i = 0;
    while i < buf.len() && i < cwd_bytes.len() {
        buf[i] = cwd_bytes[i];
        i += 1;
    }
    Ok(i)
}

/// Open syscall
pub fn open(path: &str, flags: usize) -> Result<FileHandle> {
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

        let mut parts = path_canon.splitn(2, ':');
        let scheme_name_opt = parts.next();
        let reference_opt = parts.next();

        let (scheme_id, file_id) = {
            let scheme_name = scheme_name_opt.ok_or(Error::new(ENODEV))?;
            let (scheme_id, scheme) = {
                let schemes = scheme::schemes();
                let (scheme_id, scheme) = schemes.get_name(scheme_ns, scheme_name).ok_or(Error::new(ENODEV))?;
                (scheme_id, Arc::clone(&scheme))
            };
            let reference = reference_opt.unwrap_or("");
            let file_id = match scheme.open(reference, flags, uid, gid) {
                Ok(ok) => ok,
                Err(err) => if err.errno == EXDEV {
                    let resolve_flags = O_CLOEXEC | O_SYMLINK | O_RDONLY;
                    let resolve_id = scheme.open(reference, resolve_flags, uid, gid)?;

                    let mut buf = [0; 4096];
                    let res = scheme.read(resolve_id, &mut buf);

                    let _ = scheme.close(resolve_id);

                    let count = res?;

                    let buf_str = str::from_utf8(&buf[..count]).map_err(|_| Error::new(EINVAL))?;

                    let contexts = context::contexts();
                    let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
                    let context = context_lock.read();
                    path_canon = context.canonicalize(buf_str);

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

/// chmod syscall
pub fn chmod(path: &str, mode: u16) -> Result<usize> {
    let (path_canon, uid, gid, scheme_ns) = {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();
        (context.canonicalize(path), context.euid, context.egid, context.ens)
    };

    let mut parts = path_canon.splitn(2, ':');
    let scheme_name_opt = parts.next();
    let reference_opt = parts.next();

    let scheme_name = scheme_name_opt.ok_or(Error::new(ENODEV))?;
    let scheme = {
        let schemes = scheme::schemes();
        let (_scheme_id, scheme) = schemes.get_name(scheme_ns, scheme_name).ok_or(Error::new(ENODEV))?;
        Arc::clone(&scheme)
    };
    scheme.chmod(reference_opt.unwrap_or(""), mode, uid, gid)
}

/// rmdir syscall
pub fn rmdir(path: &str) -> Result<usize> {
    let (path_canon, uid, gid, scheme_ns) = {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();
        (context.canonicalize(path), context.euid, context.egid, context.ens)
    };

    let mut parts = path_canon.splitn(2, ':');
    let scheme_name_opt = parts.next();
    let reference_opt = parts.next();

    let scheme_name = scheme_name_opt.ok_or(Error::new(ENODEV))?;
    let scheme = {
        let schemes = scheme::schemes();
        let (_scheme_id, scheme) = schemes.get_name(scheme_ns, scheme_name).ok_or(Error::new(ENODEV))?;
        Arc::clone(&scheme)
    };
    scheme.rmdir(reference_opt.unwrap_or(""), uid, gid)
}

/// Unlink syscall
pub fn unlink(path: &str) -> Result<usize> {
    let (path_canon, uid, gid, scheme_ns) = {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();
        (context.canonicalize(path), context.euid, context.egid, context.ens)
    };

    let mut parts = path_canon.splitn(2, ':');
    let scheme_name_opt = parts.next();
    let reference_opt = parts.next();

    let scheme_name = scheme_name_opt.ok_or(Error::new(ENODEV))?;
    let scheme = {
        let schemes = scheme::schemes();
        let (_scheme_id, scheme) = schemes.get_name(scheme_ns, scheme_name).ok_or(Error::new(ENODEV))?;
        Arc::clone(&scheme)
    };
    scheme.unlink(reference_opt.unwrap_or(""), uid, gid)
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

    let mut parts = path_canon.splitn(2, ':');
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
        scheme.frename(description.number, reference_opt.unwrap_or(""), uid, gid)
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
        Arc::clone(&scheme)
    };
    // Fill in scheme number as device number
    stat.st_dev = description.scheme.into() as u64;
    scheme.fstat(description.number, stat)
}

pub fn funmap_old(virtual_address: usize) -> Result<usize> {
    if virtual_address == 0 {
        Ok(0)
    } else {
        let mut desc_opt = None;

        {
            let contexts = context::contexts();
            let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
            let context = context_lock.read();

            let mut grants = context.grants.write();

            if let Some(region) = grants.contains(VirtualAddress::new(virtual_address)).map(Region::from) {
                let mut grant = grants.take(&region).unwrap();
                desc_opt = grant.desc_opt.take();
                grant.unmap();
            }
        }

        if let Some(file_ref) = desc_opt {
            let scheme_id = { file_ref.desc.description.read().scheme };

            let scheme = {
                let schemes = scheme::schemes();
                let scheme = schemes.get(scheme_id).ok_or(Error::new(EBADF))?;
                scheme.clone()
            };
            let res = scheme.funmap_old(virtual_address);

            let _ = file_ref.desc.close();

            res
        } else {
            Err(Error::new(EFAULT))
        }
    }
}

pub fn funmap(virtual_address: usize, length: usize) -> Result<usize> {
    if virtual_address == 0 || length == 0 {
        return Ok(0);
    } else if virtual_address % PAGE_SIZE != 0 {
        return Err(Error::new(EINVAL));
    }

    let mut notify_files = Vec::new();

    let virtual_address = VirtualAddress::new(virtual_address);
    let requested = Region::new(virtual_address, length);

    {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();

        let mut grants = context.grants.write();

        let conflicting: Vec<Region> = grants.conflicts(requested).map(Region::from).collect();

        for conflict in conflicting {
            let grant = grants.take(&conflict).expect("conflicting region didn't exist");
            let intersection = grant.intersect(requested);
            let (before, mut grant, after) = grant.extract(intersection.round()).expect("conflicting region shared no common parts");

            // Notify scheme that holds grant
            if let Some(file_desc) = grant.desc_opt.take() {
                notify_files.push((file_desc, intersection));
            }

            // Keep untouched regions
            if let Some(before) = before {
                grants.insert(before);
            }
            if let Some(after) = after {
                grants.insert(after);
            }

            // Remove irrelevant region
            grant.unmap();
        }
    }

    for (file_ref, intersection) in notify_files {
        let scheme_id = { file_ref.desc.description.read().scheme };

        let scheme = {
            let schemes = scheme::schemes();
            let scheme = schemes.get(scheme_id).ok_or(Error::new(EBADF))?;
            scheme.clone()
        };
        let res = scheme.funmap(intersection.start_address().data(), intersection.size());

        let _ = file_ref.desc.close();

        res?;
    }

    Ok(0)
}
