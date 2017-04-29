//! Filesystem syscalls
use core::sync::atomic::Ordering;

use context;
use scheme::{self, FileHandle};
use syscall;
use syscall::data::{Packet, Stat};
use syscall::error::*;
use syscall::flag::{F_GETFL, F_SETFL, O_ACCMODE, O_RDONLY, O_WRONLY, MODE_DIR, MODE_FILE};

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
        let scheme = schemes.get(file.scheme).ok_or(Error::new(EBADF))?;
        scheme.clone()
    };

    let mut packet = Packet {
        id: 0,
        pid: pid.into(),
        uid: uid,
        gid: gid,
        a: a,
        b: file.number,
        c: c,
        d: d,
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
    let fd = open(path, syscall::flag::O_RDONLY | syscall::flag::O_DIRECTORY)?;
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
            let (scheme_id, scheme) = schemes
                .get_name(scheme_ns, scheme_name)
                .ok_or(Error::new(ENODEV))?;
            (scheme_id, scheme.clone())
        };
        let file_id = scheme
            .open(reference_opt.unwrap_or(b""), flags, uid, gid)?;
        (scheme_id, file_id)
    };

    let contexts = context::contexts();
    let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
    let context = context_lock.read();
    context
        .add_file(::context::file::File {
                      scheme: scheme_id,
                      number: file_id,
                      flags: flags,
                      event: None,
                  })
        .ok_or(Error::new(EMFILE))
}

pub fn pipe2(fds: &mut [usize], flags: usize) -> Result<usize> {
    if fds.len() >= 2 {
        let scheme_id = ::scheme::pipe::PIPE_SCHEME_ID.load(Ordering::SeqCst);
        let (read_id, write_id) = ::scheme::pipe::pipe(flags);

        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();

        let read_fd = context
            .add_file(::context::file::File {
                          scheme: scheme_id,
                          number: read_id,
                          flags: O_RDONLY | flags & !O_ACCMODE,
                          event: None,
                      })
            .ok_or(Error::new(EMFILE))?;

        let write_fd = context
            .add_file(::context::file::File {
                          scheme: scheme_id,
                          number: write_id,
                          flags: O_WRONLY | flags & !O_ACCMODE,
                          event: None,
                      })
            .ok_or(Error::new(EMFILE))?;

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
        let (_scheme_id, scheme) = schemes
            .get_name(scheme_ns, scheme_name)
            .ok_or(Error::new(ENODEV))?;
        scheme.clone()
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
        let (_scheme_id, scheme) = schemes
            .get_name(scheme_ns, scheme_name)
            .ok_or(Error::new(ENODEV))?;
        scheme.clone()
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
        let (_scheme_id, scheme) = schemes
            .get_name(scheme_ns, scheme_name)
            .ok_or(Error::new(ENODEV))?;
        scheme.clone()
    };
    scheme.unlink(reference_opt.unwrap_or(b""), uid, gid)
}

/// Close syscall
pub fn close(fd: FileHandle) -> Result<usize> {
    let file = {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();
        let file = context.remove_file(fd).ok_or(Error::new(EBADF))?;
        file
    };

    if let Some(event_id) = file.event {
        context::event::unregister(fd, file.scheme, event_id);
    }

    let scheme = {
        let schemes = scheme::schemes();
        let scheme = schemes.get(file.scheme).ok_or(Error::new(EBADF))?;
        scheme.clone()
    };
    scheme.close(file.number)
}

/// Duplicate file descriptor
pub fn dup(fd: FileHandle, buf: &[u8]) -> Result<FileHandle> {
    let file = {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();
        let file = context.get_file(fd).ok_or(Error::new(EBADF))?;
        file
    };

    let new_id = {
        let scheme = {
            let schemes = scheme::schemes();
            let scheme = schemes.get(file.scheme).ok_or(Error::new(EBADF))?;
            scheme.clone()
        };
        scheme.dup(file.number, buf)?
    };

    let contexts = context::contexts();
    let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
    let context = context_lock.read();
    context
        .add_file(::context::file::File {
                      scheme: file.scheme,
                      number: new_id,
                      flags: file.flags,
                      event: None,
                  })
        .ok_or(Error::new(EMFILE))
}

/// Duplicate file descriptor, replacing another
pub fn dup2(fd: FileHandle, new_fd: FileHandle, buf: &[u8]) -> Result<FileHandle> {
    if fd == new_fd {
        Ok(new_fd)
    } else {
        let _ = close(new_fd)?;

        let file = {
            let contexts = context::contexts();
            let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
            let context = context_lock.read();
            let file = context.get_file(fd).ok_or(Error::new(EBADF))?;
            file
        };

        let new_id = {
            let scheme = {
                let schemes = scheme::schemes();
                let scheme = schemes.get(file.scheme).ok_or(Error::new(EBADF))?;
                scheme.clone()
            };
            scheme.dup(file.number, buf)?
        };

        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();
        context
            .insert_file(new_fd,
                         ::context::file::File {
                             scheme: file.scheme,
                             number: new_id,
                             flags: file.flags,
                             event: None,
                         })
            .ok_or(Error::new(EBADF))
    }
}

/// File descriptor controls
pub fn fcntl(fd: FileHandle, cmd: usize, arg: usize) -> Result<usize> {
    let file = {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();
        let file = context.get_file(fd).ok_or(Error::new(EBADF))?;
        file
    };

    // Communicate fcntl with scheme
    let res = {
        let scheme = {
            let schemes = scheme::schemes();
            let scheme = schemes.get(file.scheme).ok_or(Error::new(EBADF))?;
            scheme.clone()
        };
        scheme.fcntl(file.number, cmd, arg)?
    };

    // Perform kernel operation if scheme agrees
    {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();
        let mut files = context.files.lock();
        match *files.get_mut(fd.into()).ok_or(Error::new(EBADF))? {
            Some(ref mut file) => {
                match cmd {
                    F_GETFL => Ok(file.flags),
                    F_SETFL => {
                        let new_flags = (file.flags & O_ACCMODE) | (arg & !O_ACCMODE);
                        file.flags = new_flags;
                        Ok(0)
                    }
                    _ => Err(Error::new(EINVAL)),
                }
            }
            None => Err(Error::new(EBADF)),
        }
    }
}

/// Register events for file
pub fn fevent(fd: FileHandle, flags: usize) -> Result<usize> {
    let file = {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();
        let mut files = context.files.lock();
        match *files.get_mut(fd.into()).ok_or(Error::new(EBADF))? {
            Some(ref mut file) => {
                if let Some(event_id) = file.event.take() {
                    println!("{:?}: {:?}:{}: events already registered: {}",
                             fd,
                             file.scheme,
                             file.number,
                             event_id);
                    context::event::unregister(fd, file.scheme, event_id);
                }
                file.clone()
            }
            None => return Err(Error::new(EBADF)),
        }
    };

    let scheme = {
        let schemes = scheme::schemes();
        let scheme = schemes.get(file.scheme).ok_or(Error::new(EBADF))?;
        scheme.clone()
    };
    let event_id = scheme.fevent(file.number, flags)?;
    {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();
        let mut files = context.files.lock();
        match *files.get_mut(fd.into()).ok_or(Error::new(EBADF))? {
            Some(ref mut file) => file.event = Some(event_id),
            None => return Err(Error::new(EBADF)),
        }
    }
    context::event::register(fd, file.scheme, event_id);
    Ok(0)
}

pub fn funmap(virtual_address: usize) -> Result<usize> {
    if virtual_address == 0 {
        Ok(0)
    } else {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();

        let mut grants = context.grants.lock();

        for i in 0..grants.len() {
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
