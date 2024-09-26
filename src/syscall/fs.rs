//! Filesystem syscalls
use alloc::{sync::Arc, vec::Vec};
use redox_path::RedoxPath;
use spin::RwLock;

use crate::{
    context::{
        self,
        file::{FileDescription, FileDescriptor, InternalFlags},
        memory::{AddrSpace, PageSpan},
        process,
    },
    paging::{Page, VirtualAddress, PAGE_SIZE},
    scheme::{self, CallerCtx, FileHandle, KernelScheme, OpenResult},
    syscall::{data::Stat, error::*, flag::*},
};

use super::usercopy::{UserSlice, UserSliceRo, UserSliceWo};

pub fn file_op_generic<T>(
    fd: FileHandle,
    op: impl FnOnce(&dyn KernelScheme, usize) -> Result<T>,
) -> Result<T> {
    file_op_generic_ext(fd, |s, _, desc| op(s, desc.number))
}
pub fn file_op_generic_ext<T>(
    fd: FileHandle,
    op: impl FnOnce(&dyn KernelScheme, Arc<RwLock<FileDescription>>, FileDescription) -> Result<T>,
) -> Result<T> {
    let file = context::current()
        .read()
        .get_file(fd)
        .ok_or(Error::new(EBADF))?;
    let desc = *file.description.read();

    let scheme = scheme::schemes()
        .get(desc.scheme)
        .ok_or(Error::new(EBADF))?
        .clone();

    op(&*scheme, file.description, desc)
}
pub fn copy_path_to_buf(raw_path: UserSliceRo, max_len: usize) -> Result<alloc::string::String> {
    let mut path_buf = vec![0_u8; max_len];
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
    let (pid, uid, gid, scheme_ns) = match process::current()?.read() {
        ref process => (process.pid.into(), process.euid, process.egid, process.ens),
    };

    // TODO: BorrowedHtBuf!

    /*
    let mut path_buf = BorrowedHtBuf::head()?;
    let path = path_buf.use_for_string(raw_path)?;
    */
    let path_buf = copy_path_to_buf(raw_path, PATH_MAX)?;

    // Display a deprecation warning for any usage of the legacy scheme syntax (scheme:/path)
    // FIXME remove entries from this list as the respective programs get updated
    // if path_buf.contains(':')
    //     && !path_buf.starts_with(':')
    //     && path_buf != "rand:" // FIXME Remove exception at next rustc update
    //     && !path_buf.starts_with("thisproc:") // bootstrap needs redox-rt update
    //     && !path_buf.starts_with("display")
    //     && !path_buf.starts_with("orbital:")
    // {
    //     let name = context::current().read().name.clone();
    //     if !name.contains("cosmic")
    //     // FIXME cosmic apps need crate updates
    //     {
    //         println!("deprecated: legacy path {:?} used by {}", path_buf, name);
    //     }
    // }

    let path = RedoxPath::from_absolute(&path_buf).ok_or(Error::new(EINVAL))?;
    let (scheme_name, reference) = path.as_parts().ok_or(Error::new(EINVAL))?;

    let description = {
        let (scheme_id, scheme) = {
            let schemes = scheme::schemes();
            let (scheme_id, scheme) = schemes
                .get_name(scheme_ns, scheme_name.as_ref())
                .ok_or(Error::new(ENODEV))?;
            (scheme_id, scheme.clone())
        };

        match scheme.kopen(reference.as_ref(), flags, CallerCtx { uid, gid, pid })? {
            OpenResult::SchemeLocal(number, internal_flags) => {
                Arc::new(RwLock::new(FileDescription {
                    scheme: scheme_id,
                    number,
                    offset: 0,
                    flags: (flags & !O_CLOEXEC) as u32,
                    internal_flags,
                }))
            }
            OpenResult::External(desc) => desc,
        }
    };
    //drop(path_buf);

    context::current()
        .read()
        .add_file(FileDescriptor {
            description,
            cloexec: flags & O_CLOEXEC == O_CLOEXEC,
        })
        .ok_or(Error::new(EMFILE))
}

/// rmdir syscall
pub fn rmdir(raw_path: UserSliceRo) -> Result<()> {
    let (scheme_ns, caller_ctx) = match process::current()?.read() {
        ref process => (process.ens, process.caller_ctx()),
    };

    /*
    let mut path_buf = BorrowedHtBuf::head()?;
    let path = path_buf.use_for_string(raw_path)?;
    */
    let path_buf = copy_path_to_buf(raw_path, PATH_MAX)?;
    let path = RedoxPath::from_absolute(&path_buf).ok_or(Error::new(EINVAL))?;
    let (scheme_name, reference) = path.as_parts().ok_or(Error::new(EINVAL))?;

    let scheme = {
        let schemes = scheme::schemes();
        let (_scheme_id, scheme) = schemes
            .get_name(scheme_ns, scheme_name.as_ref())
            .ok_or(Error::new(ENODEV))?;
        scheme.clone()
    };
    scheme.rmdir(reference.as_ref(), caller_ctx)
}

/// Unlink syscall
pub fn unlink(raw_path: UserSliceRo) -> Result<()> {
    let (scheme_ns, caller_ctx) = match process::current()?.read() {
        ref process => (process.ens, process.caller_ctx()),
    };
    /*
    let mut path_buf = BorrowedHtBuf::head()?;
    let path = path_buf.use_for_string(raw_path)?;
    */
    let path_buf = copy_path_to_buf(raw_path, PATH_MAX)?;
    let path = RedoxPath::from_absolute(&path_buf).ok_or(Error::new(EINVAL))?;
    let (scheme_name, reference) = path.as_parts().ok_or(Error::new(EINVAL))?;

    let scheme = {
        let schemes = scheme::schemes();
        let (_scheme_id, scheme) = schemes
            .get_name(scheme_ns, scheme_name.as_ref())
            .ok_or(Error::new(ENODEV))?;
        scheme.clone()
    };
    scheme.unlink(reference.as_ref(), caller_ctx)
}

/// Close syscall
pub fn close(fd: FileHandle) -> Result<()> {
    let file = {
        let context_lock = context::current();
        let context = context_lock.read();
        context.remove_file(fd).ok_or(Error::new(EBADF))?
    };

    file.close()
}

fn duplicate_file(fd: FileHandle, user_buf: UserSliceRo) -> Result<FileDescriptor> {
    let caller_ctx = process::current()?.read().caller_ctx();
    let file = context::current()
        .read()
        .get_file(fd)
        .ok_or(Error::new(EBADF))?;

    if user_buf.is_empty() {
        Ok(FileDescriptor {
            description: Arc::clone(&file.description),
            cloexec: false,
        })
    } else {
        let description = file.description.read();

        let new_description = {
            let scheme = scheme::schemes()
                .get(description.scheme)
                .ok_or(Error::new(EBADF))?
                .clone();

            match scheme.kdup(description.number, user_buf, caller_ctx)? {
                OpenResult::SchemeLocal(number, internal_flags) => {
                    Arc::new(RwLock::new(FileDescription {
                        offset: 0,
                        internal_flags,
                        scheme: description.scheme,
                        number,
                        flags: description.flags,
                    }))
                }
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

    context::current()
        .read()
        .add_file(new_file)
        .ok_or(Error::new(EMFILE))
}

/// Duplicate file descriptor, replacing another
pub fn dup2(fd: FileHandle, new_fd: FileHandle, buf: UserSliceRo) -> Result<FileHandle> {
    if fd == new_fd {
        Ok(new_fd)
    } else {
        let _ = close(new_fd);
        let new_file = duplicate_file(fd, buf)?;

        let context_ref = context::current();
        let context = context_ref.read();

        context
            .insert_file(new_fd, new_file)
            .ok_or(Error::new(EMFILE))
    }
}
pub fn sendfd(socket: FileHandle, fd: FileHandle, flags_raw: usize, arg: u64) -> Result<usize> {
    let requested_flags = SendFdFlags::from_bits(flags_raw).ok_or(Error::new(EINVAL))?;

    let (scheme, number, desc_to_send) = {
        let current_lock = context::current();
        let current = current_lock.read();

        // TODO: Ensure deadlocks can't happen

        let (scheme, number) = match current
            .get_file(socket)
            .ok_or(Error::new(EBADF))?
            .description
            .read()
        {
            ref desc => (desc.scheme, desc.number),
        };
        let scheme = scheme::schemes()
            .get(scheme)
            .ok_or(Error::new(ENODEV))?
            .clone();

        (
            scheme,
            number,
            current
                .remove_file(fd)
                .ok_or(Error::new(EBADF))?
                .description,
        )
    };

    // Inform the scheme whether there are still references to the file description to be sent,
    // either in the current file table or in other file tables, regardless of whether EXCLUSIVE is
    // requested.

    let flags_to_scheme = if Arc::strong_count(&desc_to_send) == 1 {
        SendFdFlags::EXCLUSIVE
    } else {
        if requested_flags.contains(SendFdFlags::EXCLUSIVE) {
            return Err(Error::new(EBUSY));
        }
        SendFdFlags::empty()
    };

    scheme.ksendfd(number, desc_to_send, flags_to_scheme, arg)
}

/// File descriptor controls
pub fn fcntl(fd: FileHandle, cmd: usize, arg: usize) -> Result<usize> {
    let file = context::current()
        .read()
        .get_file(fd)
        .ok_or(Error::new(EBADF))?;

    let description = file.description.read();

    if cmd == F_DUPFD {
        // Not in match because 'files' cannot be locked
        let new_file = duplicate_file(fd, UserSlice::empty())?;

        let context_lock = context::current();
        let context = context_lock.read();

        return context
            .add_file_min(new_file, arg)
            .ok_or(Error::new(EMFILE))
            .map(FileHandle::into);
    }

    // Communicate fcntl with scheme
    if cmd != F_GETFD && cmd != F_SETFD {
        let scheme = scheme::schemes()
            .get(description.scheme)
            .ok_or(Error::new(EBADF))?
            .clone();

        scheme.fcntl(description.number, cmd, arg)?;
    };

    // Perform kernel operation if scheme agrees
    {
        let context_lock = context::current();
        let context = context_lock.read();

        let mut files = context.files.write();
        match *files.get_mut(fd.get()).ok_or(Error::new(EBADF))? {
            Some(ref mut file) => match cmd {
                F_GETFD => {
                    if file.cloexec {
                        Ok(O_CLOEXEC)
                    } else {
                        Ok(0)
                    }
                }
                F_SETFD => {
                    file.cloexec = arg & O_CLOEXEC == O_CLOEXEC;
                    Ok(0)
                }
                F_GETFL => Ok(description.flags as usize),
                F_SETFL => {
                    let new_flags =
                        (description.flags & O_ACCMODE as u32) | (arg as u32 & !O_ACCMODE as u32);
                    drop(description);
                    file.description.write().flags = new_flags;
                    Ok(0)
                }
                _ => Err(Error::new(EINVAL)),
            },
            None => Err(Error::new(EBADF)),
        }
    }
}

pub fn frename(fd: FileHandle, raw_path: UserSliceRo) -> Result<()> {
    let (caller_ctx, scheme_ns) = match process::current()?.read() {
        ref process => (
            CallerCtx {
                uid: process.euid,
                gid: process.egid,
                pid: process.pid.get(),
            },
            process.ens,
        ),
    };
    let file = context::current()
        .read()
        .get_file(fd)
        .ok_or(Error::new(EBADF))?;

    /*
    let mut path_buf = BorrowedHtBuf::head()?;
    let path = path_buf.use_for_string(raw_path)?;
    */
    let path_buf = copy_path_to_buf(raw_path, PATH_MAX)?;
    let path = RedoxPath::from_absolute(&path_buf).ok_or(Error::new(EINVAL))?;
    let (scheme_name, reference) = path.as_parts().ok_or(Error::new(EINVAL))?;

    let (scheme_id, scheme) = {
        let schemes = scheme::schemes();
        let (scheme_id, scheme) = schemes
            .get_name(scheme_ns, scheme_name.as_ref())
            .ok_or(Error::new(ENODEV))?;
        (scheme_id, scheme.clone())
    };

    let description = file.description.read();

    if scheme_id != description.scheme {
        return Err(Error::new(EXDEV));
    }

    scheme.frename(description.number, reference.as_ref(), caller_ctx)
}

/// File status
pub fn fstat(fd: FileHandle, user_buf: UserSliceWo) -> Result<()> {
    file_op_generic_ext(fd, |scheme, _, desc| {
        scheme.kfstat(desc.number, user_buf)?;

        // TODO: Ensure only the kernel can access the stat when st_dev is set, or use another API
        // for retrieving the scheme ID from a file descriptor.
        // TODO: Less hacky method.
        let st_dev = desc
            .scheme
            .get()
            .try_into()
            .map_err(|_| Error::new(EOVERFLOW))?;
        user_buf
            .advance(core::mem::offset_of!(Stat, st_dev))
            .and_then(|b| b.limit(8))
            .ok_or(Error::new(EIO))?
            .copy_from_slice(&u64::to_ne_bytes(st_dev))?;

        Ok(())
    })
}

pub fn funmap(virtual_address: usize, length: usize) -> Result<usize> {
    // Partial lengths in funmap are allowed according to POSIX, but not particularly meaningful;
    // since the memory needs to SIGSEGV if later read, the entire page needs to disappear.
    //
    // Thus, while (temporarily) allowing unaligned lengths for compatibility, aligning the length
    // should be done by libc.

    let length_aligned = length.next_multiple_of(PAGE_SIZE);
    if length != length_aligned {
        log::warn!(
            "funmap passed length {:#x} instead of {:#x}",
            length,
            length_aligned
        );
    }

    let addr_space = Arc::clone(context::current().read().addr_space()?);
    let span = PageSpan::validate_nonempty(VirtualAddress::new(virtual_address), length_aligned)
        .ok_or(Error::new(EINVAL))?;
    let unpin = false;
    let notify = addr_space.munmap(span, unpin)?;

    for map in notify {
        let _ = map.unmap();
    }

    Ok(0)
}

pub fn mremap(
    old_address: usize,
    old_size: usize,
    new_address: usize,
    new_size: usize,
    flags: usize,
) -> Result<usize> {
    if old_address % PAGE_SIZE != 0
        || old_size % PAGE_SIZE != 0
        || new_address % PAGE_SIZE != 0
        || new_size % PAGE_SIZE != 0
    {
        return Err(Error::new(EINVAL));
    }
    if old_size == 0 || new_size == 0 {
        return Err(Error::new(EINVAL));
    }

    let old_base = Page::containing_address(VirtualAddress::new(old_address));
    let new_base = Page::containing_address(VirtualAddress::new(new_address));

    let mremap_flags = MremapFlags::from_bits_truncate(flags);
    let prot_flags = MapFlags::from_bits_truncate(flags)
        & (MapFlags::PROT_READ | MapFlags::PROT_WRITE | MapFlags::PROT_EXEC);

    let map_flags = if mremap_flags.contains(MremapFlags::FIXED_REPLACE) {
        MapFlags::MAP_FIXED
    } else if mremap_flags.contains(MremapFlags::FIXED) {
        MapFlags::MAP_FIXED_NOREPLACE
    } else {
        MapFlags::empty()
    } | prot_flags;

    let addr_space = AddrSpace::current()?;
    let src_span = PageSpan::new(old_base, old_size.div_ceil(PAGE_SIZE));
    let new_page_count = new_size.div_ceil(PAGE_SIZE);
    let requested_dst_base = Some(new_base).filter(|_| new_address != 0);

    let base = addr_space.r#move(
        None,
        src_span,
        requested_dst_base,
        new_page_count,
        map_flags,
        &mut Vec::new(),
    )?;

    Ok(base.start_address().data())
}

pub fn lseek(fd: FileHandle, pos: i64, whence: usize) -> Result<usize> {
    enum Ret {
        Legacy(usize),
        Fsize((Option<u64>, Arc<RwLock<FileDescription>>)),
    }
    let fsize_or_legacy = file_op_generic_ext(fd, |scheme, desc_arc, desc| {
        Ok(
            if let Some(new_off) = scheme.legacy_seek(desc.number, pos as isize, whence) {
                Ret::Legacy(new_off?)
            } else if whence == SEEK_END {
                Ret::Fsize((Some(scheme.fsize(desc.number)?), desc_arc))
            } else {
                Ret::Fsize((None, desc_arc))
            },
        )
    })?;
    let (fsize, desc) = match fsize_or_legacy {
        Ret::Fsize(fsize) => fsize,
        Ret::Legacy(new_pos) => return Ok(new_pos),
    };

    let mut guard = desc.write();

    let new_pos = match whence {
        SEEK_SET => pos,
        SEEK_CUR => pos
            .checked_add_unsigned(guard.offset)
            .ok_or(Error::new(EOVERFLOW))?,
        SEEK_END => pos
            .checked_add_unsigned(fsize.unwrap())
            .ok_or(Error::new(EOVERFLOW))?,
        _ => return Err(Error::new(EINVAL)),
    };
    guard.offset = new_pos.try_into().map_err(|_| Error::new(EINVAL))?;

    Ok(guard.offset as usize)
}
pub fn sys_read(fd: FileHandle, buf: UserSliceWo) -> Result<usize> {
    let (bytes_read, desc_arc, desc) = file_op_generic_ext(fd, |scheme, desc_arc, desc| {
        let offset = if desc.internal_flags.contains(InternalFlags::POSITIONED) {
            desc.offset
        } else {
            u64::MAX
        };
        Ok((
            scheme.kreadoff(desc.number, buf, offset, desc.flags, desc.flags)?,
            desc_arc,
            desc,
        ))
    })?;
    if desc.internal_flags.contains(InternalFlags::POSITIONED) {
        match desc_arc.write().offset {
            ref mut offset => *offset = offset.saturating_add(bytes_read as u64),
        }
    }
    Ok(bytes_read)
}
pub fn sys_write(fd: FileHandle, buf: UserSliceRo) -> Result<usize> {
    let (bytes_written, desc_arc, desc) = file_op_generic_ext(fd, |scheme, desc_arc, desc| {
        let offset = if desc.internal_flags.contains(InternalFlags::POSITIONED) {
            desc.offset
        } else {
            u64::MAX
        };
        Ok((
            scheme.kwriteoff(desc.number, buf, offset, desc.flags, desc.flags)?,
            desc_arc,
            desc,
        ))
    })?;
    if desc.internal_flags.contains(InternalFlags::POSITIONED) {
        match desc_arc.write().offset {
            ref mut offset => *offset = offset.saturating_add(bytes_written as u64),
        }
    }
    Ok(bytes_written)
}
