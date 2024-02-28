//! Filesystem syscalls
use alloc::{sync::Arc, vec::Vec};
use redox_path::RedoxPath;
use spin::RwLock;

use crate::{
    context,
    context::{
        file::{FileDescription, FileDescriptor},
        memory::{AddrSpace, PageSpan},
    },
    paging::{Page, VirtualAddress, PAGE_SIZE},
    scheme::{self, CallerCtx, FileHandle, KernelScheme, OpenResult, SchemeId},
    syscall::{data::Stat, error::*, flag::*},
};

use super::usercopy::{UserSlice, UserSliceRo, UserSliceWo};

pub fn file_op_generic<T>(
    fd: FileHandle,
    op: impl FnOnce(&dyn KernelScheme, usize) -> Result<T>,
) -> Result<T> {
    file_op_generic_ext(fd, |s, _, no| op(s, no))
}
pub fn file_op_generic_ext<T>(
    fd: FileHandle,
    op: impl FnOnce(&dyn KernelScheme, SchemeId, usize) -> Result<T>,
) -> Result<T> {
    let file = context::current()?
        .read()
        .get_file(fd)
        .ok_or(Error::new(EBADF))?;
    let FileDescription {
        scheme: scheme_id,
        number,
        ..
    } = *file.description.read();

    let scheme = scheme::schemes()
        .get(scheme_id)
        .ok_or(Error::new(EBADF))?
        .clone();

    op(&*scheme, scheme_id, number)
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
    let (pid, uid, gid, scheme_ns, umask) = match context::current()?.read() {
        ref context => (
            context.id.into(),
            context.euid,
            context.egid,
            context.ens,
            context.umask,
        ),
    };

    let flags = (flags & (!0o777)) | ((flags & 0o777) & (!(umask & 0o777)));

    // TODO: BorrowedHtBuf!

    /*
    let mut path_buf = BorrowedHtBuf::head()?;
    let path = path_buf.use_for_string(raw_path)?;
    */
    let path_buf = copy_path_to_buf(raw_path, PATH_MAX)?;
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

    context::current()?
        .read()
        .add_file(FileDescriptor {
            description,
            cloexec: flags & O_CLOEXEC == O_CLOEXEC,
        })
        .ok_or(Error::new(EMFILE))
}

/// rmdir syscall
pub fn rmdir(raw_path: UserSliceRo) -> Result<()> {
    let (scheme_ns, caller_ctx) = match context::current()?.read() {
        ref context => (context.ens, context.caller_ctx()),
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
    let (scheme_ns, caller_ctx) = match context::current()?.read() {
        ref context => (context.ens, context.caller_ctx()),
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
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();
        context.remove_file(fd).ok_or(Error::new(EBADF))?
    };

    file.close()
}

fn duplicate_file(fd: FileHandle, user_buf: UserSliceRo) -> Result<FileDescriptor> {
    let (file, caller_ctx) = match context::current()?.read() {
        ref context => (
            context.get_file(fd).ok_or(Error::new(EBADF))?,
            context.caller_ctx(),
        ),
    };

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

    context::current()?
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

        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();

        context
            .insert_file(new_fd, new_file)
            .ok_or(Error::new(EMFILE))
    }
}
pub fn sendfd(socket: FileHandle, fd: FileHandle, flags_raw: usize, arg: u64) -> Result<usize> {
    let requested_flags = SendFdFlags::from_bits(flags_raw).ok_or(Error::new(EINVAL))?;

    let (scheme, number, desc_to_send) = {
        let current_lock = context::current()?;
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
    let file = {
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();
        context.get_file(fd).ok_or(Error::new(EBADF))?
    };

    let description = file.description.read();

    // Communicate fcntl with scheme
    if cmd != F_DUPFD && cmd != F_GETFD && cmd != F_SETFD {
        let scheme = scheme::schemes()
            .get(description.scheme)
            .ok_or(Error::new(EBADF))?
            .clone();

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

            return context
                .add_file_min(new_file, arg)
                .ok_or(Error::new(EMFILE))
                .map(FileHandle::into);
        }

        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
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
                F_GETFL => Ok(description.flags),
                F_SETFL => {
                    let new_flags = (description.flags & O_ACCMODE) | (arg & !O_ACCMODE);
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
    let (file, caller_ctx, scheme_ns) = match context::current()?.read() {
        ref context => (
            context.get_file(fd).ok_or(Error::new(EBADF))?,
            CallerCtx {
                uid: context.euid,
                gid: context.egid,
                pid: context.id.get(),
            },
            context.ens,
        ),
    };

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
    file_op_generic_ext(fd, |scheme, scheme_id, number| {
        scheme.kfstat(number, user_buf)?;

        // TODO: Ensure only the kernel can access the stat when st_dev is set, or use another API
        // for retrieving the scheme ID from a file descriptor.
        // TODO: Less hacky method.
        let st_dev = scheme_id
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

    let addr_space = Arc::clone(context::current()?.read().addr_space()?);
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
