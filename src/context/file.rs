//! File structs

use crate::{
    event,
    scheme::{self, SchemeId},
    sync::CleanLockToken,
    syscall::error::{Error, Result, EBADF},
};
use alloc::sync::Arc;
use spin::RwLock;
use syscall::{schemev2::NewFdFlags, RwFlags, O_APPEND, O_NONBLOCK};

/// A file description
#[derive(Clone, Copy, Debug)]
pub struct FileDescription {
    /// The current file offset (seek)
    pub offset: u64,
    /// The scheme that this file refers to
    pub scheme: SchemeId,
    /// The number the scheme uses to refer to this file
    pub number: usize,
    /// The flags passed to open or fcntl(SETFL)
    pub flags: u32,
    pub internal_flags: InternalFlags,
}
bitflags! {
    #[derive(Clone, Copy, Debug)]
    pub struct InternalFlags: u32 {
        const POSITIONED = 1;
    }
}
impl FileDescription {
    pub fn rw_flags(&self, rw: RwFlags) -> u32 {
        let mut ret = self.flags & !(O_NONBLOCK | O_APPEND) as u32;
        if rw.contains(RwFlags::APPEND) {
            ret |= O_APPEND as u32;
        }
        if rw.contains(RwFlags::NONBLOCK) {
            ret |= O_NONBLOCK as u32;
        }
        ret
    }
}
impl InternalFlags {
    pub fn from_extra0(fl: u8) -> Option<Self> {
        Some(
            NewFdFlags::from_bits(fl)?
                .iter()
                .map(|fd| {
                    if fd == NewFdFlags::POSITIONED {
                        Self::POSITIONED
                    } else {
                        Self::empty()
                    }
                })
                .collect(),
        )
    }
}

/// A file descriptor
#[derive(Clone, Debug)]
#[must_use = "File descriptors must be closed"]
pub struct FileDescriptor {
    /// Corresponding file description
    pub description: Arc<RwLock<FileDescription>>,
    /// Cloexec flag
    pub cloexec: bool,
}

impl FileDescription {
    /// Try closing a file, although at this point the description will be destroyed anyway, if
    /// doing so fails.
    pub fn try_close(self, token: &mut CleanLockToken) -> Result<()> {
        event::unregister_file(self.scheme, self.number);

        let scheme = scheme::schemes(token.token())
            .get(self.scheme)
            .ok_or(Error::new(EBADF))?
            .clone();

        scheme.close(self.number, token)
    }
}

impl FileDescriptor {
    pub fn close(self, token: &mut CleanLockToken) -> Result<()> {
        if let Ok(file) = Arc::try_unwrap(self.description).map(RwLock::into_inner) {
            file.try_close(token)?;
        }
        Ok(())
    }
}
