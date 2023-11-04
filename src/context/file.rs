//! File structs

use alloc::sync::Arc;
use crate::event;
use spin::RwLock;
use crate::scheme::{self, SchemeNamespace, SchemeId};
use crate::syscall::error::{Result, Error, EBADF};

/// A file description
#[derive(Clone, Copy, Debug)]
pub struct FileDescription {
    /// The namespace the file was opened from (used for debugging)
    pub namespace: SchemeNamespace,
    /// The scheme that this file refers to
    pub scheme: SchemeId,
    /// The number the scheme uses to refer to this file
    pub number: usize,
    /// The flags passed to open or fcntl(SETFL)
    pub flags: usize,
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
    pub fn try_close(self) -> Result<()> {
        event::unregister_file(self.scheme, self.number);

        let scheme = Arc::clone(
            scheme::schemes()
                .get(self.scheme).ok_or(Error::new(EBADF))?
        );
        scheme.close(self.number)
    }
}

impl FileDescriptor {
    pub fn close(self) -> Result<()> {
        if let Ok(file) = Arc::try_unwrap(self.description) {
            file.into_inner().try_close()?;
        }
        Ok(())
    }
}
