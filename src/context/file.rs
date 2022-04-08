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

impl FileDescriptor {
    pub fn close(self) -> Result<usize> {
        if let Ok(file) = Arc::try_unwrap(self.description) {
            let file = file.into_inner();

            event::unregister_file(file.scheme, file.number);

            let scheme = {
                let schemes = scheme::schemes();
                let scheme = schemes.get(file.scheme).ok_or(Error::new(EBADF))?;
                scheme.clone()
            };
            scheme.close(file.number)
        } else {
            Ok(0)
        }
    }
}
