//! File structs

use alloc::arc::Arc;
use event;
use spin::RwLock;
use scheme::{self, SchemeId};
use syscall::error::{Result, Error, EBADF};
use scheme::FileHandle;

/// A file description
#[derive(Debug)]
pub struct FileDescription {
    /// The scheme that this file refers to
    pub scheme: SchemeId,
    /// The number the scheme uses to refer to this file
    pub number: usize,
    /// The flags passed to open or fcntl(SETFL)
    pub flags: usize,
}

/// A file descriptor
#[derive(Clone, Debug)]
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
