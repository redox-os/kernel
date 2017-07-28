//! File structs

use alloc::arc::Arc;
use spin::RwLock;
use scheme::{self, SchemeId};
use core::mem;
use syscall::error::{Result, Error, EBADF};
use scheme::FileHandle;
use context;

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
    /// If events are on, this is the event ID
    pub event: Option<usize>,
    /// Cloexec flag
    pub cloexec: bool,
}

impl FileDescriptor {
    pub fn close(self, fd: FileHandle) -> Result<usize> {
        if let Some(event_id) = self.event {
            context::event::unregister(fd, self.description.read().scheme, event_id);
        }

        if let Ok(file) = Arc::try_unwrap(self.description) {
            let file = file.into_inner();
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
