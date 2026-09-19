//! File structs

use crate::{
    event,
    scheme::{
        user::{UserInner, UserScheme},
        KernelSchemes,
    },
    sync::{CleanLockToken, RwLock, L6},
    syscall::error::Result,
};
use alloc::sync::{Arc, Weak};
use syscall::{schemev2::NewFdFlags, Error, GlobalSchemes, RwFlags, ENODEV, O_APPEND, O_NONBLOCK};

pub type LockedFileDescription = RwLock<L6, FileDescription>;

#[derive(Clone, Debug)]
pub enum KernelSchemeRef {
    SchemeMgr,
    Global(GlobalSchemes),
    User(Weak<UserInner>),
}
impl KernelSchemeRef {
    pub fn upgrade(&self) -> Result<KernelSchemes> {
        Ok(match self {
            Self::SchemeMgr => KernelSchemes::SchemeMgr,
            Self::Global(gl) => KernelSchemes::Global(*gl),
            Self::User(u) => {
                KernelSchemes::User(UserScheme::new(u.upgrade().ok_or(Error::new(ENODEV))?))
            }
        })
    }
    #[inline]
    pub fn same_ref_as(&self, other: &KernelSchemes) -> bool {
        match (self, other) {
            (Self::SchemeMgr, KernelSchemes::SchemeMgr) => true,
            (Self::Global(gl1), KernelSchemes::Global(gl2)) => gl1 == gl2,
            (Self::User(weak), KernelSchemes::User(user)) => {
                Weak::as_ptr(weak) == Arc::as_ptr(&user.inner)
            }
            _ => false,
        }
    }
}

/// A file description, as defined in e.g. POSIX.
//
// TODO: Consider "rotating" the way these are stored so that there's one big file description
// array/radix tree per scheme. That would improve efficiency in part because `scheme_ref` would be
// implicit. The scheme can be pointed to either by aligning-down the pointers or in the
// `PageInfo`s. Another advantage is that `number` can be typed into e.g. `Arc<T>`, improving code
// clarity and likely performance as redundant slabs/hashmaps can be eliminated.
#[derive(Clone, Debug)]
pub struct FileDescription {
    /// The current file offset (seek)
    // XXX: This is stored in the kernel because of the nowadays rather stupid design decision of
    // POSIX to associate the file cursor with *file descriptions* rather than *file descriptors*.
    // This makes it much harder to move that state to userspace as POSIX applications can
    // technically expect this cursor to be updated across multiple fork children whose address
    // spaces can have diverged for long. It would be good to either work around that, or find
    // another use for this field for the other 99% of cases in practice.
    pub offset: u64,
    /// The scheme that this file refers to
    pub scheme_ref: KernelSchemeRef,
    /// An arbitrary identifier chosen by the scheme to distinguish between file descriptions it
    /// provides.
    pub number: usize,
    /// The flags passed to open or fcntl(SETFL)
    pub flags: u32,
    pub internal_flags: InternalFlags,
}
bitflags! {
    #[derive(Clone, Copy, Debug)]
    pub struct InternalFlags: u32 {
        const POSITIONED = 1 << 0;
        const NOTIFY_ON_NEXT_DETACH = 1 << 1;
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
    pub description: Arc<LockedFileDescription>,
}

impl FileDescription {
    /// Try closing a file, although at this point the description will be destroyed anyway, if
    /// doing so fails.
    pub fn try_close(self, token: &mut CleanLockToken) -> Result<()> {
        let scheme = self.scheme_ref.upgrade()?;
        event::unregister_file(scheme.scheme_id(), self.number, token);

        scheme.close(self.number, token)
    }
}

impl FileDescriptor {
    pub fn close(self, token: &mut CleanLockToken) -> Result<()> {
        {
            let (scheme, number, internal_flags) = {
                let desc = self.description.read(token.token());
                (desc.scheme_ref.upgrade()?, desc.number, desc.internal_flags)
            };
            if internal_flags.contains(InternalFlags::NOTIFY_ON_NEXT_DETACH) {
                scheme.detach(number, token)?;
            }
        }

        if let Ok(file) = Arc::try_unwrap(self.description).map(RwLock::into_inner) {
            file.try_close(token)?;
        }

        Ok(())
    }
}
