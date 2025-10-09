//! # Schemes
//! A scheme is a primitive for handling filesystem syscalls in Redox.
//! Schemes accept paths from the kernel for `open`, and file descriptors that they generate
//! are then passed for operations like `close`, `read`, `write`, etc.
//!
//! The kernel validates paths and file descriptors before they are passed to schemes,
//! also stripping the scheme identifier of paths if necessary.

// TODO: Move handling of the global namespace to userspace.

use alloc::{boxed::Box, string::ToString, sync::Arc, vec::Vec};
use core::{
    hash::BuildHasherDefault,
    str,
    sync::atomic::{AtomicUsize, Ordering},
};
use hashbrown::{hash_map::DefaultHashBuilder, HashMap};
use indexmap::IndexMap;
use spin::{Once, RwLock as SpinRwLock};
use syscall::{data::GlobalSchemes, CallFlags, EventFlags, MunmapFlags};
use syscall::{
    dirent::{DirEntry, DirentBuf, DirentKind},
    O_EXLOCK, O_FSYNC,
};

use crate::{
    context::{
        self,
        file::{FileDescription, InternalFlags},
        memory::AddrSpaceWrapper,
    },
    scheme::{
        self,
        user::{UserInner, UserScheme},
        FileDescription, SchemeId, SchemeNamespace,
    },
    sync::{CleanLockToken, LockToken, RwLock, RwLockReadGuard, RwLockWriteGuard, L0, L1},
    syscall::{
        data::Stat,
        error::*,
        flag::{CallFlags, EventFlags, MODE_DIR, MODE_FILE, O_CREAT, O_RDWR},
        usercopy::{UserSliceRo, UserSliceRw, UserSliceWo},
    },
};

#[cfg(feature = "acpi")]
use self::acpi::AcpiScheme;
#[cfg(dtb)]
use self::dtb::DtbScheme;

use self::{
    debug::DebugScheme, event::EventScheme, irq::IrqScheme, memory::MemoryScheme, pipe::PipeScheme,
    proc::ProcScheme, root::RootScheme, serio::SerioScheme, sys::SysScheme, time::TimeScheme,
    user::UserScheme,
};

/// When compiled with the "acpi" feature - `acpi:` - allows drivers to read a limited set of ACPI tables.
#[cfg(feature = "acpi")]
pub mod acpi;
#[cfg(dtb)]
pub mod dtb;

/// `debug:` - provides access to serial console
pub mod debug;

/// `event:` - allows reading of `Event`s which are registered using `fevent`
pub mod event;

/// `irq:` - allows userspace handling of IRQs
pub mod irq;

/// `memory:` - a scheme for accessing physical memory
pub mod memory;

/// `pipe:` - used internally by the kernel to implement `pipe`
pub mod pipe;

/// `proc:` - allows tracing processes and reading/writing their memory
pub mod proc;

/// `:` - allows the creation of userspace schemes, tightly dependent on `user`
pub mod root;

/// `serio:` - provides access to ps/2 devices
pub mod serio;

/// `sys:` - system information, such as the context list and scheme list
pub mod sys;

/// `time:` - allows reading time, setting timeouts and getting events when they are met
pub mod time;

/// A wrapper around userspace schemes, tightly dependent on `root`
pub mod user;

/// Limit on number of schemes
pub const SCHEME_MAX_SCHEMES: usize = 65_536;

// Unique identifier for a scheme namespace.
int_like!(SchemeNamespace, AtomicSchemeNamespace, usize, AtomicUsize);

// Unique identifier for a scheme.
int_like!(SchemeId, usize);

// Unique identifier for a file descriptor.
int_like!(FileHandle, AtomicFileHandle, usize, AtomicUsize);

#[allow(dead_code)]
pub enum StrOrBytes<'a> {
    Str(&'a str),
    Bytes(&'a [u8]),
}

#[allow(dead_code)]
impl<'a> StrOrBytes<'a> {
    pub fn as_str(&self) -> Result<&str, core::str::Utf8Error> {
        match self {
            StrOrBytes::Str(path) => Ok(path),
            StrOrBytes::Bytes(slice) => core::str::from_utf8(slice),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            StrOrBytes::Str(path) => path.as_bytes(),
            StrOrBytes::Bytes(slice) => slice,
        }
    }

    pub fn from_str(path: &'a str) -> Self {
        StrOrBytes::Str(path)
    }

    pub fn from_bytes(slice: &'a [u8]) -> Self {
        StrOrBytes::Bytes(slice)
    }
}

pub struct SchemeIter<'a> {
    inner: Option<indexmap::map::Iter<'a, Box<str>, SchemeId>>,
}

impl<'a> Iterator for SchemeIter<'a> {
    type Item = (&'a Box<str>, &'a SchemeId);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.as_mut().and_then(|iter| iter.next())
    }
}

enum Handle {
    SchemeCreationCapability,
    UserScheme(KernelSchemes),
}
/// Scheme list type
pub struct SchemeList {
    handles: RwLock<L1, HashMap<SchemeId, Handle>>,
    next_id: usize,
}
impl SchemeList {
    /// Create a new scheme list.
    pub fn new() -> Self {
        let mut handles = HashMap::new();
        let mut insert_globals = |globals: &[GlobalSchemes]| {
            for &g in globals {
                handles.insert(SchemeId::from(g as usize), KernelSchemes::Global(g));
            }
        };

        // TODO: impl TryFrom<SchemeId> and bypass map for global schemes?
        {
            use GlobalSchemes::*;
            insert_globals(&[Debug, Event, Memory, Pipe, Serio, Irq, Time, Sys, Proc]);

            #[cfg(feature = "acpi")]
            insert_globals(&[Acpi]);

            #[cfg(dtb)]
            insert_globals(&[Dtb]);
        }

        let list = SchemeList {
            handles: RwLock::new(handles),
            next_id: MAX_GLOBAL_SCHEMES,
        };

        list
    }

    /// Get the nth scheme.
    pub fn get(&self, id: SchemeId, token: &mut CleanLockToken) -> Option<&KernelSchemes> {
        self.handles.read(token.token().get(&id))
    }

    /// Get the UserInner
    pub fn get_user_inner(
        &self,
        id: SchemeId,
        token: &mut CleanLockToken,
    ) -> Option<Arc<UserInner>> {
        match self.handles.read(token.token()).get(&id) {
            Some(Handle::Scheme(KernelSchemes::User(UserScheme { inner }))) => Some(inner.clone()),
            _ => None,
        }
    }

    /// Create a new scheme.
    pub fn insert(&mut self, context: Weak<ContextLock>) -> Result<SchemeId> {
        if self.next_id >= SCHEME_MAX_SCHEMES {
            self.next_id = 1;
        }

        while self.handles.contains_key(&SchemeId(self.next_id)) {
            self.next_id += 1;
        }

        let id = SchemeId(self.next_id);
        self.next_id += 1;

        let inner = Arc::new(UserInner::new(
            id,
            // TODO: This is a hack, but eventually the legacy interface will be
            // removed.
            false, false, id, context,
        ));
        let new_scheme = UserScheme::new(Arc::downgrade(&inner));
        assert!(self.handles.insert(id, new_scheme).is_none());
        Ok(id)
    }

    /// Remove a scheme
    pub fn remove(&mut self, id: SchemeId, token: &mut CleanLockToken) {
        assert!(self.handles.write(token.token())remove(&id).is_some());
    }
}

/// Schemes list
static SCHEMES: Once<RwLock<L1, Arc<SchemeList>>> = Once::new();

/// Initialize schemes, called if needed
fn init_schemes() -> RwLock<L1, Arc<SchemeList>> {
    let list = Arc::new(SchemeList::new());
    {
        let mut inner_list = list.clone();
        let self_wrapper = KernelSchemes::SchemeMgr(list.clone());
        /// Safety: This initialization function is guaranteed by Once::call_once to run in a single,
        /// uncontended thread. We assume no previous locks were acquired in this thread,
        /// and that no other CleanLockToken instances exist before this point
        let token = unsafe { CleanLockToken::new() };
        inner_list
            .handles
            .write(token.token())
            .insert(SchemeId(inner_list.next_id), self_wrapper);
        inner_list.next_id += 1;
    }

    RwLock::new(list)
}

/// Get the global schemes list, const
pub fn schemes<'a>(token: LockToken<'a, L0>) -> RwLockReadGuard<'a, L1, SchemeList> {
    SCHEMES.call_once(init_schemes).read(token)
}

/// Get the global schemes list, mutable
pub fn schemes_mut<'a>(token: LockToken<'a, L0>) -> RwLockWriteGuard<'a, L1, Arc<SchemeList>> {
    SCHEMES.call_once(init_schemes).write(token)
}

#[derive(Clone)]
pub enum KernelSchemes {
    SchemeMgr(Arc<SchemeList>),
    User(UserScheme),
    Global(GlobalSchemes),
}

impl core::ops::Deref for KernelSchemes {
    type Target = dyn KernelScheme;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::SchemeMgr(scheme) => &**scheme,
            Self::User(scheme) => scheme,

            Self::Global(global) => &**global,
        }
    }
}

#[allow(unused_variables)]
pub trait KernelScheme: Send + Sync + 'static {
    fn root_cap(&self, token: &mut CleanLockToken) -> Result<usize> {
        Err(Error::new(EOPNOTSUPP))
    }

    fn kopen(
        &self,
        path: &str,
        flags: usize,
        _ctx: CallerCtx,
        token: &mut CleanLockToken,
    ) -> Result<OpenResult> {
        Err(Error::new(ENOENT))
    }

    fn kopenat(
        &self,
        file: usize,
        path: StrOrBytes,
        flags: usize,
        fcntl_flags: u32,
        _ctx: CallerCtx,
        token: &mut CleanLockToken,
    ) -> Result<OpenResult> {
        Err(Error::new(EOPNOTSUPP))
    }

    fn kfmap(
        &self,
        number: usize,
        addr_space: &Arc<AddrSpaceWrapper>,
        map: &crate::syscall::data::Map,
        consume: bool,
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        Err(Error::new(EOPNOTSUPP))
    }
    fn kfunmap(
        &self,
        number: usize,
        offset: usize,
        size: usize,
        flags: MunmapFlags,
        token: &mut CleanLockToken,
    ) -> Result<()> {
        Err(Error::new(EOPNOTSUPP))
    }

    fn kdup(
        &self,
        old_id: usize,
        buf: UserSliceRo,
        _caller: CallerCtx,
        token: &mut CleanLockToken,
    ) -> Result<OpenResult> {
        Err(Error::new(EOPNOTSUPP))
    }
    fn kwriteoff(
        &self,
        id: usize,
        buf: UserSliceRo,
        offset: u64,
        flags: u32,
        stored_flags: u32,
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        if offset != u64::MAX {
            return Err(Error::new(ESPIPE));
        }
        self.kwrite(id, buf, flags, stored_flags, token)
    }
    fn kreadoff(
        &self,
        id: usize,
        buf: UserSliceWo,
        offset: u64,
        flags: u32,
        stored_flags: u32,
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        if offset != u64::MAX {
            return Err(Error::new(ESPIPE));
        }
        self.kread(id, buf, flags, stored_flags, token)
    }
    fn kwrite(
        &self,
        id: usize,
        buf: UserSliceRo,
        flags: u32,
        stored_flags: u32,
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        Err(Error::new(EBADF))
    }
    fn kread(
        &self,
        id: usize,
        buf: UserSliceWo,
        flags: u32,
        stored_flags: u32,
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        Err(Error::new(EBADF))
    }
    fn kfpath(&self, id: usize, buf: UserSliceWo, token: &mut CleanLockToken) -> Result<usize> {
        Err(Error::new(EBADF))
    }
    fn kfutimens(&self, id: usize, buf: UserSliceRo, token: &mut CleanLockToken) -> Result<usize> {
        Err(Error::new(EBADF))
    }
    fn kfstat(&self, id: usize, buf: UserSliceWo, token: &mut CleanLockToken) -> Result<()> {
        Err(Error::new(EBADF))
    }
    fn kfstatvfs(&self, id: usize, buf: UserSliceWo, token: &mut CleanLockToken) -> Result<()> {
        Err(Error::new(EBADF))
    }

    fn getdents(
        &self,
        id: usize,
        buf: UserSliceWo,
        header_size: u16,
        opaque_id_first: u64,
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        Err(Error::new(EOPNOTSUPP))
    }

    fn fsync(&self, id: usize, token: &mut CleanLockToken) -> Result<()> {
        Ok(())
    }
    fn ftruncate(&self, id: usize, len: usize, token: &mut CleanLockToken) -> Result<()> {
        Err(Error::new(EBADF))
    }
    fn fsize(&self, id: usize, token: &mut CleanLockToken) -> Result<u64> {
        Err(Error::new(ESPIPE))
    }
    fn legacy_seek(
        &self,
        id: usize,
        pos: isize,
        whence: usize,
        token: &mut CleanLockToken,
    ) -> Option<Result<usize>> {
        None
    }
    fn fchmod(&self, id: usize, new_mode: u16, token: &mut CleanLockToken) -> Result<()> {
        Err(Error::new(EBADF))
    }
    fn fchown(
        &self,
        id: usize,
        new_uid: u32,
        new_gid: u32,
        token: &mut CleanLockToken,
    ) -> Result<()> {
        Err(Error::new(EBADF))
    }
    fn fevent(
        &self,
        id: usize,
        flags: EventFlags,
        token: &mut CleanLockToken,
    ) -> Result<EventFlags> {
        Ok(EventFlags::empty())
    }
    fn flink(
        &self,
        id: usize,
        new_path: &str,
        caller_ctx: CallerCtx,
        token: &mut CleanLockToken,
    ) -> Result<()> {
        Err(Error::new(EBADF))
    }
    fn frename(
        &self,
        id: usize,
        new_path: &str,
        caller_ctx: CallerCtx,
        token: &mut CleanLockToken,
    ) -> Result<()> {
        Err(Error::new(EBADF))
    }
    fn fcntl(
        &self,
        id: usize,
        cmd: usize,
        arg: usize,
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        Ok(0)
    }
    fn rmdir(&self, path: &str, ctx: CallerCtx, token: &mut CleanLockToken) -> Result<()> {
        Err(Error::new(ENOENT))
    }
    fn unlink(&self, path: &str, ctx: CallerCtx, token: &mut CleanLockToken) -> Result<()> {
        Err(Error::new(ENOENT))
    }
    fn close(&self, id: usize, token: &mut CleanLockToken) -> Result<()> {
        Ok(())
    }
    fn kcall(
        &self,
        id: usize,
        payload: UserSliceRw,
        flags: CallFlags,
        metadata: &[u64],
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        Err(Error::new(EOPNOTSUPP))
    }
    fn kfdwrite(
        &self,
        id: usize,
        descs: Vec<Arc<spin::RwLock<FileDescription>>>,
        flags: CallFlags,
        args: u64,
        metadata: &[u64],
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        Err(Error::new(EOPNOTSUPP))
    }
    fn kfdread(
        &self,
        id: usize,
        payload: UserSliceRw,
        flags: CallFlags,
        metadata: &[u64],
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        Err(Error::new(EOPNOTSUPP))
    }
}

#[derive(Debug)]
pub enum OpenResult {
    SchemeLocal(usize, InternalFlags),
    External(Arc<spin::RwLock<FileDescription>>),
}
pub struct CallerCtx {
    pub pid: usize,
    pub uid: u32,
    pub gid: u32,
}

pub const ALL_KERNEL_SCHEMES: &'static [GlobalSchemes] = &[
    GlobalSchemes::Debug,
    GlobalSchemes::Event,
    GlobalSchemes::Memory,
    GlobalSchemes::Pipe,
    GlobalSchemes::Serio,
    GlobalSchemes::Irq,
    GlobalSchemes::Time,
    GlobalSchemes::Sys,
    GlobalSchemes::Proc,
    #[cfg(feature = "acpi")]
    GlobalSchemes::Acpi,
    #[cfg(dtb)]
    GlobalSchemes::Dtb,
];

pub const MAX_GLOBAL_SCHEMES: usize = 16;
pub const KERNEL_SCHEMES_COUNT: usize = ALL_KERNEL_SCHEMES.len();
const _: () = {
    assert!(1 + KERNEL_SCHEMES_COUNT < MAX_GLOBAL_SCHEMES);
};

pub trait SchemeExt {
    fn as_scheme(&self) -> &dyn KernelScheme;
    fn scheme_id(self) -> SchemeId;
}
impl SchemeExt for GlobalSchemes {
    fn as_scheme(&self) -> &dyn KernelScheme {
        match self {
            Self::Debug => &DebugScheme,
            Self::Event => &EventScheme,
            Self::Memory => &MemoryScheme,
            Self::Pipe => &PipeScheme,
            Self::Serio => &SerioScheme,
            Self::Irq => &IrqScheme,
            Self::Time => &TimeScheme,
            Self::Sys => &SysScheme,
            Self::Proc => &ProcScheme,
            #[cfg(feature = "acpi")]
            Self::Acpi => &AcpiScheme,
            #[cfg(dtb)]
            Self::Dtb => &DtbScheme,
            _ => panic!("Unknown global scheme"),
        }
    }
    fn scheme_id(self) -> SchemeId {
        SchemeId::new(self as usize)
    }
}

#[cold]
pub fn init_globals() {
    #[cfg(feature = "acpi")]
    {
        AcpiScheme::init();
    }
    #[cfg(dtb)]
    {
        DtbScheme::init();
    }
    IrqScheme::init();
}

impl KernelScheme for SchemeList {
    fn root_cap(&self, token: &mut CleanLockToken) -> Result<usize> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.handles
            .write(token.token())
            .insert(id, Handle::SchemeCreationCapability);
        Ok(id)
    }
    fn kdup(
        &self,
        scheme_id: usize,
        buf: UserSliceRo,
        _caller: CallerCtx,
        token: &mut CleanLockToken,
    ) -> Result<OpenResult> {
        match self
            .handles
            .read(token.token())
            .get(&old_id)
            .ok_or(Error::new(EBADF))?
        {
            Handle::Scheme(KernelSchemes::User(UserScheme { inner })) => {
                assert!(scheme_id == inner.scheme_id.get());
                let scheme = SchemeId(scheme_id);
                let number = buf.read_usize()?;
                return Ok(OpenResult::External(Arc::new(SpinRwLock::new(
                    FileDescription {
                        scheme,
                        number,
                        offset: 0,
                        flags: (O_CREAT | O_RDWR) as u32,
                        internal_flags: InternalFlags::empty(),
                    },
                ))));
            }
            Handle::SchemeCreationCapability => (),
            _ => return Err(Error::new(EBADF)),
        };

        if ctx.uid != 0 {
            return Err(Error::new(EACCES));
        };

        let context = Arc::downgrade(&context::current());

        let scheme_id = self.insert(context)?;
        Ok(OpenResult::SchemeLocal(
            scheme_id.get(),
            InternalFlags::empty(),
        ))
    }

    fn fevent(
        &self,
        file: usize,
        flags: EventFlags,
        token: &mut CleanLockToken,
    ) -> Result<EventFlags> {
        match self.get_user_inner(id, token) {
            Some(inner) => inner.fevent(flags),
            _ => return Err(Error::new(EBADF)),
        }
    }

    fn fsync(&self, file: usize, token: &mut CleanLockToken) -> Result<()> {
        match self.get_user_inner(id, token) {
            Some(inner) => inner.fsync(),
            None => return Err(Error::new(EBADF)),
        }
    }

    fn close(&self, file: usize, token: &mut CleanLockToken) -> Result<()> {
        self.remove(&file, token);
        Ok(())
    }

    fn kreadoff(
        &self,
        file: usize,
        buf: UserSliceWo,
        _offset: u64,
        flags: u32,
        _stored_flags: u32,
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        match self.get_user_inner(id, token) {
            Some(inner) => inner.read(buf, flags, token),
            None => return Err(Error::new(EBADF)),
        }
    }

    fn kwrite(
        &self,
        file: usize,
        buf: UserSliceRo,
        _flags: u32,
        _stored_flags: u32,
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        match self.get_user_inner(id, token) {
            Some(inner) => inner.write(buf, token),
            None => return Err(Error::new(EBADF)),
        }
    }

    fn kfdwrite(
        &self,
        id: usize,
        descs: Vec<Arc<spin::RwLock<FileDescription>>>,
        flags: CallFlags,
        arg: u64,
        metadata: &[u64],
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        match self.get_user_inner(id, token) {
            Some(inner) => inner.call_fdwrite(descs, flags, arg, metadata),
            None => Err(Error::new(EBADF)),
        }
    }

    fn kfdread(
        &self,
        id: usize,
        payload: UserSliceRw,
        flags: CallFlags,
        metadata: &[u64],
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        match self.get_user_inner(id, token) {
            Some(inner) => inner.call_fdread(payload, flags, metadata, token),
            None => Err(Error::new(EBADF)),
        }
    }
}
