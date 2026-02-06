//! # Schemes
//! A scheme is a primitive for handling filesystem syscalls in Redox.
//! Schemes accept paths from the kernel for `open`, and file descriptors that they generate
//! are then passed for operations like `close`, `read`, `write`, etc.
//!
//! The kernel validates paths and file descriptors before they are passed to schemes,
//! also stripping the scheme identifier of paths if necessary.

// TODO: Move handling of the global namespace to userspace.

use alloc::{
    boxed::Box,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    hash::BuildHasherDefault,
    str,
    sync::atomic::{AtomicUsize, Ordering},
};
use hashbrown::hash_map::{DefaultHashBuilder, HashMap};
use spin::{Once, RwLock as SpinRwLock};
use syscall::{
    data::{GlobalSchemes, NewFdParams},
    error::*,
    CallFlags, EventFlags, MunmapFlags,
};

use crate::{
    context::{
        self,
        file::{FileDescription, InternalFlags},
        memory::AddrSpaceWrapper,
        ContextLock,
    },
    sync::{CleanLockToken, LockToken, RwLock, RwLockReadGuard, L0, L1},
    syscall::usercopy::{UserSliceRo, UserSliceRw, UserSliceWo},
};

#[cfg(feature = "acpi")]
use self::acpi::AcpiScheme;
#[cfg(dtb)]
use self::dtb::DtbScheme;

use self::{
    debug::DebugScheme,
    event::EventScheme,
    irq::IrqScheme,
    memory::MemoryScheme,
    pipe::PipeScheme,
    proc::ProcScheme,
    serio::SerioScheme,
    sys::SysScheme,
    time::TimeScheme,
    user::{UserInner, UserScheme},
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
    Scheme(KernelSchemes),
}

/// Schemes list
static HANDLES: Once<RwLock<L1, HashMap<SchemeId, Handle>>> = Once::new();
static SCHEME_LIST_NEXT_ID: AtomicUsize = AtomicUsize::new(MAX_GLOBAL_SCHEMES);
static SCHEME_LIST_ID: AtomicUsize = AtomicUsize::new(0);

/// Initialize schemes, called if needed
fn init_schemes() -> RwLock<L1, HashMap<SchemeId, Handle>> {
    let mut handles = HashMap::new();
    let mut insert_globals = |globals: &[GlobalSchemes]| {
        for &g in globals {
            handles.insert(
                SchemeId::from(g as usize),
                Handle::Scheme(KernelSchemes::Global(g)),
            );
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
    let next_id = SCHEME_LIST_NEXT_ID.fetch_add(1, Ordering::Relaxed);
    handles.insert(SchemeId(next_id), Handle::Scheme(KernelSchemes::SchemeMgr));
    SCHEME_LIST_ID.store(next_id, Ordering::Relaxed);

    RwLock::new(handles)
}

/// Get the global schemes list, const
pub fn schemes<'a>(token: LockToken<'a, L0>) -> SchemesView<'a> {
    SchemesView(handles().read(token))
}

fn handles<'a>() -> &'a RwLock<L1, HashMap<SchemeId, Handle>> {
    HANDLES.call_once(init_schemes)
}

pub struct SchemesView<'a>(RwLockReadGuard<'a, L1, HashMap<SchemeId, Handle>>);
impl<'a> SchemesView<'a> {
    pub fn get(&self, id: SchemeId) -> Option<&KernelSchemes> {
        match self.0.get(&id) {
            Some(Handle::Scheme(scheme)) => Some(&scheme),
            _ => None,
        }
    }
}

/// Scheme list type
pub struct SchemeList;

impl SchemeList {
    /// Get the id of the scheme list
    pub fn id(&self) -> SchemeId {
        SchemeId(SCHEME_LIST_ID.load(Ordering::Relaxed))
    }

    /// Get the UserInner
     fn get_user_inner(&self, id: usize, token: &mut CleanLockToken) -> Option<Arc<UserInner>> {
        match handles().read(token.token()).get(&SchemeId(id)) {
            Some(Handle::Scheme(KernelSchemes::User(UserScheme { inner }))) => Some(inner.clone()),
            _ => None,
        }
    }

    /// Create a new scheme.
    fn insert(
        &self,
        context: Weak<ContextLock>,
        token: &mut CleanLockToken,
    ) -> Result<SchemeId> {
        let mut handles = handles().write(token.token());
        let id = loop {
            let mut id = SCHEME_LIST_NEXT_ID.fetch_add(1, Ordering::Relaxed);

            if id >= SCHEME_MAX_SCHEMES {
                id = 1;
                SCHEME_LIST_NEXT_ID.store(id, Ordering::Relaxed);
            }

            let id = SchemeId(id);

            if !handles.contains_key(&id) {
                break id;
            }
        };

        let root_id = SchemeId(SCHEME_LIST_ID.load(Ordering::Relaxed));
        let inner = Arc::new(UserInner::new(root_id, id, true, context));
        let new_scheme = Handle::Scheme(KernelSchemes::User(UserScheme::new(inner)));
        assert!(handles.insert(id, new_scheme).is_none());
        Ok(id)
    }

    /// Remove a scheme
    fn remove(&self, id: usize, token: &mut CleanLockToken) {
        assert!(handles()
            .write(token.token())
            .remove(&SchemeId(id))
            .is_some());
    }
}

impl KernelScheme for SchemeList {
    fn scheme_root(&self, token: &mut CleanLockToken) -> Result<usize> {
        let id = SchemeId(0);
        handles()
            .write(token.token())
            .insert(id, Handle::SchemeCreationCapability);
        Ok(id.get())
    }
    fn kdup(
        &self,
        scheme_id: usize,
        user_buf: UserSliceRo,
        caller: CallerCtx,
        token: &mut CleanLockToken,
    ) -> Result<OpenResult> {
        let scheme_id = SchemeId(scheme_id);
        match handles()
            .read(token.token())
            .get(&scheme_id)
            .ok_or(Error::new(EBADF))?
        {
            Handle::Scheme(KernelSchemes::User(UserScheme { inner })) => {
                let inner = inner.clone();
                assert!(scheme_id == inner.scheme_id);
                let scheme = scheme_id;
                let params = unsafe { user_buf.read_exact::<NewFdParams>()? };

                return Ok(OpenResult::External(Arc::new(SpinRwLock::new(
                    FileDescription {
                        scheme,
                        number: params.number,
                        offset: params.offset,
                        flags: params.flags as u32,
                        internal_flags: InternalFlags::from_extra0(params.internal_flags)
                            .ok_or(Error::new(EINVAL))?,
                    },
                ))));
            }
            Handle::SchemeCreationCapability => (),
            _ => return Err(Error::new(EBADF)),
        };

        const EXPECTED: &[u8] = b"create-scheme";
        let mut buf = [0u8; EXPECTED.len()];

        if user_buf.copy_common_bytes_to_slice(&mut buf)? < EXPECTED.len() || buf != *EXPECTED {
            return Err(Error::new(EINVAL));
        }

        if caller.uid != 0 {
            return Err(Error::new(EACCES));
        };

        let context = Arc::downgrade(&context::current());

        let scheme_id = self.insert(context, token)?;
        Ok(OpenResult::SchemeLocal(
            scheme_id.get(),
            InternalFlags::empty(),
        ))
    }

    fn kfpath(&self, _id: usize, buf: UserSliceWo, _token: &mut CleanLockToken) -> Result<usize> {
        buf.copy_common_bytes_from_slice("/scheme".as_bytes())
    }

    fn fevent(
        &self,
        id: usize,
        flags: EventFlags,
        token: &mut CleanLockToken,
    ) -> Result<EventFlags> {
        match self.get_user_inner(id, token) {
            Some(inner) => inner.fevent(flags),
            _ => return Err(Error::new(EBADF)),
        }
    }

    fn fsync(&self, id: usize, token: &mut CleanLockToken) -> Result<()> {
        match self.get_user_inner(id, token) {
            Some(inner) => inner.fsync(),
            None => return Err(Error::new(EBADF)),
        }
    }

    fn close(&self, id: usize, token: &mut CleanLockToken) -> Result<()> {
        self.remove(id, token);
        Ok(())
    }

    fn kreadoff(
        &self,
        id: usize,
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
        id: usize,
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
        descs: Vec<Arc<SpinRwLock<FileDescription>>>,
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

#[derive(Clone)]
pub enum KernelSchemes {
    SchemeMgr,
    User(UserScheme),
    Global(GlobalSchemes),
}

impl core::ops::Deref for KernelSchemes {
    type Target = dyn KernelScheme;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::SchemeMgr => &SchemeList,
            Self::User(scheme) => scheme,

            Self::Global(global) => global.as_scheme(),
        }
    }
}

pub const ALL_KERNEL_SCHEMES: &[GlobalSchemes] = &[
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
            #[cfg(not(all(feature = "acpi", dtb)))]
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

#[allow(unused_variables)]
pub trait KernelScheme: Send + Sync + 'static {
    fn scheme_root(&self, token: &mut CleanLockToken) -> Result<usize> {
        Err(Error::new(EOPNOTSUPP))
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
    fn kfpath(&self, id: usize, buf: UserSliceWo, token: &mut CleanLockToken) -> Result<usize>;
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
    fn unlinkat(
        &self,
        file: usize,
        path: &str,
        flags: usize,
        ctx: CallerCtx,
        token: &mut CleanLockToken,
    ) -> Result<()> {
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
        descs: Vec<Arc<SpinRwLock<FileDescription>>>,
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
    External(Arc<SpinRwLock<FileDescription>>),
}
pub struct CallerCtx {
    pub pid: usize,
    pub uid: u32,
    pub gid: u32,
}
impl CallerCtx {
    pub fn filter_uid_gid(self, euid: u32, egid: u32) -> Self {
        if self.uid == 0 && self.gid == 0 {
            Self {
                pid: self.pid,
                uid: euid,
                gid: egid,
            }
        } else {
            self
        }
    }
}
