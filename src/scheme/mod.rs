//! # Schemes
//! A scheme is a primitive for handling filesystem syscalls in Redox.
//! Schemes accept paths from the kernel for `open`, and file descriptors that they generate
//! are then passed for operations like `close`, `read`, `write`, etc.
//!
//! The kernel validates paths and file descriptors before they are passed to schemes,
//! also stripping the scheme identifier of paths if necessary.

// TODO: Move handling of the global namespace to userspace.

use alloc::{boxed::Box, collections::BTreeMap, string::ToString, sync::Arc, vec::Vec};
use core::{hash::BuildHasherDefault, sync::atomic::AtomicUsize};
use hashbrown::{hash_map::DefaultHashBuilder, HashMap};
use indexmap::IndexMap;
use spin::{Once, RwLock, RwLockReadGuard, RwLockWriteGuard};
use syscall::{EventFlags, MunmapFlags, SendFdFlags};

use crate::{
    context::{
        file::{FileDescription, InternalFlags},
        memory::AddrSpaceWrapper,
    },
    syscall::{
        error::*,
        usercopy::{UserSliceRo, UserSliceWo},
    },
};

#[cfg(feature = "acpi")]
use self::acpi::AcpiScheme;
#[cfg(dtb)]
use self::dtb::DtbScheme;

use self::{
    debug::DebugScheme, event::EventScheme, irq::IrqScheme, itimer::ITimerScheme,
    memory::MemoryScheme, pipe::PipeScheme, proc::ProcScheme, root::RootScheme, serio::SerioScheme,
    sys::SysScheme, time::TimeScheme, user::UserScheme,
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

/// `itimer:` - support for getitimer and setitimer
pub mod itimer;

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

pub struct SchemeIter<'a> {
    inner: Option<indexmap::map::Iter<'a, Box<str>, SchemeId>>,
}

impl<'a> Iterator for SchemeIter<'a> {
    type Item = (&'a Box<str>, &'a SchemeId);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.as_mut().and_then(|iter| iter.next())
    }
}

/// Scheme list type
pub struct SchemeList {
    map: HashMap<SchemeId, KernelSchemes>,
    pub(crate) names: HashMap<SchemeNamespace, IndexMap<Box<str>, SchemeId, DefaultHashBuilder>>,
    next_ns: usize,
    next_id: usize,
}
impl SchemeList {
    /// Create a new scheme list.
    pub fn new() -> Self {
        let mut list = SchemeList {
            map: HashMap::new(),
            names: HashMap::new(),
            // Scheme namespaces always start at 1. 0 is a reserved namespace, the null namespace
            next_ns: 1,
            next_id: MAX_GLOBAL_SCHEMES,
        };

        let mut insert_globals = |globals: &[GlobalSchemes]| {
            for &g in globals {
                list.map
                    .insert(SchemeId::from(g as usize), KernelSchemes::Global(g));
            }
        };

        // TODO: impl TryFrom<SchemeId> and bypass map for global schemes?
        {
            use GlobalSchemes::*;
            insert_globals(&[
                Debug,
                Event,
                Memory,
                Pipe,
                Serio,
                Irq,
                Time,
                ITimer,
                Sys,
                ProcFull,
                ProcRestricted,
            ]);

            #[cfg(feature = "acpi")]
            insert_globals(&[Acpi]);

            #[cfg(dtb)]
            insert_globals(&[Dtb]);
        }

        list.new_null();
        list.new_root();
        list
    }

    /// Initialize the null namespace
    fn new_null(&mut self) {
        let ns = SchemeNamespace(0);
        self.names
            .insert(ns, IndexMap::with_hasher(BuildHasherDefault::default()));

        //TODO: Only memory: is in the null namespace right now. It should be removed when
        //anonymous mmap's are implemented
        self.insert_global(ns, "memory", GlobalSchemes::Memory)
            .unwrap();
        self.insert_global(ns, "thisproc", GlobalSchemes::ProcRestricted)
            .unwrap();
        self.insert_global(ns, "pipe", GlobalSchemes::Pipe).unwrap();
    }

    /// Initialize a new namespace
    fn new_ns(&mut self) -> SchemeNamespace {
        let ns = SchemeNamespace(self.next_ns);
        self.next_ns += 1;
        self.names
            .insert(ns, IndexMap::with_hasher(BuildHasherDefault::default()));

        self.insert(ns, "", |scheme_id| {
            KernelSchemes::Root(Arc::new(RootScheme::new(ns, scheme_id)))
        })
        .unwrap();
        self.insert_global(ns, "event", GlobalSchemes::Event)
            .unwrap();
        self.insert_global(ns, "itimer", GlobalSchemes::ITimer)
            .unwrap();
        self.insert_global(ns, "memory", GlobalSchemes::Memory)
            .unwrap();
        self.insert_global(ns, "pipe", GlobalSchemes::Pipe).unwrap();
        self.insert_global(ns, "sys", GlobalSchemes::Sys).unwrap();
        self.insert_global(ns, "time", GlobalSchemes::Time).unwrap();

        ns
    }

    /// Initialize the root namespace
    fn new_root(&mut self) {
        // Do common namespace initialization
        let ns = self.new_ns();

        // These schemes should only be available on the root
        #[cfg(dtb)]
        {
            self.insert_global(ns, "kernel.dtb", GlobalSchemes::Dtb)
                .unwrap();
        }
        #[cfg(feature = "acpi")]
        {
            self.insert_global(ns, "kernel.acpi", GlobalSchemes::Acpi)
                .unwrap();
        }
        self.insert_global(ns, "debug", GlobalSchemes::Debug)
            .unwrap();
        self.insert_global(ns, "irq", GlobalSchemes::Irq).unwrap();
        self.insert_global(ns, "proc", GlobalSchemes::ProcFull)
            .unwrap();
        self.insert_global(ns, "thisproc", GlobalSchemes::ProcRestricted)
            .unwrap();
        self.insert_global(ns, "serio", GlobalSchemes::Serio)
            .unwrap();
    }

    pub fn make_ns(
        &mut self,
        from: SchemeNamespace,
        names: impl IntoIterator<Item = Box<str>>,
    ) -> Result<SchemeNamespace> {
        // Create an empty namespace
        let to = self.new_ns();

        // Copy requested scheme IDs
        for name in names {
            let Some((id, _scheme)) = self.get_name(from, &name) else {
                return Err(Error::new(ENODEV));
            };

            if let Some(ref mut names) = self.names.get_mut(&to) {
                if names
                    .insert(name.to_string().into_boxed_str(), id)
                    .is_some()
                {
                    return Err(Error::new(EEXIST));
                }
            } else {
                panic!("scheme namespace not found");
            }
        }

        Ok(to)
    }

    pub fn iter_name(&self, ns: SchemeNamespace) -> SchemeIter {
        SchemeIter {
            inner: self.names.get(&ns).map(|names| names.iter()),
        }
    }

    /// Get the nth scheme.
    pub fn get(&self, id: SchemeId) -> Option<&KernelSchemes> {
        self.map.get(&id)
    }

    pub fn get_name(&self, ns: SchemeNamespace, name: &str) -> Option<(SchemeId, &KernelSchemes)> {
        if let Some(names) = self.names.get(&ns) {
            if let Some(&id) = names.get(name) {
                return self.get(id).map(|scheme| (id, scheme));
            }
        }
        None
    }

    pub fn insert_global(
        &mut self,
        ns: SchemeNamespace,
        name: &str,
        global: GlobalSchemes,
    ) -> Result<()> {
        let prev = self
            .names
            .get_mut(&ns)
            .ok_or(Error::new(ENODEV))?
            .insert(name.into(), global.scheme_id());

        if prev.is_some() {
            return Err(Error::new(EEXIST));
        }

        Ok(())
    }

    /// Create a new scheme.
    pub fn insert(
        &mut self,
        ns: SchemeNamespace,
        name: &str,
        scheme_fn: impl FnOnce(SchemeId) -> KernelSchemes,
    ) -> Result<SchemeId> {
        self.insert_and_pass(ns, name, |id| (scheme_fn(id), ()))
            .map(|(id, ())| id)
    }

    pub fn insert_and_pass<T>(
        &mut self,
        ns: SchemeNamespace,
        name: &str,
        scheme_fn: impl FnOnce(SchemeId) -> (KernelSchemes, T),
    ) -> Result<(SchemeId, T)> {
        if let Some(names) = self.names.get(&ns) {
            if names.contains_key(name) {
                return Err(Error::new(EEXIST));
            }
        }

        if self.next_id >= SCHEME_MAX_SCHEMES {
            self.next_id = 1;
        }

        while self.map.contains_key(&SchemeId(self.next_id)) {
            self.next_id += 1;
        }

        /* Allow scheme list to grow if required
        if self.next_id >= SCHEME_MAX_SCHEMES {
            return Err(Error::new(EAGAIN));
        }
        */

        let id = SchemeId(self.next_id);
        self.next_id += 1;

        let (new_scheme, t) = scheme_fn(id);

        assert!(self.map.insert(id, new_scheme).is_none());
        if let Some(ref mut names) = self.names.get_mut(&ns) {
            assert!(names
                .insert(name.to_string().into_boxed_str(), id)
                .is_none());
        } else {
            // Nonexistent namespace, posssibly null namespace
            return Err(Error::new(ENODEV));
        }
        Ok((id, t))
    }

    /// Remove a scheme
    pub fn remove(&mut self, id: SchemeId) {
        assert!(self.map.remove(&id).is_some());
        for (_ns, names) in self.names.iter_mut() {
            let mut remove = Vec::with_capacity(1);
            for (name, name_id) in names.iter() {
                if name_id == &id {
                    remove.push(name.clone());
                }
            }
            for name in remove {
                assert!(names.swap_remove(&name).is_some());
            }
        }
    }
}

/// Schemes list
static SCHEMES: Once<RwLock<SchemeList>> = Once::new();

/// Initialize schemes, called if needed
fn init_schemes() -> RwLock<SchemeList> {
    RwLock::new(SchemeList::new())
}

/// Get the global schemes list, const
pub fn schemes() -> RwLockReadGuard<'static, SchemeList> {
    SCHEMES.call_once(init_schemes).read()
}

/// Get the global schemes list, mutable
pub fn schemes_mut() -> RwLockWriteGuard<'static, SchemeList> {
    SCHEMES.call_once(init_schemes).write()
}

#[allow(unused_variables)]
pub trait KernelScheme: Send + Sync + 'static {
    fn kopen(&self, path: &str, flags: usize, _ctx: CallerCtx) -> Result<OpenResult> {
        Err(Error::new(ENOENT))
    }

    fn kfmap(
        &self,
        number: usize,
        addr_space: &Arc<AddrSpaceWrapper>,
        map: &crate::syscall::data::Map,
        consume: bool,
    ) -> Result<usize> {
        Err(Error::new(EOPNOTSUPP))
    }
    fn kfunmap(&self, number: usize, offset: usize, size: usize, flags: MunmapFlags) -> Result<()> {
        Err(Error::new(EOPNOTSUPP))
    }

    fn kdup(&self, old_id: usize, buf: UserSliceRo, _caller: CallerCtx) -> Result<OpenResult> {
        Err(Error::new(EOPNOTSUPP))
    }
    fn kwriteoff(
        &self,
        id: usize,
        buf: UserSliceRo,
        offset: u64,
        flags: u32,
        stored_flags: u32,
    ) -> Result<usize> {
        if offset != u64::MAX {
            return Err(Error::new(ESPIPE));
        }
        self.kwrite(id, buf, flags, stored_flags)
    }
    fn kreadoff(
        &self,
        id: usize,
        buf: UserSliceWo,
        offset: u64,
        flags: u32,
        stored_flags: u32,
    ) -> Result<usize> {
        if offset != u64::MAX {
            return Err(Error::new(ESPIPE));
        }
        self.kread(id, buf, flags, stored_flags)
    }
    fn kwrite(&self, id: usize, buf: UserSliceRo, flags: u32, stored_flags: u32) -> Result<usize> {
        Err(Error::new(EBADF))
    }
    fn kread(&self, id: usize, buf: UserSliceWo, flags: u32, stored_flags: u32) -> Result<usize> {
        Err(Error::new(EBADF))
    }
    fn kfpath(&self, id: usize, buf: UserSliceWo) -> Result<usize> {
        Err(Error::new(EBADF))
    }
    fn kfutimens(&self, id: usize, buf: UserSliceRo) -> Result<usize> {
        Err(Error::new(EBADF))
    }
    fn kfstat(&self, id: usize, buf: UserSliceWo) -> Result<()> {
        Err(Error::new(EBADF))
    }
    fn kfstatvfs(&self, id: usize, buf: UserSliceWo) -> Result<()> {
        Err(Error::new(EBADF))
    }

    fn ksendfd(
        &self,
        id: usize,
        desc: Arc<RwLock<FileDescription>>,
        flags: SendFdFlags,
        arg: u64,
    ) -> Result<usize> {
        Err(Error::new(EOPNOTSUPP))
    }
    fn getdents(
        &self,
        id: usize,
        buf: UserSliceWo,
        header_size: u16,
        opaque_id_first: u64,
    ) -> Result<usize> {
        Err(Error::new(EOPNOTSUPP))
    }

    fn fsync(&self, id: usize) -> Result<()> {
        Ok(())
    }
    fn ftruncate(&self, id: usize, len: usize) -> Result<()> {
        Err(Error::new(EBADF))
    }
    fn fsize(&self, id: usize) -> Result<u64> {
        Err(Error::new(ESPIPE))
    }
    fn legacy_seek(&self, id: usize, pos: isize, whence: usize) -> Option<Result<usize>> {
        None
    }
    fn fchmod(&self, id: usize, new_mode: u16) -> Result<()> {
        Err(Error::new(EBADF))
    }
    fn fchown(&self, id: usize, new_uid: u32, new_gid: u32) -> Result<()> {
        Err(Error::new(EBADF))
    }
    fn fevent(&self, id: usize, flags: EventFlags) -> Result<EventFlags> {
        Ok(EventFlags::empty())
    }
    fn frename(&self, id: usize, new_path: &str, caller_ctx: CallerCtx) -> Result<()> {
        Err(Error::new(EBADF))
    }
    fn fcntl(&self, id: usize, cmd: usize, arg: usize) -> Result<usize> {
        Ok(0)
    }
    fn rmdir(&self, path: &str, ctx: CallerCtx) -> Result<()> {
        Err(Error::new(ENOENT))
    }
    fn unlink(&self, path: &str, ctx: CallerCtx) -> Result<()> {
        Err(Error::new(ENOENT))
    }
    fn close(&self, id: usize) -> Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
pub enum OpenResult {
    SchemeLocal(usize, InternalFlags),
    External(Arc<RwLock<FileDescription>>),
}
pub struct CallerCtx {
    pub pid: usize,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Clone)]
pub enum KernelSchemes {
    Root(Arc<RootScheme>),
    User(UserScheme),
    Global(GlobalSchemes),
}
#[repr(u8)]
#[derive(Clone, Copy)]
pub enum GlobalSchemes {
    Debug = 1,
    Event,
    Memory,
    Pipe,
    Serio,
    Irq,
    Time,
    ITimer,
    Sys,
    ProcFull,
    ProcRestricted,

    #[cfg(feature = "acpi")]
    Acpi,

    #[cfg(dtb)]
    Dtb,
}
pub const MAX_GLOBAL_SCHEMES: usize = 16;

const _: () = {
    assert!(1 + core::mem::variant_count::<GlobalSchemes>() < MAX_GLOBAL_SCHEMES);
};

impl core::ops::Deref for KernelSchemes {
    type Target = dyn KernelScheme;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Root(scheme) => &**scheme,
            Self::User(scheme) => scheme,

            Self::Global(global) => &**global,
        }
    }
}
impl core::ops::Deref for GlobalSchemes {
    type Target = dyn KernelScheme;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Debug => &DebugScheme,
            Self::Event => &EventScheme,
            Self::Memory => &MemoryScheme,
            Self::Pipe => &PipeScheme,
            Self::Serio => &SerioScheme,
            Self::Irq => &IrqScheme,
            Self::Time => &TimeScheme,
            Self::ITimer => &ITimerScheme,
            Self::Sys => &SysScheme,
            Self::ProcFull => &ProcScheme::<true>,
            Self::ProcRestricted => &ProcScheme::<false>,
            #[cfg(feature = "acpi")]
            Self::Acpi => &AcpiScheme,
            #[cfg(dtb)]
            Self::Dtb => &DtbScheme,
        }
    }
}
impl GlobalSchemes {
    pub fn scheme_id(self) -> SchemeId {
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
