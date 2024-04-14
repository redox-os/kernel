//! # Schemes
//! A scheme is a primitive for handling filesystem syscalls in Redox.
//! Schemes accept paths from the kernel for `open`, and file descriptors that they generate
//! are then passed for operations like `close`, `read`, `write`, etc.
//!
//! The kernel validates paths and file descriptors before they are passed to schemes,
//! also stripping the scheme identifier of paths if necessary.

use alloc::{boxed::Box, collections::BTreeMap, string::ToString, sync::Arc, vec::Vec};
use core::sync::atomic::AtomicUsize;
use hashbrown::HashMap;
use spin::{Once, RwLock, RwLockReadGuard, RwLockWriteGuard};
use syscall::{EventFlags, MunmapFlags, SendFdFlags, SEEK_CUR, SEEK_END, SEEK_SET};

use crate::{
    context::{file::FileDescription, memory::AddrSpaceWrapper},
    syscall::{
        error::*,
        usercopy::{UserSliceRo, UserSliceWo},
    },
};

#[cfg(all(feature = "acpi", any(target_arch = "x86", target_arch = "x86_64")))]
use self::acpi::AcpiScheme;
#[cfg(all(any(target_arch = "aarch64")))]
use self::dtb::DtbScheme;

use self::{
    debug::DebugScheme, event::EventScheme, irq::IrqScheme, itimer::ITimerScheme,
    memory::MemoryScheme, pipe::PipeScheme, proc::ProcScheme, root::RootScheme, serio::SerioScheme,
    sys::SysScheme, time::TimeScheme, user::UserScheme,
};

/// When compiled with the "acpi" feature - `acpi:` - allows drivers to read a limited set of ACPI tables.
#[cfg(all(feature = "acpi", any(target_arch = "x86", target_arch = "x86_64")))]
pub mod acpi;
#[cfg(all(any(target_arch = "aarch64")))]
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
    inner: Option<hashbrown::hash_map::Iter<'a, Box<str>, SchemeId>>,
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
    pub(crate) names: HashMap<SchemeNamespace, HashMap<Box<str>, SchemeId>>,
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

        list.new_null();
        list.new_root();
        list
    }

    /// Initialize the null namespace
    fn new_null(&mut self) {
        let ns = SchemeNamespace(0);
        self.names.insert(ns, HashMap::new());

        //TODO: Only memory: is in the null namespace right now. It should be removed when
        //anonymous mmap's are implemented
        self.insert_global(ns, "memory", GlobalSchemes::Memory(MemoryScheme))
            .unwrap();
        self.insert_global(ns, "thisproc", GlobalSchemes::ProcRestricted(ProcScheme::<false>))
            .unwrap();
        self.insert_global(ns, "pipe", GlobalSchemes::Pipe(PipeScheme)).unwrap();
    }

    /// Initialize a new namespace
    fn new_ns(&mut self) -> SchemeNamespace {
        let ns = SchemeNamespace(self.next_ns);
        self.next_ns += 1;
        self.names.insert(ns, HashMap::new());

        self.insert(ns, "", |scheme_id| {
            KernelSchemes::Root(Arc::new(RootScheme::new(ns, scheme_id)))
        })
        .unwrap();
        self.insert_global(ns, "event", GlobalSchemes::Event(EventScheme))
            .unwrap();
        self.insert_global(ns, "itimer", GlobalSchemes::ITimer(ITimerScheme))
            .unwrap();
        self.insert_global(ns, "memory", GlobalSchemes::Memory(MemoryScheme))
            .unwrap();
        self.insert_global(ns, "pipe", GlobalSchemes::Pipe(PipeScheme)).unwrap();
        self.insert_global(ns, "sys", GlobalSchemes::Sys(SysScheme)).unwrap();
        self.insert_global(ns, "time", GlobalSchemes::Time(TimeScheme)).unwrap();

        ns
    }

    /// Initialize the root namespace
    fn new_root(&mut self) {
        // Do common namespace initialization
        let ns = self.new_ns();

        // These schemes should only be available on the root
        #[cfg(all(any(target_arch = "aarch64")))]
        {
            self.insert_global(ns, "kernel.dtb", GlobalSchemes::Dtb(DtbScheme))
                .unwrap();
        }
        #[cfg(all(feature = "acpi", any(target_arch = "x86", target_arch = "x86_64")))]
        {
            self.insert_global(ns, "kernel.acpi", GlobalSchemes::Acpi(AcpiScheme))
                .unwrap();
        }
        self.insert_global(ns, "debug", GlobalSchemes::Debug(DebugScheme))
            .unwrap();
        self.insert_global(ns, "irq", GlobalSchemes::Irq(IrqScheme)).unwrap();
        self.insert_global(ns, "proc", GlobalSchemes::ProcFull(ProcScheme::<true>))
            .unwrap();
        self.insert_global(ns, "thisproc", GlobalSchemes::ProcRestricted(ProcScheme::<false>))
            .unwrap();
        self.insert_global(ns, "serio", GlobalSchemes::Serio(SerioScheme))
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
        if let Some(global) = GlobalSchemes::ALL.get(id.get()) && id.get() != 0 {
            return Some(global);
        }
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
                assert!(names.remove(&name).is_some());
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
#[enum_dispatch::enum_dispatch]
pub trait KernelScheme where Self: Send + Sync + 'static {
    fn kopen(&self, path: &str, flags: usize, _ctx: CallerCtx) -> Result<OpenResult> {
        Err(Error::new(ENOENT))
    }

    fn kdup(&self, old_id: usize, buf: UserSliceRo, _caller: CallerCtx) -> Result<OpenResult> {
        Err(Error::new(EOPNOTSUPP))
    }
    fn kwrite(&self, id: usize, buf: UserSliceRo) -> Result<usize> {
        Err(Error::new(EBADF))
    }
    fn kread(&self, id: usize, buf: UserSliceWo) -> Result<usize> {
        Err(Error::new(EBADF))
    }
    fn kfpath(&self, id: usize, buf: UserSliceWo) -> Result<usize> {
        Err(Error::new(EBADF))
    }
    fn kfstat(&self, id: usize, buf: UserSliceWo) -> Result<()> {
        Err(Error::new(EBADF))
    }

    fn fsync(&self, id: usize) -> Result<()> {
        Err(Error::new(EBADF))
    }
    fn seek(&self, id: usize, pos: isize, whence: usize) -> Result<usize> {
        Err(Error::new(ESPIPE))
    }
    fn fevent(&self, id: usize, flags: EventFlags) -> Result<EventFlags> {
        Err(Error::new(EBADF))
    }
    fn fcntl(&self, id: usize, cmd: usize, arg: usize) -> Result<usize> {
        Err(Error::new(EBADF))
    }
    fn close(&self, id: usize) -> Result<()> {
        Err(Error::new(EBADF))
    }
}
impl KernelSchemes {
    pub fn mmap(&self, id: usize, addrspace: &Arc<AddrSpaceWrapper>, map: &crate::syscall::data::Map, consume: bool) -> Result<usize> {
        match self {
            KernelSchemes::User(user) => user.mmap(id, &addrspace, &map, consume),
            KernelSchemes::Global(GlobalSchemes::Memory(_)) => MemoryScheme::mmap(id, &addrspace, &map, consume),
            KernelSchemes::Global(GlobalSchemes::ProcFull(_) | GlobalSchemes::ProcRestricted(_)) => ProcScheme::<false>::mmap(id, &addrspace, &map, consume),
            _ => Err(Error::new(EOPNOTSUPP)),
        }
    }
}

#[derive(Debug)]
pub enum OpenResult {
    SchemeLocal(usize),
    External(Arc<RwLock<FileDescription>>),
}
pub struct CallerCtx {
    pub pid: usize,
    pub uid: u32,
    pub gid: u32,
}

pub fn calc_seek_offset(
    cur_pos: usize,
    rel_pos: isize,
    whence: usize,
    len: usize,
) -> Result<usize> {
    match whence {
        SEEK_SET => usize::try_from(rel_pos).map_err(|_| Error::new(EINVAL)),
        SEEK_CUR => cur_pos
            .checked_add_signed(rel_pos)
            .ok_or(Error::new(EOVERFLOW)),
        SEEK_END => len.checked_add_signed(rel_pos).ok_or(Error::new(EOVERFLOW)),

        _ => return Err(Error::new(EINVAL)),
    }
}

#[derive(Clone)]
#[enum_dispatch::enum_dispatch(KernelScheme)]
pub enum KernelSchemes {
    Root(Arc<RootScheme>),
    User(UserScheme),
    Global(GlobalSchemes),
}
#[repr(u8)]
#[enum_dispatch::enum_dispatch(KernelScheme)]
#[derive(Clone, Copy)]
pub enum GlobalSchemes {
    Debug(DebugScheme),
    Event(EventScheme),
    Memory(MemoryScheme),
    Pipe(PipeScheme),
    Serio(SerioScheme),
    Irq(IrqScheme),
    Time(TimeScheme),
    ITimer(ITimerScheme),
    Sys(SysScheme),
    ProcFull(ProcScheme<true>),
    ProcRestricted(ProcScheme<false>),

    #[cfg(all(feature = "acpi", any(target_arch = "x86", target_arch = "x86_64")))]
    Acpi(AcpiScheme),

    #[cfg(target_arch = "aarch64")]
    Dtb(DtbScheme),
}
pub const MAX_GLOBAL_SCHEMES: usize = 16;

const _: () = {
    assert!(1 + core::mem::variant_count::<GlobalSchemes>() < MAX_GLOBAL_SCHEMES);
};

impl GlobalSchemes {
    pub fn scheme_id(self) -> SchemeId {
        SchemeId::new(match self {
            Self::Debug(_) => 1,
            Self::Event(_) => 2,
            Self::Memory(_) => 3,
            Self::Pipe(_) => 4,
            Self::Serio(_) => 5,
            Self::Irq(_) => 6,
            Self::Time(_) => 7,
            Self::ITimer(_) => 8,
            Self::Sys(_) => 9,
            Self::ProcFull(_) => 10,
            Self::ProcRestricted(_) => 11,

            #[cfg(all(feature = "acpi", any(target_arch = "x86", target_arch = "x86_64")))]
            Self::Acpi(_) => 12,

            #[cfg(target_arch = "aarch64")]
            Self::Dtb(_) => 12,
        })
    }
    const ALL: [KernelSchemes; {core::mem::variant_count::<GlobalSchemes>() + 1}] = [
        // ignored, just ensures it starts from 1
        KernelSchemes::Global(Self::Debug(DebugScheme)),

        KernelSchemes::Global(Self::Debug(DebugScheme)),
        KernelSchemes::Global(Self::Event(EventScheme)),
        KernelSchemes::Global(Self::Memory(MemoryScheme)),
        KernelSchemes::Global(Self::Pipe(PipeScheme)),
        KernelSchemes::Global(Self::Serio(SerioScheme)),
        KernelSchemes::Global(Self::Irq(IrqScheme)),
        KernelSchemes::Global(Self::Time(TimeScheme)),
        KernelSchemes::Global(Self::ITimer(ITimerScheme)),
        KernelSchemes::Global(Self::Sys(SysScheme)),
        KernelSchemes::Global(Self::ProcFull(ProcScheme::<true>)),
        KernelSchemes::Global(Self::ProcRestricted(ProcScheme::<false>)),

        #[cfg(all(feature = "acpi", any(target_arch = "x86", target_arch = "x86_64")))]
        KernelSchemes::Global(Self::Acpi(AcpiScheme)),

        #[cfg(target_arch = "aarch64")]
        KernelSchemes::Global(Self::Dtb(DtbScheme)),
    ];
}

#[cold]
pub fn init_globals() {
    #[cfg(all(feature = "acpi", any(target_arch = "x86", target_arch = "x86_64")))]
    {
        AcpiScheme::init();
    }
    #[cfg(target_arch = "aarch64")]
    {
        DtbScheme::init();
    }
    IrqScheme::init();
}
