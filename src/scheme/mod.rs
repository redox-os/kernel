//! # Schemes
//! A scheme is a primitive for handling filesystem syscalls in Redox.
//! Schemes accept paths from the kernel for `open`, and file descriptors that they generate
//! are then passed for operations like `close`, `read`, `write`, etc.
//!
//! The kernel validates paths and file descriptors before they are passed to schemes,
//! also stripping the scheme identifier of paths if necessary.

use alloc::{
    boxed::Box,
    collections::BTreeMap,
    string::ToString,
    sync::Arc,
    vec::Vec,
};
use core::sync::atomic::AtomicUsize;
use spin::{Once, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::syscall::error::*;
use crate::syscall::scheme::Scheme;

#[cfg(all(feature = "acpi", target_arch = "x86_64"))]
use self::acpi::AcpiScheme;

use self::debug::DebugScheme;
use self::event::EventScheme;
use self::initfs::InitFsScheme;
use self::irq::IrqScheme;
use self::itimer::ITimerScheme;
use self::memory::MemoryScheme;
use self::pipe::PipeScheme;
use self::proc::ProcScheme;
use self::root::RootScheme;
use self::serio::SerioScheme;
use self::sys::SysScheme;
use self::time::TimeScheme;

/// When compiled with the "acpi" feature - `acpi:` - allows drivers to read a limited set of ACPI tables.
#[cfg(all(feature = "acpi", target_arch = "x86_64"))]
pub mod acpi;

/// `debug:` - provides access to serial console
pub mod debug;

/// `event:` - allows reading of `Event`s which are registered using `fevent`
pub mod event;

/// `initfs:` - a readonly filesystem used for initializing the system
pub mod initfs;

/// `irq:` - allows userspace handling of IRQs
pub mod irq;

/// `itimer:` - support for getitimer and setitimer
pub mod itimer;

/// When `disk/live:` - embedded filesystem for live disk
pub mod live;

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
int_like!(SchemeId, AtomicSchemeId, usize, AtomicUsize);

// Unique identifier for a file descriptor.
int_like!(FileHandle, AtomicFileHandle, usize, AtomicUsize);

pub struct SchemeIter<'a> {
    inner: Option<::alloc::collections::btree_map::Iter<'a, Box<str>, SchemeId>>
}

impl<'a> Iterator for SchemeIter<'a> {
    type Item = (&'a Box<str>, &'a SchemeId);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.as_mut().and_then(|iter| iter.next())
    }
}

/// Scheme list type
pub struct SchemeList {
    map: BTreeMap<SchemeId, Arc<dyn Scheme + Send + Sync>>,
    names: BTreeMap<SchemeNamespace, BTreeMap<Box<str>, SchemeId>>,
    next_ns: usize,
    next_id: usize
}

impl SchemeList {
    /// Create a new scheme list.
    pub fn new() -> Self {
        let mut list = SchemeList {
            map: BTreeMap::new(),
            names: BTreeMap::new(),
            // Scheme namespaces always start at 1. 0 is a reserved namespace, the null namespace
            next_ns: 1,
            next_id: 1
        };
        list.new_null();
        list.new_root();
        list
    }

    /// Initialize the null namespace
    fn new_null(&mut self) {
        let ns = SchemeNamespace(0);
        self.names.insert(ns, BTreeMap::new());

        //TODO: Only memory: is in the null namespace right now. It should be removed when
        //anonymous mmap's are implemented
        self.insert(ns, "memory", |_| Arc::new(MemoryScheme::new())).unwrap();
        self.insert(ns, "thisproc", |_| Arc::new(ProcScheme::restricted())).unwrap();
    }

    /// Initialize a new namespace
    fn new_ns(&mut self) -> SchemeNamespace {
        let ns = SchemeNamespace(self.next_ns);
        self.next_ns += 1;
        self.names.insert(ns, BTreeMap::new());

        self.insert(ns, "", |scheme_id| Arc::new(RootScheme::new(ns, scheme_id))).unwrap();
        self.insert(ns, "event", |_| Arc::new(EventScheme)).unwrap();
        self.insert(ns, "itimer", |_| Arc::new(ITimerScheme::new())).unwrap();
        self.insert(ns, "memory", |_| Arc::new(MemoryScheme::new())).unwrap();
        self.insert(ns, "sys", |_| Arc::new(SysScheme::new())).unwrap();
        self.insert(ns, "time", |scheme_id| Arc::new(TimeScheme::new(scheme_id))).unwrap();

        ns
    }

    /// Initialize the root namespace
    fn new_root(&mut self) {
        // Do common namespace initialization
        let ns = self.new_ns();

        // These schemes should only be available on the root
        #[cfg(all(feature = "acpi", target_arch = "x86_64"))] {
            self.insert(ns, "kernel/acpi", |scheme_id| Arc::new(AcpiScheme::new(scheme_id))).unwrap();
        }
        self.insert(ns, "debug", |scheme_id| Arc::new(DebugScheme::new(scheme_id))).unwrap();
        self.insert(ns, "initfs", |_| Arc::new(InitFsScheme)).unwrap();
        self.insert(ns, "irq", |scheme_id| Arc::new(IrqScheme::new(scheme_id))).unwrap();
        self.insert(ns, "proc", |scheme_id| Arc::new(ProcScheme::new(scheme_id))).unwrap();
        self.insert(ns, "thisproc", |_| Arc::new(ProcScheme::restricted())).unwrap();
        self.insert(ns, "serio", |scheme_id| Arc::new(SerioScheme::new(scheme_id))).unwrap();

        if let Some(scheme) = self::live::DiskScheme::new().map(Arc::new) {
            self.insert(ns, "disk/live", move |_| scheme.clone()).unwrap();
        }

        // Pipe is special and needs to be in the root namespace
        self.insert(ns, "pipe", |scheme_id| Arc::new(PipeScheme::new(scheme_id))).unwrap();
    }

    pub fn make_ns(&mut self, from: SchemeNamespace, names: &[&str]) -> Result<SchemeNamespace> {
        // Create an empty namespace
        let to = self.new_ns();

        // Copy requested scheme IDs
        for name in names.iter() {
            let id = if let Some((id, _scheme)) = self.get_name(from, name) {
                id
            } else {
                return Err(Error::new(ENODEV));
            };

            if let Some(ref mut names) = self.names.get_mut(&to) {
                assert!(names.insert(name.to_string().into_boxed_str(), id).is_none());
            } else {
                panic!("scheme namespace not found");
            }
        }

        Ok(to)
    }

    pub fn iter(&self) -> ::alloc::collections::btree_map::Iter<SchemeId, Arc<dyn Scheme + Send + Sync>> {
        self.map.iter()
    }

    pub fn iter_name(&self, ns: SchemeNamespace) -> SchemeIter {
        SchemeIter {
            inner: self.names.get(&ns).map(|names| names.iter())
        }
    }

    /// Get the nth scheme.
    pub fn get(&self, id: SchemeId) -> Option<&Arc<dyn Scheme + Send + Sync>> {
        self.map.get(&id)
    }

    pub fn get_name(&self, ns: SchemeNamespace, name: &str) -> Option<(SchemeId, &Arc<dyn Scheme + Send + Sync>)> {
        if let Some(names) = self.names.get(&ns) {
            if let Some(&id) = names.get(name) {
                return self.get(id).map(|scheme| (id, scheme));
            }
        }
        None
    }

    /// Create a new scheme.
    pub fn insert<F>(&mut self, ns: SchemeNamespace, name: &str, scheme_fn: F) -> Result<SchemeId>
        where F: Fn(SchemeId) -> Arc<dyn Scheme + Send + Sync>
    {
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

        let scheme = scheme_fn(id);

        assert!(self.map.insert(id, scheme).is_none());
        if let Some(ref mut names) = self.names.get_mut(&ns) {
            assert!(names.insert(name.to_string().into_boxed_str(), id).is_none());
        } else {
            // Nonexistent namespace, posssibly null namespace
            return Err(Error::new(ENODEV));
        }
        Ok(id)
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
