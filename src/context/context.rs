use alloc::{
    boxed::Box,
    collections::VecDeque,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::{
    alloc::GlobalAlloc,
    cmp::Ordering,
    mem,
};
use spin::RwLock;

use crate::arch::{interrupt::InterruptStack, paging::PAGE_SIZE};
use crate::common::unique::Unique;
use crate::context::arch;
use crate::context::file::{FileDescriptor, FileDescription};
use crate::context::memory::{UserGrants, Memory, SharedMemory};
use crate::ipi::{ipi, IpiKind, IpiTarget};
use crate::scheme::{SchemeNamespace, FileHandle};
use crate::sync::WaitMap;

use crate::syscall::data::SigAction;
use crate::syscall::error::{Result, Error, ENOMEM};
use crate::syscall::flag::{SIG_DFL, SigActionFlags};

/// Unique identifier for a context (i.e. `pid`).
use ::core::sync::atomic::AtomicUsize;
int_like!(ContextId, AtomicContextId, usize, AtomicUsize);

/// The status of a context - used for scheduling
/// See `syscall::process::waitpid` and the `sync` module for examples of usage
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Status {
    Runnable,
    Blocked,
    Stopped(usize),
    Exited(usize),
}

#[derive(Copy, Clone, Debug)]
pub struct WaitpidKey {
    pub pid: Option<ContextId>,
    pub pgid: Option<ContextId>,
}

impl Ord for WaitpidKey {
    fn cmp(&self, other: &WaitpidKey) -> Ordering {
        // If both have pid set, compare that
        if let Some(s_pid) = self.pid {
            if let Some(o_pid) = other.pid {
                return s_pid.cmp(&o_pid);
            }
        }

        // If both have pgid set, compare that
        if let Some(s_pgid) = self.pgid {
            if let Some(o_pgid) = other.pgid {
                return s_pgid.cmp(&o_pgid);
            }
        }

        // If either has pid set, it is greater
        if self.pid.is_some() {
            return Ordering::Greater;
        }

        if other.pid.is_some() {
            return Ordering::Less;
        }

        // If either has pgid set, it is greater
        if self.pgid.is_some() {
            return Ordering::Greater;
        }

        if other.pgid.is_some() {
            return Ordering::Less;
        }

        // If all pid and pgid are None, they are equal
        Ordering::Equal
    }
}

impl PartialOrd for WaitpidKey {
    fn partial_cmp(&self, other: &WaitpidKey) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for WaitpidKey {
    fn eq(&self, other: &WaitpidKey) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for WaitpidKey {}

pub struct ContextSnapshot {
    // Copy fields
    pub id: ContextId,
    pub pgid: ContextId,
    pub ppid: ContextId,
    pub ruid: u32,
    pub rgid: u32,
    pub rns: SchemeNamespace,
    pub euid: u32,
    pub egid: u32,
    pub ens: SchemeNamespace,
    pub sigmask: [u64; 2],
    pub umask: usize,
    pub status: Status,
    pub status_reason: &'static str,
    pub running: bool,
    pub cpu_id: Option<usize>,
    pub ticks: u64,
    pub syscall: Option<(usize, usize, usize, usize, usize, usize)>,
    // Clone fields
    //TODO: is there a faster way than allocation?
    pub name: Box<str>,
    pub files: Vec<Option<FileDescription>>,
    // pub cwd: Box<[u8]>,
}

impl ContextSnapshot {
    //TODO: Should this accept &mut Context to ensure name/files will not change?
    pub fn new(context: &Context) -> Self {
        let name = context.name.read().clone();
        let mut files = Vec::new();
        for descriptor_opt in context.files.read().iter() {
            let description = if let Some(descriptor) = descriptor_opt {
                let description = descriptor.description.read();
                Some(FileDescription {
                    namespace: description.namespace,
                    scheme: description.scheme,
                    number: description.number,
                    flags: description.flags,
                })
            } else {
                None
            };
            files.push(description);
        }

        Self {
            id: context.id,
            pgid: context.pgid,
            ppid: context.ppid,
            ruid: context.ruid,
            rgid: context.rgid,
            rns: context.rns,
            euid: context.euid,
            egid: context.egid,
            ens: context.ens,
            sigmask: context.sigmask,
            umask: context.umask,
            status: context.status,
            status_reason: context.status_reason,
            running: context.running,
            cpu_id: context.cpu_id,
            ticks: context.ticks,
            syscall: context.syscall,
            name,
            files,
        }
    }
}

/// A context, which identifies either a process or a thread
#[derive(Debug)]
pub struct Context {
    /// The ID of this context
    pub id: ContextId,
    /// The group ID of this context
    pub pgid: ContextId,
    /// The ID of the parent context
    pub ppid: ContextId,
    /// The real user id
    pub ruid: u32,
    /// The real group id
    pub rgid: u32,
    /// The real namespace id
    pub rns: SchemeNamespace,
    /// The effective user id
    pub euid: u32,
    /// The effective group id
    pub egid: u32,
    /// The effective namespace id
    pub ens: SchemeNamespace,
    /// Signal mask
    pub sigmask: [u64; 2],
    /// Process umask
    pub umask: usize,
    /// Status of context
    pub status: Status,
    pub status_reason: &'static str,
    /// Context running or not
    pub running: bool,
    /// CPU ID, if locked
    pub cpu_id: Option<usize>,
    /// Number of timer ticks executed
    pub ticks: u64,
    /// Current system call
    pub syscall: Option<(usize, usize, usize, usize, usize, usize)>,
    /// Head buffer to use when system call buffers are not page aligned
    pub syscall_head: AlignedBox<[u8; PAGE_SIZE], PAGE_SIZE>,
    /// Tail buffer to use when system call buffers are not page aligned
    pub syscall_tail: AlignedBox<[u8; PAGE_SIZE], PAGE_SIZE>,
    /// Context is halting parent
    pub vfork: bool,
    /// Context is being waited on
    pub waitpid: Arc<WaitMap<WaitpidKey, (ContextId, usize)>>,
    /// Context should handle pending signals
    pub pending: VecDeque<u8>,
    /// Context should wake up at specified time
    pub wake: Option<(u64, u64)>,
    /// The architecture specific context
    pub arch: arch::Context,
    /// Kernel FX - used to store SIMD and FPU registers on context switch
    pub kfx: Option<Box<[u8]>>,
    /// Kernel stack
    pub kstack: Option<Box<[u8]>>,
    /// Kernel signal backup: Registers, Kernel FX, Kernel Stack, Signal number
    pub ksig: Option<(arch::Context, Option<Box<[u8]>>, Option<Box<[u8]>>, u8)>,
    /// Restore ksig context on next switch
    pub ksig_restore: bool,
    /// Executable image
    pub image: Vec<SharedMemory>,
    /// User stack
    pub stack: Option<SharedMemory>,
    /// User signal stack
    pub sigstack: Option<Memory>,
    /// User grants
    pub grants: Arc<RwLock<UserGrants>>,
    /// The name of the context
    pub name: Arc<RwLock<Box<str>>>,
    /// The current working directory
    pub cwd: Arc<RwLock<String>>,
    /// The open files in the scheme
    pub files: Arc<RwLock<Vec<Option<FileDescriptor>>>>,
    /// Signal actions
    pub actions: Arc<RwLock<Vec<(SigAction, usize)>>>,
    /// The pointer to the user-space registers, saved after certain
    /// interrupts. This pointer is somewhere inside kstack, and the
    /// kstack address at the time of creation is the first element in
    /// this tuple.
    pub regs: Option<(usize, Unique<InterruptStack>)>,
    /// A somewhat hacky way to initially stop a context when creating
    /// a new instance of the proc: scheme, entirely separate from
    /// signals or any other way to restart a process.
    pub ptrace_stop: bool
}

// Necessary because GlobalAlloc::dealloc requires the layout to be the same, and therefore Box
// cannot be used for increased alignment directly.
// TODO: move to common?
pub struct AlignedBox<T, const ALIGN: usize> {
    inner: Unique<T>,
}
pub unsafe trait ValidForZero {}
unsafe impl<const N: usize> ValidForZero for [u8; N] {}

impl<T, const ALIGN: usize> AlignedBox<T, ALIGN> {
    const LAYOUT: core::alloc::Layout = {
        const fn max(a: usize, b: usize) -> usize {
            if a > b { a } else { b }
        }

        match core::alloc::Layout::from_size_align(mem::size_of::<T>(), max(mem::align_of::<T>(), ALIGN)) {
            Ok(l) => l,
            Err(_) => panic!("layout validation failed at compile time"),
        }
    };
    #[inline(always)]
    pub fn try_zeroed() -> Result<Self>
    where
        T: ValidForZero,
    {
        Ok(unsafe {
            let ptr = crate::ALLOCATOR.alloc_zeroed(Self::LAYOUT);
            if ptr.is_null() {
                return Err(Error::new(ENOMEM))?;
            }
            Self {
                inner: Unique::new_unchecked(ptr.cast()),
            }
        })
    }
}

impl<T, const ALIGN: usize> core::fmt::Debug for AlignedBox<T, ALIGN> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "[aligned box at {:p}, size {} alignment {}]", self.inner.as_ptr(), mem::size_of::<T>(), mem::align_of::<T>())
    }
}
impl<T, const ALIGN: usize> Drop for AlignedBox<T, ALIGN> {
    fn drop(&mut self) {
        unsafe {
            core::ptr::drop_in_place(self.inner.as_ptr());
            crate::ALLOCATOR.dealloc(self.inner.as_ptr().cast(), Self::LAYOUT);
        }
    }
}

impl Context {
    pub fn new(id: ContextId) -> Result<Context> {
        let syscall_head = AlignedBox::try_zeroed()?;
        let syscall_tail = AlignedBox::try_zeroed()?;

        Ok(Context {
            id,
            pgid: id,
            ppid: ContextId::from(0),
            ruid: 0,
            rgid: 0,
            rns: SchemeNamespace::from(0),
            euid: 0,
            egid: 0,
            ens: SchemeNamespace::from(0),
            sigmask: [0; 2],
            umask: 0o022,
            status: Status::Blocked,
            status_reason: "",
            running: false,
            cpu_id: None,
            ticks: 0,
            syscall: None,
            syscall_head,
            syscall_tail,
            vfork: false,
            waitpid: Arc::new(WaitMap::new()),
            pending: VecDeque::new(),
            wake: None,
            arch: arch::Context::new(),
            kfx: None,
            kstack: None,
            ksig: None,
            ksig_restore: false,
            image: Vec::new(),
            stack: None,
            sigstack: None,
            grants: Arc::new(RwLock::new(UserGrants::default())),
            name: Arc::new(RwLock::new(String::new().into_boxed_str())),
            cwd: Arc::new(RwLock::new(String::new())),
            files: Arc::new(RwLock::new(Vec::new())),
            actions: Arc::new(RwLock::new(vec![(
                SigAction {
                    sa_handler: unsafe { mem::transmute(SIG_DFL) },
                    sa_mask: [0; 2],
                    sa_flags: SigActionFlags::empty(),
                },
                0
            ); 128])),
            regs: None,
            ptrace_stop: false
        })
    }

    /// Make a relative path absolute
    /// Given a cwd of "scheme:/path"
    /// This function will turn "foo" into "scheme:/path/foo"
    /// "/foo" will turn into "scheme:/foo"
    /// "bar:/foo" will be used directly, as it is already absolute
    pub fn canonicalize(&self, path: &str) -> String {
        let mut canon = if path.find(':').is_none() {
            let cwd = self.cwd.read();

            let mut canon = if !path.starts_with('/') {
                let mut c = cwd.clone();
                if ! c.ends_with('/') {
                    c.push('/');
                }
                c
            } else {
                cwd[..cwd.find(':').map_or(1, |i| i + 1)].to_string()
            };

            canon.push_str(&path);
            canon
        } else {
            path.to_string()
        };

        // NOTE: assumes the scheme does not include anything like "../" or "./"
        let mut result = {
            let parts = canon.split('/')
                .rev()
                .scan(0, |nskip, part| {
                    if part == "." {
                        Some(None)
                    } else if part == ".." {
                        *nskip += 1;
                        Some(None)
                    } else if *nskip > 0 {
                            *nskip -= 1;
                            Some(None)
                    } else {
                        Some(Some(part))
                    }
                })
                .filter_map(|x| x)
                .filter(|x| !x.is_empty())
                .collect::<Vec<_>>();
            parts
                .iter()
                .rev()
                .fold(String::new(), |mut string, &part| {
                    string.push_str(part);
                    string.push('/');
                    string
                })
        };
        result.pop(); // remove extra '/'

        // replace with the root of the scheme if it's empty
        if result.is_empty() {
            let pos = canon.find(':')
                            .map_or(canon.len(), |p| p + 1);
            canon.truncate(pos);
            canon
        } else {
            result
        }
    }

    /// Block the context, and return true if it was runnable before being blocked
    pub fn block(&mut self, reason: &'static str) -> bool {
        if self.status == Status::Runnable {
            self.status = Status::Blocked;
            self.status_reason = reason;
            true
        } else {
            false
        }
    }

    /// Unblock context, and return true if it was blocked before being marked runnable
    pub fn unblock(&mut self) -> bool {
        if self.status == Status::Blocked {
            self.status = Status::Runnable;
            self.status_reason = "";

            if let Some(cpu_id) = self.cpu_id {
               if cpu_id != crate::cpu_id() {
                    // Send IPI if not on current CPU
                    ipi(IpiKind::Wakeup, IpiTarget::Other);
               }
            }

            true
        } else {
            false
        }
    }

    /// Add a file to the lowest available slot.
    /// Return the file descriptor number or None if no slot was found
    pub fn add_file(&self, file: FileDescriptor) -> Option<FileHandle> {
        self.add_file_min(file, 0)
    }

    /// Add a file to the lowest available slot greater than or equal to min.
    /// Return the file descriptor number or None if no slot was found
    pub fn add_file_min(&self, file: FileDescriptor, min: usize) -> Option<FileHandle> {
        let mut files = self.files.write();
        for (i, file_option) in files.iter_mut().enumerate() {
            if file_option.is_none() && i >= min {
                *file_option = Some(file);
                return Some(FileHandle::from(i));
            }
        }
        let len = files.len();
        if len < super::CONTEXT_MAX_FILES {
            if len >= min {
                files.push(Some(file));
                Some(FileHandle::from(len))
            } else {
                drop(files);
                self.insert_file(FileHandle::from(min), file)
            }
        } else {
            None
        }
    }

    /// Get a file
    pub fn get_file(&self, i: FileHandle) -> Option<FileDescriptor> {
        let files = self.files.read();
        if i.into() < files.len() {
            files[i.into()].clone()
        } else {
            None
        }
    }

    /// Insert a file with a specific handle number. This is used by dup2
    /// Return the file descriptor number or None if the slot was not empty, or i was invalid
    pub fn insert_file(&self, i: FileHandle, file: FileDescriptor) -> Option<FileHandle> {
        let mut files = self.files.write();
        if i.into() < super::CONTEXT_MAX_FILES {
            while i.into() >= files.len() {
                files.push(None);
            }
            if files[i.into()].is_none() {
                files[i.into()] = Some(file);
                Some(i)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Remove a file
    // TODO: adjust files vector to smaller size if possible
    pub fn remove_file(&self, i: FileHandle) -> Option<FileDescriptor> {
        let mut files = self.files.write();
        if i.into() < files.len() {
            files[i.into()].take()
        } else {
            None
        }
    }
}
