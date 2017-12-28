use alloc::arc::Arc;
use alloc::boxed::Box;
use alloc::{BTreeMap, Vec, VecDeque};
use core::mem;
use spin::Mutex;

use context::arch;
use context::file::FileDescriptor;
use context::memory::{Grant, Memory, SharedMemory, Tls};
use device;
use scheme::{SchemeNamespace, FileHandle};
use syscall::data::{Event, SigAction};
use syscall::flag::SIG_DFL;
use sync::{WaitMap, WaitQueue};

/// Unique identifier for a context (i.e. `pid`).
use ::core::sync::atomic::AtomicUsize;
int_like!(ContextId, AtomicContextId, usize, AtomicUsize);

/// The status of a context - used for scheduling
/// See `syscall::process::waitpid` and the `sync` module for examples of usage
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Status {
    Runnable,
    Blocked,
    Exited(usize)
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
    /// Status of context
    pub status: Status,
    /// Context running or not
    pub running: bool,
    /// CPU ID, if locked
    pub cpu_id: Option<usize>,
    /// Current system call
    pub syscall: Option<(usize, usize, usize, usize, usize, usize)>,
    /// Context is halting parent
    pub vfork: bool,
    /// Context is being waited on
    pub waitpid: Arc<WaitMap<ContextId, usize>>,
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
    /// Kernel signal backup
    pub ksig: Option<(arch::Context, Option<Box<[u8]>>, Option<Box<[u8]>>)>,
    /// Restore ksig context on next switch
    pub ksig_restore: bool,
    /// Executable image
    pub image: Vec<SharedMemory>,
    /// User heap
    pub heap: Option<SharedMemory>,
    /// User stack
    pub stack: Option<Memory>,
    /// User signal stack
    pub sigstack: Option<Memory>,
    /// User Thread local storage
    pub tls: Option<Tls>,
    /// User grants
    pub grants: Arc<Mutex<Vec<Grant>>>,
    /// The name of the context
    pub name: Arc<Mutex<Vec<u8>>>,
    /// The current working directory
    pub cwd: Arc<Mutex<Vec<u8>>>,
    /// Kernel events
    pub events: Arc<WaitQueue<Event>>,
    /// The process environment
    pub env: Arc<Mutex<BTreeMap<Box<[u8]>, Arc<Mutex<Vec<u8>>>>>>,
    /// The open files in the scheme
    pub files: Arc<Mutex<Vec<Option<FileDescriptor>>>>,
    /// Singal actions
    pub actions: Arc<Mutex<Vec<(SigAction, usize)>>>,
}

impl Context {
    pub fn new(id: ContextId) -> Context {
        Context {
            id: id,
            pgid: id,
            ppid: ContextId::from(0),
            ruid: 0,
            rgid: 0,
            rns: SchemeNamespace::from(0),
            euid: 0,
            egid: 0,
            ens: SchemeNamespace::from(0),
            status: Status::Blocked,
            running: false,
            cpu_id: None,
            syscall: None,
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
            heap: None,
            stack: None,
            sigstack: None,
            tls: None,
            grants: Arc::new(Mutex::new(Vec::new())),
            name: Arc::new(Mutex::new(Vec::new())),
            cwd: Arc::new(Mutex::new(Vec::new())),
            events: Arc::new(WaitQueue::new()),
            env: Arc::new(Mutex::new(BTreeMap::new())),
            files: Arc::new(Mutex::new(Vec::new())),
            actions: Arc::new(Mutex::new(vec![(
                SigAction {
                    sa_handler: unsafe { mem::transmute(SIG_DFL) },
                    sa_mask: [0; 2],
                    sa_flags: 0,
                },
                0
            ); 128])),
        }
    }

    /// Make a relative path absolute
    /// Given a cwd of "scheme:/path"
    /// This function will turn "foo" into "scheme:/path/foo"
    /// "/foo" will turn into "scheme:/foo"
    /// "bar:/foo" will be used directly, as it is already absolute
    pub fn canonicalize(&self, path: &[u8]) -> Vec<u8> {
        let mut canon = if path.iter().position(|&b| b == b':').is_none() {
            let cwd = self.cwd.lock();

            let mut canon = if !path.starts_with(b"/") {
                let mut c = cwd.clone();
                if ! c.ends_with(b"/") {
                    c.push(b'/');
                }
                c
            } else {
                cwd[..cwd.iter().position(|&b| b == b':').map_or(1, |i| i + 1)].to_vec()
            };

            canon.extend_from_slice(&path);
            canon
        } else {
            path.to_vec()
        };

        // NOTE: assumes the scheme does not include anything like "../" or "./"
        let mut result = {
            let parts = canon.split(|&c| c == b'/')
                .filter(|&part| part != b".")
                .rev()
                .scan(0, |nskip, part| {
                    if part == b"." {
                        Some(None)
                    } else if part == b".." {
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
                .fold(Vec::new(), |mut vec, &part| {
                    vec.extend_from_slice(part);
                    vec.push(b'/');
                    vec
                })
        };
        result.pop(); // remove extra '/'

        // replace with the root of the scheme if it's empty
        if result.is_empty() {
            let pos = canon.iter()
                            .position(|&b| b == b':')
                            .map_or(canon.len(), |p| p + 1);
            canon.truncate(pos);
            canon
        } else {
            result
        }
    }

    /// Block the context, and return true if it was runnable before being blocked
    pub fn block(&mut self) -> bool {
        if self.status == Status::Runnable {
            self.status = Status::Blocked;
            true
        } else {
            false
        }
    }

    /// Unblock context, and return true if it was blocked before being marked runnable
    pub fn unblock(&mut self) -> bool {
        if self.status == Status::Blocked {
            self.status = Status::Runnable;
            if cfg!(feature = "multi_core") {
                if let Some(cpu_id) = self.cpu_id {
                    if cpu_id != ::cpu_id() {
                        // Send IPI if not on current CPU
                        // TODO: Make this more architecture independent
                        unsafe { device::local_apic::LOCAL_APIC.set_icr(3 << 18 | 1 << 14 | 0x40) };
                    }
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
        let mut files = self.files.lock();
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
        let files = self.files.lock();
        if i.into() < files.len() {
            files[i.into()].clone()
        } else {
            None
        }
    }

    /// Insert a file with a specific handle number. This is used by dup2
    /// Return the file descriptor number or None if the slot was not empty, or i was invalid
    pub fn insert_file(&self, i: FileHandle, file: FileDescriptor) -> Option<FileHandle> {
        let mut files = self.files.lock();
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
        let mut files = self.files.lock();
        if i.into() < files.len() {
            files[i.into()].take()
        } else {
            None
        }
    }
}
