use core::{
    cmp::Ordering,
    mem,
};
use alloc::{
    boxed::Box,
    collections::VecDeque,
    sync::Arc,
    vec::Vec, borrow::Cow,
};
use spin::RwLock;

use crate::{LogicalCpuId, LogicalCpuSet};
use crate::arch::{interrupt::InterruptStack, paging::PAGE_SIZE};
use crate::common::aligned_box::AlignedBox;
use crate::common::unique::Unique;
use crate::context::{self, arch};
use crate::context::file::{FileDescriptor, FileDescription};
use crate::context::memory::AddrSpace;
use crate::ipi::{ipi, IpiKind, IpiTarget};
use crate::paging::{RmmA, RmmArch};
use crate::memory::{RaiiFrame, Frame};
use crate::scheme::{SchemeNamespace, FileHandle};
use crate::sync::WaitMap;

use crate::syscall::data::SigAction;
use crate::syscall::error::{Result, Error, EAGAIN, EINVAL, ESRCH};
use crate::syscall::flag::{SIG_DFL, SigActionFlags};

/// Unique identifier for a context (i.e. `pid`).
use ::core::sync::atomic::AtomicUsize;

use super::memory::GrantFileRef;
int_like!(ContextId, AtomicContextId, usize, AtomicUsize);

/// The status of a context - used for scheduling
/// See `syscall::process::waitpid` and the `sync` module for examples of usage
#[derive(Clone, Debug)]
pub enum Status {
    Runnable,

    // TODO: Rename to SoftBlocked and move status_reason to this variant.

    /// Not currently runnable, typically due to some blocking syscall, but it can be trivially
    /// unblocked by e.g. signals.
    Blocked,

    /// Not currently runnable, and cannot be runnable until manually unblocked, depending on what
    /// reason.
    HardBlocked { reason: HardBlockedReason },

    Stopped(usize),
    Exited(usize),
}

impl Status {
    pub fn is_runnable(&self) -> bool {
        matches!(self, Self::Runnable)
    }
    pub fn is_soft_blocked(&self) -> bool {
        matches!(self, Self::Blocked)
    }
}

#[derive(Clone, Debug)]
pub enum HardBlockedReason {
    AwaitingMmap { file_ref: GrantFileRef },
    // TODO: PageFaultOom?
    // TODO: NotYetStarted/ManuallyBlocked (when new contexts are created)
    // TODO: ptrace_stop?
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
    pub cpu_id: Option<LogicalCpuId>,
    pub cpu_time: u128,
    pub sched_affinity: LogicalCpuSet,
    pub syscall: Option<(usize, usize, usize, usize, usize, usize)>,
    // Clone fields
    //TODO: is there a faster way than allocation?
    pub name: Box<str>,
    pub files: Vec<Option<FileDescription>>,
}

impl ContextSnapshot {
    //TODO: Should this accept &mut Context to ensure name/files will not change?
    pub fn new(context: &Context) -> Self {
        let name = context.name.clone().into_owned().into_boxed_str();
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
            status: context.status.clone(),
            status_reason: context.status_reason,
            running: context.running,
            cpu_id: context.cpu_id,
            cpu_time: context.cpu_time,
            sched_affinity: context.sched_affinity,
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
    /// Current CPU ID
    pub cpu_id: Option<LogicalCpuId>,
    /// Time this context was switched to
    pub switch_time: u128,
    /// Amount of CPU time used
    pub cpu_time: u128,
    /// Scheduler CPU affinity. If set, [`cpu_id`] can except [`None`] never be anything else than
    /// this value.
    // TODO: bitmask (selection of multiple allowed CPUs)?
    pub sched_affinity: LogicalCpuSet,
    /// Current system call
    pub syscall: Option<(usize, usize, usize, usize, usize, usize)>,
    /// Head buffer to use when system call buffers are not page aligned
    // TODO: Store in user memory?
    pub syscall_head: Option<RaiiFrame>,
    /// Tail buffer to use when system call buffers are not page aligned
    // TODO: Store in user memory?
    pub syscall_tail: Option<RaiiFrame>,
    /// Context is being waited on
    pub waitpid: Arc<WaitMap<WaitpidKey, (ContextId, usize)>>,
    /// Context should handle pending signals
    pub pending: VecDeque<u8>,
    /// Context should wake up at specified time
    pub wake: Option<u128>,
    /// The architecture specific context
    pub arch: arch::Context,
    /// Kernel FX - used to store SIMD and FPU registers on context switch
    pub kfx: AlignedBox<[u8], {arch::KFX_ALIGN}>,
    /// Kernel stack
    pub kstack: Option<Box<[u8]>>,
    /// Kernel signal backup: Registers, Kernel FX, Kernel Stack, Signal number
    pub ksig: Option<(arch::Context, AlignedBox<[u8], {arch::KFX_ALIGN}>, Option<Box<[u8]>>, u8)>,
    /// Restore ksig context on next switch
    pub ksig_restore: bool,
    /// Address space containing a page table lock, and grants. Normally this will have a value,
    /// but can be None while the context is being reaped or when a new context is created but has
    /// not yet had its address space changed. Note that these are only for user mappings; kernel
    /// mappings are universal and independent on address spaces or contexts.
    pub addr_space: Option<Arc<RwLock<AddrSpace>>>,
    /// The name of the context
    // TODO: fixed size ArrayString?
    pub name: Cow<'static, str>,
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
    pub ptrace_stop: bool,
    /// A pointer to the signal stack. If this is unset, none of the sigactions can be anything
    /// else than SIG_DFL, otherwise signals will not be delivered. Userspace is responsible for
    /// setting this.
    pub sigstack: Option<usize>,
    /// An even hackier way to pass the return entry point and stack pointer to new contexts while
    /// implementing clone. Before a context has returned to userspace, its IntRegisters cannot be
    /// set since there is no interrupt stack (unless the kernel stack is copied, but that is in my
    /// opinion hackier and less efficient than this (and UB to do in Rust)).
    pub clone_entry: Option<[usize; 2]>,
    pub fmap_ret: Option<Frame>,
}

impl Context {
    pub fn new(id: ContextId) -> Result<Context> {
        let this = Context {
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
            switch_time: 0,
            cpu_time: 0,
            sched_affinity: LogicalCpuSet::all(),
            syscall: None,
            syscall_head: Some(RaiiFrame::allocate()?),
            syscall_tail: Some(RaiiFrame::allocate()?),
            waitpid: Arc::new(WaitMap::new()),
            pending: VecDeque::new(),
            wake: None,
            arch: arch::Context::new(),
            kfx: AlignedBox::<[u8], {arch::KFX_ALIGN}>::try_zeroed_slice(crate::arch::kfx_size())?,
            kstack: None,
            ksig: None,
            ksig_restore: false,
            addr_space: None,
            name: Cow::Borrowed(""),
            files: Arc::new(RwLock::new(Vec::new())),
            actions: Self::empty_actions(),
            regs: None,
            ptrace_stop: false,
            sigstack: None,
            clone_entry: None,
            fmap_ret: None,
        };
        Ok(this)
    }

    /// Block the context, and return true if it was runnable before being blocked
    pub fn block(&mut self, reason: &'static str) -> bool {
        if self.status.is_runnable() {
            self.status = Status::Blocked;
            self.status_reason = reason;
            true
        } else {
            false
        }
    }

    pub fn hard_block(&mut self, reason: HardBlockedReason) -> bool {
        if self.status.is_runnable() {
            self.status = Status::HardBlocked { reason };

            true
        } else {
            false
        }
    }

    /// Unblock context, and return true if it was blocked before being marked runnable
    pub fn unblock(&mut self) -> bool {
        if self.status.is_soft_blocked() {
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
        if i.get() < files.len() {
            files[i.get()].clone()
        } else {
            None
        }
    }

    /// Insert a file with a specific handle number. This is used by dup2
    /// Return the file descriptor number or None if the slot was not empty, or i was invalid
    pub fn insert_file(&self, i: FileHandle, file: FileDescriptor) -> Option<FileHandle> {
        let mut files = self.files.write();
        if i.get() < super::CONTEXT_MAX_FILES {
            while i.get() >= files.len() {
                files.push(None);
            }
            if files[i.get()].is_none() {
                files[i.get()] = Some(file);
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
        if i.get() < files.len() {
            files[i.get()].take()
        } else {
            None
        }
    }

    pub fn addr_space(&self) -> Result<&Arc<RwLock<AddrSpace>>> {
        self.addr_space.as_ref().ok_or(Error::new(ESRCH))
    }
    pub fn set_addr_space(&mut self, addr_space: Arc<RwLock<AddrSpace>>) -> Option<Arc<RwLock<AddrSpace>>> {
        if self.id == super::context_id() {
            unsafe { addr_space.read().table.utable.make_current(); }
        }

        self.addr_space.replace(addr_space)
    }
    pub fn empty_actions() -> Arc<RwLock<Vec<(SigAction, usize)>>> {
        Arc::new(RwLock::new(vec![(
            SigAction {
                sa_handler: unsafe { mem::transmute(SIG_DFL) },
                sa_mask: [0; 2],
                sa_flags: SigActionFlags::empty(),
            },
            0
        ); 128]))
    }
}

/// Wrapper struct for borrowing the syscall head or tail buf.
#[derive(Debug)]
pub struct BorrowedHtBuf {
    inner: Option<RaiiFrame>,
    head_and_not_tail: bool,
}
impl BorrowedHtBuf {
    pub fn head() -> Result<Self> {
        Ok(Self {
            inner: Some(context::current()?.write().syscall_head.take().ok_or(Error::new(EAGAIN))?),
            head_and_not_tail: true,
        })
    }
    pub fn tail() -> Result<Self> {
        Ok(Self {
            inner: Some(context::current()?.write().syscall_tail.take().ok_or(Error::new(EAGAIN))?),
            head_and_not_tail: false,
        })
    }
    pub fn buf(&self) -> &[u8; PAGE_SIZE] {
        unsafe { &*(RmmA::phys_to_virt(self.inner.as_ref().expect("must succeed").get().start_address()).data() as *const [u8; PAGE_SIZE]) }
    }
    pub fn buf_mut(&mut self) -> &mut [u8; PAGE_SIZE] {
        unsafe { &mut *(RmmA::phys_to_virt(self.inner.as_mut().expect("must succeed").get().start_address()).data() as *mut [u8; PAGE_SIZE]) }
    }
    pub fn frame(&self) -> Frame {
        self.inner.as_ref().expect("must succeed").get()
    }
    /*
    pub fn use_for_slice(&mut self, raw: UserSlice) -> Result<Option<&[u8]>> {
        if raw.len() > self.buf().len() {
            return Ok(None);
        }
        raw.copy_to_slice(&mut self.buf_mut()[..raw.len()])?;
        Ok(Some(&self.buf()[..raw.len()]))
    }
    pub fn use_for_string(&mut self, raw: UserSlice) -> Result<&str> {
        let slice = self.use_for_slice(raw)?.ok_or(Error::new(ENAMETOOLONG))?;
        core::str::from_utf8(slice).map_err(|_| Error::new(EINVAL))
    }
    */
    pub unsafe fn use_for_struct<T>(&mut self) -> Result<&mut T> {
        if mem::size_of::<T>() > PAGE_SIZE || mem::align_of::<T>() > PAGE_SIZE {
            return Err(Error::new(EINVAL));
        }
        self.buf_mut().fill(0_u8);
        Ok(unsafe { &mut *self.buf_mut().as_mut_ptr().cast() })
    }
}
impl Drop for BorrowedHtBuf {
    fn drop(&mut self) {
        let Ok(context) = context::current() else {
            return;
        };
        let Some(inner) = self.inner.take() else {
            return;
        };
        match context.write() {
            mut context => {
                (if self.head_and_not_tail { &mut context.syscall_head } else { &mut context.syscall_tail }).get_or_insert(inner);
            }
        }
    }
}
