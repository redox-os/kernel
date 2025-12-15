use alloc::{collections::BTreeSet, sync::Arc, vec::Vec};
use arrayvec::ArrayString;
use core::{
    mem::{self, size_of},
    num::NonZeroUsize,
    sync::atomic::{AtomicU32, Ordering},
};
use spin::RwLock;
use syscall::{SigProcControl, Sigcontrol, UPPER_FDTBL_TAG};

use crate::{
    arch::{interrupt::InterruptStack, paging::PAGE_SIZE},
    common::aligned_box::AlignedBox,
    context::{self, arch, file::FileDescriptor},
    cpu_set::{LogicalCpuId, LogicalCpuSet},
    cpu_stats,
    ipi::{ipi, IpiKind, IpiTarget},
    memory::{allocate_p2frame, deallocate_p2frame, Enomem, Frame, RaiiFrame},
    paging::{RmmA, RmmArch},
    percpu::PercpuBlock,
    scheme::{CallerCtx, FileHandle, SchemeId, SchemeNamespace},
    sync::CleanLockToken,
};

use crate::syscall::error::{Error, Result, EAGAIN, EBADF, EEXIST, EINVAL, EMFILE, ESRCH};

use super::{
    empty_cr3,
    memory::{AddrSpaceWrapper, GrantFileRef},
};

/// The status of a context - used for scheduling
#[derive(Clone, Debug)]
pub enum Status {
    Runnable,

    // TODO: Rename to SoftBlocked and move status_reason to this variant.
    /// Not currently runnable, typically due to some blocking syscall, but it can be trivially
    /// unblocked by e.g. signals.
    Blocked,

    /// Not currently runnable, and cannot be runnable until manually unblocked, depending on what
    /// reason.
    HardBlocked {
        reason: HardBlockedReason,
    },
    Dead {
        excp: Option<syscall::Exception>,
    },
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
    /// "SIGSTOP", only procmgr is allowed to switch contexts this state
    Stopped,
    AwaitingMmap {
        file_ref: GrantFileRef,
    },
    // TODO: PageFaultOom?
    NotYetStarted,
}

const CONTEXT_NAME_CAPAC: usize = 32;

#[derive(Debug)]
pub enum SyscallFrame {
    Free(RaiiFrame),
    // The field is used by the consistency checker of the kernel debugger
    Used { _frame: Frame },
    Dummy,
}

/// A context, which is typically mapped to a userspace thread
#[derive(Debug)]
pub struct Context {
    pub debug_id: u32,
    /// Signal handler
    pub sig: Option<SignalState>,
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
    pub sched_affinity: LogicalCpuSet,
    /// Keeps track of whether this context is currently handling a syscall. Only up-to-date when
    /// not running.
    pub inside_syscall: bool,

    #[cfg(feature = "syscall_debug")]
    pub syscall_debug_info: crate::syscall::debug::SyscallDebugInfo,

    /// Head buffer to use when system call buffers are not page aligned
    // TODO: Store in user memory?
    pub syscall_head: SyscallFrame,
    /// Tail buffer to use when system call buffers are not page aligned
    // TODO: Store in user memory?
    pub syscall_tail: SyscallFrame,
    /// Context should wake up at specified time
    pub wake: Option<u128>,
    /// The architecture specific context
    pub arch: arch::Context,
    /// Kernel FX - used to store SIMD and FPU registers on context switch
    pub kfx: AlignedBox<[u8], { arch::KFX_ALIGN }>,
    /// Kernel stack, if located on the heap.
    pub kstack: Option<Kstack>,
    /// Address space containing a page table lock, and grants. Normally this will have a value,
    /// but can be None while the context is being reaped or when a new context is created but has
    /// not yet had its address space changed. Note that these are only for user mappings; kernel
    /// mappings are universal and independent on address spaces or contexts.
    pub addr_space: Option<Arc<AddrSpaceWrapper>>,
    /// The name of the context
    pub name: ArrayString<CONTEXT_NAME_CAPAC>,
    /// The open files in the scheme
    pub files: Arc<RwLock<FdTbl>>,
    /// All contexts except kmain will primarily live in userspace, and enter the kernel only when
    /// interrupts or syscalls occur. This flag is set for all contexts but kmain.
    pub userspace: bool,
    pub being_sigkilled: bool,
    pub fmap_ret: Option<Frame>,

    // TODO: id can reappear after wraparound?
    pub owner_proc_id: Option<NonZeroUsize>,

    // TODO: Temporary replacement for existing kernel logic, replace with capabilities!
    pub ens: SchemeNamespace,
    pub euid: u32,
    pub egid: u32,
    pub pid: usize,

    // See [`PreemptGuard`]
    //
    // When > 0, preemption is disabled.
    pub(super) preempt_locks: usize,
}

#[derive(Debug)]
pub struct SignalState {
    /// Offset to jump to when a signal is received.
    pub user_handler: NonZeroUsize,
    /// Offset to jump to when a program fault occurs. If None, the context is sigkilled.
    pub excp_handler: Option<NonZeroUsize>,

    /// Signal control pages, shared memory
    pub thread_control: RaiiFrame,
    pub proc_control: RaiiFrame,
    /// Offset within the control pages of respective word-aligned structs.
    pub threadctl_off: u16,
    pub procctl_off: u16,
}

impl Context {
    pub fn new(owner_proc_id: Option<NonZeroUsize>) -> Result<Context> {
        static DEBUG_ID: AtomicU32 = AtomicU32::new(1);
        let this = Self {
            debug_id: DEBUG_ID.fetch_add(1, Ordering::Relaxed),
            sig: None,
            status: Status::HardBlocked {
                reason: HardBlockedReason::NotYetStarted,
            },
            status_reason: "",
            running: false,
            cpu_id: None,
            switch_time: 0,
            cpu_time: 0,
            sched_affinity: LogicalCpuSet::all(),
            inside_syscall: false,
            syscall_head: SyscallFrame::Free(RaiiFrame::allocate()?),
            syscall_tail: SyscallFrame::Free(RaiiFrame::allocate()?),
            wake: None,
            arch: arch::Context::new(),
            kfx: AlignedBox::<[u8], { arch::KFX_ALIGN }>::try_zeroed_slice(crate::arch::kfx_size())?,
            kstack: None,
            addr_space: None,
            name: ArrayString::new(),
            files: Arc::new(RwLock::new(FdTbl::new())),
            userspace: false,
            fmap_ret: None,
            being_sigkilled: false,
            owner_proc_id,

            ens: 0.into(),
            euid: 0,
            egid: 0,
            pid: 0,

            #[cfg(feature = "syscall_debug")]
            syscall_debug_info: crate::syscall::debug::SyscallDebugInfo::default(),

            preempt_locks: 0,
        };
        cpu_stats::add_context();
        Ok(this)
    }

    pub fn is_preemptable(&self) -> bool {
        self.preempt_locks == 0
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
        if self.unblock_no_ipi() {
            // TODO: Only send IPI if currently running?
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

    /// Unblock context without IPI, and return true if it was blocked before being marked runnable
    pub fn unblock_no_ipi(&mut self) -> bool {
        if self.status.is_soft_blocked() {
            self.status = Status::Runnable;
            self.status_reason = "";

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
        self.files.write().add_file_min(file, min)
    }

    /// Bulk-add multiple files to the POSIX file table
    pub fn bulk_add_files_posix(
        &self,
        files_to_add: Vec<FileDescriptor>,
    ) -> Option<Vec<FileHandle>> {
        self.files.write().bulk_add_files_posix(files_to_add)
    }

    /// Bulk-insert multiple files into to the upper file table contiguously
    pub fn bulk_insert_files_upper(
        &self,
        files_to_insert: Vec<FileDescriptor>,
    ) -> Option<Vec<FileHandle>> {
        self.files.write().bulk_insert_files_upper(files_to_insert)
    }

    /// Bulk-insert multiple files into to the upper file table manually
    pub fn bulk_insert_files_upper_manual(
        &self,
        files_to_insert: Vec<FileDescriptor>,
        handles: &[FileHandle],
    ) -> Result<()> {
        self.files
            .write()
            .bulk_insert_files_upper_manual(files_to_insert, handles)
    }

    /// Get a file
    pub fn get_file(&self, i: FileHandle) -> Option<FileDescriptor> {
        self.files.read().get_file(i)
    }

    /// Bulk get files
    pub fn bulk_get_files(&self, handles: &[FileHandle]) -> Result<Vec<FileDescriptor>> {
        self.files.read().bulk_get_files(handles)
    }

    /// Insert a file with a specific handle number. This is used by dup2
    /// Return the file descriptor number or None if the slot was not empty, or i was invalid
    pub fn insert_file(&self, i: FileHandle, file: FileDescriptor) -> Option<FileHandle> {
        self.files.write().insert_file(i, file)
    }

    /// Remove a file
    // TODO: adjust files vector to smaller size if possible
    pub fn remove_file(&self, i: FileHandle) -> Option<FileDescriptor> {
        self.files.write().remove_file(i)
    }

    /// Bulk remove files
    pub fn bulk_remove_files(&self, handles: &[FileHandle]) -> Result<Vec<FileDescriptor>> {
        self.files.write().bulk_remove_files(handles)
    }

    pub fn is_current_context(&self) -> bool {
        self.running && self.cpu_id == Some(crate::cpu_id())
    }

    pub fn addr_space(&self) -> Result<&Arc<AddrSpaceWrapper>> {
        self.addr_space.as_ref().ok_or(Error::new(ESRCH))
    }
    pub fn set_addr_space(
        &mut self,
        addr_space: Option<Arc<AddrSpaceWrapper>>,
    ) -> Option<Arc<AddrSpaceWrapper>> {
        if let (Some(old), Some(new)) = (&self.addr_space, &addr_space)
            && Arc::ptr_eq(old, new)
        {
            return addr_space;
        };

        if self.is_current_context() {
            // TODO: Share more code with context::arch::switch_to.
            let this_percpu = PercpuBlock::current();

            if let Some(ref prev_addrsp) = self.addr_space {
                assert!(Arc::ptr_eq(
                    this_percpu.current_addrsp.borrow().as_ref().unwrap(),
                    prev_addrsp
                ));
                prev_addrsp
                    .acquire_read()
                    .used_by
                    .atomic_clear(this_percpu.cpu_id);
            }

            let _old_addrsp = core::mem::replace(
                &mut *this_percpu.current_addrsp.borrow_mut(),
                addr_space.clone(),
            );

            match addr_space {
                Some(ref new) => {
                    let new_addrsp = new.acquire_read();
                    new_addrsp.used_by.atomic_set(this_percpu.cpu_id);

                    unsafe {
                        new_addrsp.table.utable.make_current();
                    }
                }
                _ => unsafe {
                    crate::paging::RmmA::set_table(rmm::TableKind::User, empty_cr3());
                },
            }
        } else {
            assert!(!self.running);
        }

        core::mem::replace(&mut self.addr_space, addr_space)
    }

    fn can_access_regs(&self) -> bool {
        self.userspace
    }

    pub fn regs(&self) -> Option<&InterruptStack> {
        if !self.can_access_regs() {
            return None;
        }
        let kstack = self.kstack.as_ref()?;
        Some(unsafe { &*kstack.initial_top().sub(size_of::<InterruptStack>()).cast() })
    }
    pub fn regs_mut(&mut self) -> Option<&mut InterruptStack> {
        if !self.can_access_regs() {
            return None;
        }
        let kstack = self.kstack.as_ref()?;
        Some(unsafe { &mut *kstack.initial_top().sub(size_of::<InterruptStack>()).cast() })
    }
    pub fn sigcontrol(&mut self) -> Option<(&Sigcontrol, &SigProcControl, &mut SignalState)> {
        Some(Self::sigcontrol_raw(self.sig.as_mut()?))
    }
    pub fn sigcontrol_raw(
        sig: &mut SignalState,
    ) -> (&Sigcontrol, &SigProcControl, &mut SignalState) {
        let check = |off| {
            assert_eq!(usize::from(off) % mem::align_of::<usize>(), 0);
            assert!(usize::from(off).saturating_add(mem::size_of::<Sigcontrol>()) < PAGE_SIZE);
        };
        check(sig.procctl_off);
        check(sig.threadctl_off);

        let for_thread = unsafe {
            &*(RmmA::phys_to_virt(sig.thread_control.get().base()).data() as *const Sigcontrol)
                .byte_add(usize::from(sig.threadctl_off))
        };
        let for_proc = unsafe {
            &*(RmmA::phys_to_virt(sig.proc_control.get().base()).data() as *const SigProcControl)
                .byte_add(usize::from(sig.procctl_off))
        };

        (for_thread, for_proc, sig)
    }
    pub fn caller_ctx(&self) -> CallerCtx {
        CallerCtx {
            uid: self.euid,
            gid: self.egid,
            pid: self.pid,
        }
    }
}

/// Wrapper struct for borrowing the syscall head or tail buf.
#[derive(Debug)]
pub struct BorrowedHtBuf {
    inner: Option<RaiiFrame>,
    head_and_not_tail: bool,
}
impl BorrowedHtBuf {
    pub fn head(token: &mut CleanLockToken) -> Result<Self> {
        let current = context::current();
        let frame = &mut current.write(token.token()).syscall_head;
        match mem::replace(frame, SyscallFrame::Dummy) {
            SyscallFrame::Free(free_frame) => {
                *frame = SyscallFrame::Used {
                    _frame: free_frame.get(),
                };
                Ok(Self {
                    inner: Some(free_frame),
                    head_and_not_tail: true,
                })
            }
            SyscallFrame::Used { .. } | SyscallFrame::Dummy => Err(Error::new(EAGAIN)),
        }
    }
    pub fn tail(token: &mut CleanLockToken) -> Result<Self> {
        let current = context::current();
        let frame = &mut current.write(token.token()).syscall_tail;
        match mem::replace(frame, SyscallFrame::Dummy) {
            SyscallFrame::Free(free_frame) => {
                *frame = SyscallFrame::Used {
                    _frame: free_frame.get(),
                };
                Ok(Self {
                    inner: Some(free_frame),
                    head_and_not_tail: false,
                })
            }
            SyscallFrame::Used { .. } | SyscallFrame::Dummy => Err(Error::new(EAGAIN)),
        }
    }
    pub fn buf(&self) -> &[u8; PAGE_SIZE] {
        unsafe {
            &*(RmmA::phys_to_virt(self.inner.as_ref().expect("must succeed").get().base()).data()
                as *const [u8; PAGE_SIZE])
        }
    }
    pub fn buf_mut(&mut self) -> &mut [u8; PAGE_SIZE] {
        unsafe {
            &mut *(RmmA::phys_to_virt(self.inner.as_mut().expect("must succeed").get().base())
                .data() as *mut [u8; PAGE_SIZE])
        }
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
    pub unsafe fn use_for_struct<T>(&mut self) -> Result<&mut T> {
        if mem::size_of::<T>() > PAGE_SIZE || mem::align_of::<T>() > PAGE_SIZE {
            return Err(Error::new(EINVAL));
        }
        self.buf_mut().fill(0_u8);
        Ok(unsafe { &mut *self.buf_mut().as_mut_ptr().cast() })
    }
    */
}
impl Drop for BorrowedHtBuf {
    fn drop(&mut self) {
        let context = context::current();

        let Some(inner) = self.inner.take() else {
            return;
        };
        //TODO: do not allow drop so lock token can be passed in
        let mut token = unsafe { CleanLockToken::new() };
        let mut context = context.write(token.token());
        {
            *(if self.head_and_not_tail {
                &mut context.syscall_head
            } else {
                &mut context.syscall_tail
            }) = SyscallFrame::Free(inner);
        }
    }
}

pub struct Kstack {
    /// naturally aligned, order 4
    base: Frame,
}
impl Kstack {
    pub fn new() -> Result<Self, Enomem> {
        Ok(Self {
            base: allocate_p2frame(4).ok_or(Enomem)?,
        })
    }
    pub fn initial_top(&self) -> *mut u8 {
        unsafe { (RmmA::phys_to_virt(self.base.base()).data() as *mut u8).add(PAGE_SIZE << 4) }
    }
    pub fn len(&self) -> usize {
        PAGE_SIZE << 4
    }
}

impl Drop for Kstack {
    fn drop(&mut self) {
        unsafe { deallocate_p2frame(self.base, 4) }
    }
}
impl core::fmt::Debug for Kstack {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "[kstack at {:?}]", self.base)
    }
}

#[derive(Clone, Debug, Default)]
pub struct FdTbl {
    pub posix_fdtbl: Vec<Option<FileDescriptor>>,
    pub upper_fdtbl: Vec<Option<FileDescriptor>>,
    active_count: usize,
}

impl FdTbl {
    pub fn new() -> Self {
        Self {
            posix_fdtbl: Vec::new(),
            upper_fdtbl: Vec::new(),
            active_count: 0,
        }
    }

    fn strip_tags(index: usize) -> usize {
        index & !UPPER_FDTBL_TAG
    }

    fn select_fdtbl(&self, index: usize) -> (&Vec<Option<FileDescriptor>>, usize) {
        if index & UPPER_FDTBL_TAG == 0 {
            (&self.posix_fdtbl, index)
        } else {
            (&self.upper_fdtbl, Self::strip_tags(index))
        }
    }

    fn select_fdtbl_mut(&mut self, index: usize) -> (&mut Vec<Option<FileDescriptor>>, usize) {
        if index & UPPER_FDTBL_TAG == 0 {
            (&mut self.posix_fdtbl, index)
        } else {
            (&mut self.upper_fdtbl, Self::strip_tags(index))
        }
    }

    fn validate_handles(&self, handles: &[FileHandle]) -> Result<()> {
        let mut checked_handles = BTreeSet::new();
        for i in handles {
            let index = i.get();
            if Self::strip_tags(index) >= super::CONTEXT_MAX_FILES {
                return Err(Error::new(EMFILE));
            }
            if !checked_handles.insert(index) {
                return Err(Error::new(EBADF)); // Duplicate handle
            }
            if !matches!(self.get(index), Some(Some(_))) {
                return Err(Error::new(EBADF));
            }
        }

        Ok(())
    }

    fn validate_free_slots(&self, handles: &[FileHandle]) -> Result<()> {
        let mut checked_slots = BTreeSet::new();
        for i in handles {
            let index = i.get();
            if Self::strip_tags(index) >= super::CONTEXT_MAX_FILES {
                return Err(Error::new(EMFILE));
            }
            if !checked_slots.insert(index) {
                return Err(Error::new(EINVAL)); // Duplicate slots
            }
            if matches!(self.get(index), Some(Some(_))) {
                return Err(Error::new(EEXIST));
            }
        }

        Ok(())
    }

    pub fn add_file_min(&mut self, file: FileDescriptor, min: usize) -> Option<FileHandle> {
        if self.active_count >= super::CONTEXT_MAX_FILES {
            return None;
        }

        let tag = min & UPPER_FDTBL_TAG;

        let (fdtbl, min) = self.select_fdtbl_mut(min);

        // Find the first empty slot in the posix_fdtbl starting from `min`.
        if let Some((pos, slot)) = fdtbl
            .iter_mut()
            .enumerate()
            .skip(min)
            .find(|(_, slot)| slot.is_none())
        {
            *slot = Some(file);
            self.active_count += 1;
            return Some(FileHandle::from(pos | tag));
        };

        let len = fdtbl.len();

        // If no empty slot was found, we need to allocate a new slot.
        if len >= min {
            fdtbl.push(Some(file));
            self.active_count += 1;
            Some(FileHandle::from(len | tag))
        } else {
            self.insert_file(FileHandle::from(min | tag), file)
        }
    }

    fn bulk_add_files_posix(
        &mut self,
        files_to_add: Vec<FileDescriptor>,
    ) -> Option<Vec<FileHandle>> {
        let count = files_to_add.len();
        if count == 0 {
            return Some(Vec::new());
        }
        if self.active_count + count > super::CONTEXT_MAX_FILES {
            return None;
        }

        let handles = self.find_free_posix_slots(count);
        let max_index = handles[count - 1].get();
        if self.posix_fdtbl.len() <= max_index {
            // Resize the posix_fdtbl to accommodate the new files.
            self.posix_fdtbl.resize(max_index + 1, None);
        }

        for (&handle, file) in handles.iter().zip(files_to_add) {
            let index = handle.get();
            self.posix_fdtbl[index] = Some(file);
        }

        self.active_count += count;
        Some(handles)
    }

    fn insert_file(&mut self, i: FileHandle, file: FileDescriptor) -> Option<FileHandle> {
        if self.active_count >= super::CONTEXT_MAX_FILES {
            return None;
        }
        let index = i.get();
        let (fdtbl, real_index) = self.select_fdtbl_mut(index);

        if real_index >= super::CONTEXT_MAX_FILES {
            return None;
        }

        if real_index >= fdtbl.len() {
            fdtbl.resize_with(real_index + 1, || None);
        }

        if let Some(slot @ None) = fdtbl.get_mut(real_index) {
            *slot = Some(file);
            self.active_count += 1;
            Some(i)
        } else {
            None
        }
    }

    fn bulk_insert_files_upper(
        &mut self,
        files_to_insert: Vec<FileDescriptor>,
    ) -> Option<Vec<FileHandle>> {
        let count = files_to_insert.len();
        if count == 0 {
            return Some(Vec::new());
        }
        if self.active_count + count > super::CONTEXT_MAX_FILES {
            return None;
        }

        let index = Self::strip_tags(self.find_free_upper_block(count).get());
        let mut handles = Vec::with_capacity(count);
        for (i, file) in files_to_insert.into_iter().enumerate() {
            let current_index = index + i;
            self.upper_fdtbl[current_index] = Some(file);
            handles.push(FileHandle::from(current_index | UPPER_FDTBL_TAG));
        }

        self.active_count += count;
        Some(handles)
    }

    fn bulk_insert_files_upper_manual(
        &mut self,
        files_to_insert: Vec<FileDescriptor>,
        handles: &[FileHandle],
    ) -> Result<()> {
        if handles.len() != files_to_insert.len() {
            return Err(Error::new(EINVAL));
        }
        let count = files_to_insert.len();
        if count == 0 {
            return Ok(());
        }
        if self.active_count + count > super::CONTEXT_MAX_FILES {
            return Err(Error::new(EMFILE));
        }
        self.validate_free_slots(handles)?;

        let max_index = handles
            .iter()
            .map(|h| Self::strip_tags(h.get()))
            .max()
            .unwrap_or(0);
        if self.upper_fdtbl.len() <= max_index {
            self.upper_fdtbl.resize_with(max_index + 1, || None);
        }
        for (file, &handle) in files_to_insert.into_iter().zip(handles) {
            let index = Self::strip_tags(handle.get());
            self.upper_fdtbl[index] = Some(file);
        }

        self.active_count += count;
        Ok(())
    }

    pub fn get(&self, index: usize) -> Option<&Option<FileDescriptor>> {
        let (fdtbl, real_index) = self.select_fdtbl(index);

        fdtbl.get(real_index)
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut Option<FileDescriptor>> {
        let (fdtbl, real_index) = self.select_fdtbl_mut(index);

        fdtbl.get_mut(real_index)
    }

    pub fn get_file(&self, i: FileHandle) -> Option<FileDescriptor> {
        self.get(i.get()).cloned().flatten()
    }

    fn bulk_get_files(&self, handles: &[FileHandle]) -> Result<Vec<FileDescriptor>> {
        // Validate that all handles are valid before proceeding to avoid partial results.
        self.validate_handles(handles)?;

        let files = handles
            .iter()
            .map(|&i| self.get_file(i).expect("File should exist"))
            .collect();

        Ok(files)
    }

    // TODO: Faster, cleaner mechanism to get descriptor
    // Find a file descriptor by scheme id and number.
    pub fn find_by_scheme(
        &self,
        scheme_id: SchemeId,
        scheme_number: usize,
    ) -> Result<FileDescriptor> {
        self.iter()
            .flatten()
            .find(|&context_fd| {
                let desc = context_fd.description.read();
                desc.scheme == scheme_id && desc.number == scheme_number
            })
            .cloned()
            .ok_or(Error::new(EBADF))
    }

    fn remove_file(&mut self, i: FileHandle) -> Option<FileDescriptor> {
        let index = i.get();
        let (fdtbl, real_index) = self.select_fdtbl_mut(index);

        let removed_file_opt = fdtbl.get_mut(real_index).and_then(|opt| opt.take());
        if removed_file_opt.is_some() {
            self.active_count -= 1;
        }

        removed_file_opt
    }

    fn bulk_remove_files(&mut self, handles: &[FileHandle]) -> Result<Vec<FileDescriptor>> {
        // Validate that all handles are valid before proceeding to avoid partial results.
        self.validate_handles(handles)?;

        let files = handles
            .iter()
            .map(|&i| self.remove_file(i).expect("File should exist"))
            .collect();

        Ok(files)
    }

    fn find_free_posix_slots(&self, count: usize) -> Vec<FileHandle> {
        let mut free_slots = Vec::with_capacity(count);

        for (i, slot) in self.posix_fdtbl.iter().enumerate() {
            if slot.is_none() {
                free_slots.push(FileHandle::from(i));
                if free_slots.len() == count {
                    return free_slots;
                }
            }
        }

        let mut current_len = self.posix_fdtbl.len();
        while free_slots.len() < count {
            free_slots.push(FileHandle::from(current_len));
            current_len += 1;
        }
        free_slots
    }

    fn find_free_upper_block(&mut self, len: usize) -> FileHandle {
        let mut start = 0;
        let mut count = 0;

        for (i, file_opt) in self.upper_fdtbl.iter().enumerate() {
            if file_opt.is_none() {
                if count == 0 {
                    start = i;
                }
                count += 1;
                if count == len {
                    break;
                }
            } else {
                count = 0;
            }
        }

        if count < len {
            if count == 0 {
                start = self.upper_fdtbl.len();
            }
            let needed = len - count;
            self.upper_fdtbl
                .resize(self.upper_fdtbl.len() + needed, None);
        }

        FileHandle::from(start | UPPER_FDTBL_TAG)
    }

    pub fn force_close_all(&mut self, token: &mut CleanLockToken) {
        for file_opt in self.iter_mut() {
            if let Some(file) = file_opt.take() {
                let _ = file.close(token);
            }
        }
        self.active_count = 0;
    }
}

impl FdTbl {
    pub fn enumerate(&self) -> impl Iterator<Item = (usize, &Option<FileDescriptor>)> {
        self.posix_fdtbl.iter().enumerate().chain(
            self.upper_fdtbl
                .iter()
                .enumerate()
                .map(|(i, fd)| (i | UPPER_FDTBL_TAG, fd)),
        )
    }

    pub fn iter(&self) -> impl Iterator<Item = &Option<FileDescriptor>> {
        self.posix_fdtbl.iter().chain(self.upper_fdtbl.iter())
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Option<FileDescriptor>> {
        self.posix_fdtbl
            .iter_mut()
            .chain(self.upper_fdtbl.iter_mut())
    }
}
