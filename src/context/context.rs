use alloc::{collections::BTreeSet, sync::Arc, vec::Vec};
use arrayvec::ArrayString;
use core::{
    mem::{self, size_of},
    num::NonZeroUsize,
    sync::atomic::{AtomicU32, Ordering},
};
use spin::RwLock;
use syscall::EBADF;
use syscall::{SigProcControl, Sigcontrol};

#[cfg(feature = "sys_stat")]
use crate::cpu_stats;
use crate::{
    arch::{interrupt::InterruptStack, paging::PAGE_SIZE},
    common::aligned_box::AlignedBox,
    context::{self, arch, file::FileDescriptor},
    cpu_set::{LogicalCpuId, LogicalCpuSet},
    ipi::{ipi, IpiKind, IpiTarget},
    memory::{allocate_p2frame, deallocate_p2frame, Enomem, Frame, RaiiFrame},
    paging::{RmmA, RmmArch},
    percpu::PercpuBlock,
    scheme::{CallerCtx, FileHandle, SchemeId, SchemeNamespace},
};

use crate::syscall::error::{Error, Result, EAGAIN, EINVAL, ESRCH};

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
    PtraceStop,
}

const CONTEXT_NAME_CAPAC: usize = 32;

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
    pub syscall_head: Option<RaiiFrame>,
    /// Tail buffer to use when system call buffers are not page aligned
    // TODO: Store in user memory?
    pub syscall_tail: Option<RaiiFrame>,
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
            syscall_head: Some(RaiiFrame::allocate()?),
            syscall_tail: Some(RaiiFrame::allocate()?),
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
        };
        #[cfg(feature = "sys_stat")]
        cpu_stats::add_context();
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
        let mut files = self.files.write();
        files.add_file_min(file, min)
    }

    /// Bulk-add multiple files to the POSIX file table
    pub fn bulk_add_files(&self, files_to_add: Vec<FileDescriptor>) -> Option<Vec<FileHandle>> {
        let mut files = self.files.write();
        let mut indices = files.find_free_slots(files_to_add.len());
        files.bulk_insert_files(files_to_add, indices)
    }

    /// Bulk-insert multiple files into to the upper file table contiguously
    pub fn bulk_insert_upper_files(
        &self,
        files_to_insert: Vec<FileDescriptor>,
    ) -> Option<Vec<FileHandle>> {
        let mut files = self.files.write();
        let len = files_to_insert.len();
        let index = files.find_free_block(len).get();
        let mut indices = Vec::new();
        for i in 0..len {
            indices.push(FileHandle::from(index + i));
        }
        files.bulk_insert_files(files_to_insert, indices)
    }

    /// Get a file
    pub fn get_file(&self, i: FileHandle) -> Option<FileDescriptor> {
        let files = self.files.read();
        files.get_file(i)
    }

    /// Bulk get files
    pub fn bulk_get_files(&self, handles: &[FileHandle]) -> Result<Vec<FileDescriptor>> {
        let files = self.files.read();
        files.bulk_get_files(handles)
    }

    /// Insert a file with a specific handle number. This is used by dup2
    /// Return the file descriptor number or None if the slot was not empty, or i was invalid
    pub fn insert_file(&self, i: FileHandle, file: FileDescriptor) -> Option<FileHandle> {
        let mut files = self.files.write();
        files.insert_file(i, file)
    }

    /// Remove a file
    // TODO: adjust files vector to smaller size if possible
    pub fn remove_file(&self, i: FileHandle) -> Option<FileDescriptor> {
        let mut files = self.files.write();
        files.remove_file(i)
    }

    /// Bulk remove files
    pub fn bulk_remove_files(&self, handles: &[FileHandle]) -> Result<Vec<FileDescriptor>> {
        let mut files = self.files.write();
        files.bulk_remove_files(handles)
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
        if let (Some(ref old), Some(ref new)) = (&self.addr_space, &addr_space)
            && Arc::ptr_eq(old, new)
        {
            return addr_space;
        };

        if self.is_current_context() {
            // TODO: Share more code with context::arch::switch_to.
            let this_percpu = PercpuBlock::current();

            if let Some(ref prev_addrsp) = self.addr_space {
                assert!(Arc::ptr_eq(
                    &this_percpu.current_addrsp.borrow().as_ref().unwrap(),
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

            if let Some(ref new) = addr_space {
                let new_addrsp = new.acquire_read();
                new_addrsp.used_by.atomic_set(this_percpu.cpu_id);

                unsafe {
                    new_addrsp.table.utable.make_current();
                }
            } else {
                unsafe {
                    crate::paging::RmmA::set_table(rmm::TableKind::User, empty_cr3());
                }
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
        let Some(ref kstack) = self.kstack else {
            return None;
        };
        Some(unsafe { &*kstack.initial_top().sub(size_of::<InterruptStack>()).cast() })
    }
    pub fn regs_mut(&mut self) -> Option<&mut InterruptStack> {
        if !self.can_access_regs() {
            return None;
        }
        let Some(ref mut kstack) = self.kstack else {
            return None;
        };
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
    pub fn head() -> Result<Self> {
        Ok(Self {
            inner: Some(
                context::current()
                    .write()
                    .syscall_head
                    .take()
                    .ok_or(Error::new(EAGAIN))?,
            ),
            head_and_not_tail: true,
        })
    }
    pub fn tail() -> Result<Self> {
        Ok(Self {
            inner: Some(
                context::current()
                    .write()
                    .syscall_tail
                    .take()
                    .ok_or(Error::new(EAGAIN))?,
            ),
            head_and_not_tail: false,
        })
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
        match context.write() {
            mut context => {
                (if self.head_and_not_tail {
                    &mut context.syscall_head
                } else {
                    &mut context.syscall_tail
                })
                .get_or_insert(inner);
            }
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

// TODO: Move to syscall crate?.
pub const UPPER_TABLE_FLAG: usize = 1 << (usize::BITS - 2);

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

    fn select_fdtbl(&self, index: usize) -> (&Vec<Option<FileDescriptor>>, usize) {
        if index & UPPER_TABLE_FLAG == 0 {
            (&self.posix_fdtbl, index)
        } else {
            log::info!("Selecting upper file descriptor table at index {}", index,);
            (&self.upper_fdtbl, index & !UPPER_TABLE_FLAG)
        }
    }

    fn select_fdtbl_mut(&mut self, index: usize) -> (&mut Vec<Option<FileDescriptor>>, usize) {
        if index & UPPER_TABLE_FLAG == 0 {
            (&mut self.posix_fdtbl, index)
        } else {
            log::info!("Selecting upper file descriptor table at index {}", index,);
            (&mut self.upper_fdtbl, index & !UPPER_TABLE_FLAG)
        }
    }

    fn validate_handles(&self, handles: &[FileHandle]) -> Result<()> {
        let mut checked_handles = BTreeSet::new();
        for i in handles {
            let index = i.get();
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
            if !checked_slots.insert(index) {
                return Err(Error::new(EINVAL)); // Duplicate slots
            }
            if matches!(self.get(index), Some(Some(_))) {
                return Err(Error::new(EINVAL));
            }
        }

        Ok(())
    }

    pub fn add_file_min(&mut self, file: FileDescriptor, min: usize) -> Option<FileHandle> {
        if self.active_count >= super::CONTEXT_MAX_FILES {
            return None;
        }

        // Find the first empty slot in the posix_fdtbl starting from `min`.
        if let Some((pos, slot)) = self
            .posix_fdtbl
            .iter_mut()
            .enumerate()
            .skip(min)
            .find(|(_, slot)| slot.is_none())
        {
            *slot = Some(file);
            self.active_count += 1;
            return Some(FileHandle::from(pos));
        };

        let len = self.posix_fdtbl.len();

        // If no empty slot was found, we need to allocate a new slot.
        if len >= min {
            self.posix_fdtbl.push(Some(file));
            self.active_count += 1;
            Some(FileHandle::from(len))
        } else {
            self.insert_file(FileHandle::from(min), file)
        }
    }

    fn bulk_insert_files(
        &mut self,
        files: Vec<FileDescriptor>,
        mut indices: Vec<FileHandle>,
    ) -> Option<Vec<FileHandle>> {
        let len = files.len();
        if self.active_count + len > super::CONTEXT_MAX_FILES {
            return None;
        }
        // self.validate_free_slots(&indices)?;
        for (handle, file) in indices.iter_mut().zip(files) {
            let min = handle.get();
            // This add_file_min woun't fail, as we checked the active_count above.
            *handle = self
                .add_file_min(file, 0)
                .expect("add_file_min should not fail");
        }

        Some(indices)
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
            .map(|fd| fd.clone())
            .ok_or(Error::new(EBADF))
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

    fn find_free_slots(&self, len: usize) -> Vec<FileHandle> {
        let mut free_slots = Vec::new();
        free_slots.resize(len, FileHandle::from(self.posix_fdtbl.len()));
        let mut found = 0;

        for (i, slot) in self.posix_fdtbl.iter().enumerate() {
            if slot.is_none() {
                free_slots[found] = FileHandle::from(i);
                found += 1;
                if found == len {
                    break;
                }
            }
        }

        free_slots
    }

    fn find_free_block(&mut self, len: usize) -> FileHandle {
        let (fdtbl, _) = self.select_fdtbl_mut(UPPER_TABLE_FLAG);

        // Search for a block of `len` consecutive None slots.
        let found_pos = fdtbl
            .windows(len)
            .position(|window| window.iter().all(|opt| opt.is_none()));

        if let Some(pos) = found_pos {
            return FileHandle::from(pos | UPPER_TABLE_FLAG);
        }

        // If no block was found, we need to resize the table.
        let nones_num = fdtbl.iter().rev().take_while(|opt| opt.is_none()).count();

        let start = fdtbl.len() - nones_num;

        let needed = len.saturating_sub(nones_num);
        fdtbl.resize(fdtbl.len() + needed, None);

        FileHandle::from(start | UPPER_TABLE_FLAG)
    }

    pub fn force_close_all(&mut self) {
        for file_opt in self.iter_mut() {
            if let Some(file) = file_opt.take() {
                let _ = file.close();
            }
        }
    }
}

impl FdTbl {
    pub fn iter(&self) -> impl Iterator<Item = &Option<FileDescriptor>> {
        self.posix_fdtbl.iter().chain(self.upper_fdtbl.iter())
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Option<FileDescriptor>> {
        self.posix_fdtbl
            .iter_mut()
            .chain(self.upper_fdtbl.iter_mut())
    }
}
