use alloc::sync::{Arc, Weak};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use syscall::{SKMSG_FRETURNFD, CallerCtx, SKMSG_PROVIDE_MMAP};
use core::num::NonZeroUsize;
use core::sync::atomic::{AtomicBool, Ordering};
use core::{mem, usize};
use core::convert::TryFrom;
use spin::{Mutex, RwLock};

use crate::context::context::HardBlockedReason;
use crate::context::{self, Context, BorrowedHtBuf, Status};
use crate::context::file::FileDescription;
use crate::context::memory::{AddrSpace, DANGLING, Grant, GrantFileRef, PageSpan, MmapMode, page_flags, BorrowedFmapSource};
use crate::event;
use crate::memory::Frame;
use crate::paging::{PAGE_SIZE, Page, VirtualAddress};
use crate::scheme::{AtomicSchemeId, SchemeId};
use crate::sync::{WaitQueue, WaitMap};
use crate::syscall::data::{Map, Packet};
use crate::syscall::error::*;
use crate::syscall::flag::{EventFlags, EVENT_READ, O_NONBLOCK, PROT_READ, PROT_WRITE, MapFlags};
use crate::syscall::number::*;
use crate::syscall::scheme::Scheme;
use crate::syscall::usercopy::{UserSlice, UserSliceWo, UserSliceRo};

use super::{FileHandle, OpenResult, KernelScheme, current_caller_ctx};

pub struct UserInner {
    root_id: SchemeId,
    handle_id: usize,
    pub name: Box<str>,
    pub flags: usize,
    pub scheme_id: AtomicSchemeId,
    next_id: Mutex<u64>,
    context: Weak<RwLock<Context>>,
    todo: WaitQueue<Packet>,
    done: WaitMap<u64, Response>,
    fmap: Mutex<BTreeMap<u64, Weak<RwLock<Context>>>>,
    unmounting: AtomicBool,
}
#[derive(Debug)]
pub enum Response {
    Regular(usize),
    Fd(Arc<RwLock<FileDescription>>),
}

const ONE: NonZeroUsize = NonZeroUsize::new(1).unwrap();

impl UserInner {
    pub fn new(root_id: SchemeId, handle_id: usize, name: Box<str>, flags: usize, context: Weak<RwLock<Context>>) -> UserInner {
        UserInner {
            root_id,
            handle_id,
            name,
            flags,
            scheme_id: AtomicSchemeId::default(),
            next_id: Mutex::new(1),
            context,
            todo: WaitQueue::new(),
            done: WaitMap::new(),
            unmounting: AtomicBool::new(false),
            fmap: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn unmount(&self) -> Result<usize> {
        // First, block new requests and prepare to return EOF
        self.unmounting.store(true, Ordering::SeqCst);

        // Wake up any blocked scheme handler
        unsafe { self.todo.condition.notify_signal() };

        // Tell the scheme handler to read
        event::trigger(self.root_id, self.handle_id, EVENT_READ);

        //TODO: wait for all todo and done to be processed?
        Ok(0)
    }

    fn next_id(&self) -> u64 {
        let mut guard = self.next_id.lock();
        let id = *guard;
        *guard += 1;
        id
    }

    pub fn call(&self, a: usize, b: usize, c: usize, d: usize) -> Result<usize> {
        match self.call_extended(current_caller_ctx()?, [a, b, c, d])? {
            Response::Regular(code) => Error::demux(code),
            Response::Fd(_) => {
                if a & SYS_RET_FILE == SYS_RET_FILE {
                    log::warn!("Kernel code using UserScheme::call wrongly, as an external file descriptor was returned.");
                }

                Err(Error::new(EIO))
            }
        }
    }

    pub fn call_extended(&self, ctx: CallerCtx, [a, b, c, d]: [usize; 4]) -> Result<Response> {
        self.call_extended_inner(Packet {
            id: self.next_id(),
            pid: ctx.pid,
            uid: ctx.uid,
            gid: ctx.gid,
            a,
            b,
            c,
            d
        })
    }

    fn call_extended_inner(&self, packet: Packet) -> Result<Response> {
        if self.unmounting.load(Ordering::SeqCst) {
            return Err(Error::new(ENODEV));
        }

        let id = packet.id;

        self.todo.send(packet);
        event::trigger(self.root_id, self.handle_id, EVENT_READ);

        Ok(self.done.receive(&id, "UserInner::call_inner"))
    }

    /// Map a readable structure to the scheme's userspace and return the
    /// pointer
    #[must_use = "copying back to head/tail buffers can fail"]
    pub fn capture_user<const READ: bool, const WRITE: bool>(&self, buf: UserSlice<READ, WRITE>) -> Result<CaptureGuard<READ, WRITE>> {
        UserInner::capture_inner(
            &self.context,
            buf,
        )
    }
    pub fn copy_and_capture_tail(&self, buf: &[u8]) -> Result<CaptureGuard<false, false>> {
        let dst_addr_space = Arc::clone(self.context.upgrade().ok_or(Error::new(ENODEV))?.read().addr_space()?);

        let mut tail = BorrowedHtBuf::tail()?;
        let tail_frame = tail.frame();
        if buf.len() > tail.buf().len() {
            return Err(Error::new(EINVAL));
        }
        tail.buf_mut()[..buf.len()].copy_from_slice(buf);

        let src_page = Page::containing_address(VirtualAddress::new(tail.buf_mut().as_ptr() as usize));

        let dst_page = dst_addr_space.write().mmap(None, ONE, PROT_READ, |dst_page, flags, mapper, flusher| Ok(Grant::physmap(tail_frame, PageSpan::new(dst_page, 1), flags, mapper, flusher)?))?;

        Ok(CaptureGuard {
            destroyed: false,
            base: dst_page.start_address().data(),
            len: buf.len(),
            space: Some(dst_addr_space),
            head: CopyInfo {
                src: Some(tail),
                dst: None,
            },
            tail: CopyInfo { src: None, dst: None },
        })
    }

    // TODO: Use an address space Arc over a context Arc. While contexts which share address spaces
    // still can access borrowed scheme pages, it would both be cleaner and would handle the case
    // where the initial context is closed.
    /// Capture a buffer owned by userspace, mapping it contiguously onto scheme memory.
    // TODO: Hypothetical accept_head_leak, accept_tail_leak options might be useful for
    // libc-controlled buffer pools.
    fn capture_inner<const READ: bool, const WRITE: bool>(context_weak: &Weak<RwLock<Context>>, user_buf: UserSlice<READ, WRITE>) -> Result<CaptureGuard<READ, WRITE>> {
        let (mode, map_flags) = match (READ, WRITE) {
            (true, false) => (Mode::Ro, PROT_READ),
            (false, true) => (Mode::Wo, PROT_WRITE),

            _ => unreachable!(),
        };
        if user_buf.is_empty() {
            // NOTE: Rather than returning NULL, we return a dummy dangling address, that is
            // happens to be non-canonical on x86. This relieves scheme handlers from having to
            // check the length before e.g. creating nonnull Rust references (when an empty length
            // still requires a nonnull but possibly dangling pointer, and this has in practice
            // made nulld errorneously confuse an empty Some("") with None (invalid UTF-8), due to
            // enum layout optimization, as the pointer was null and not dangling). A good choice
            // is thus to simply set the most-significant bit to be compatible with all alignments.
            return Ok(CaptureGuard {
                destroyed: false,
                base: DANGLING,
                len: 0,
                space: None,
                head: CopyInfo { src: None, dst: None },
                tail: CopyInfo { src: None, dst: None },
            });
        }

        let cur_space_lock = AddrSpace::current()?;
        let dst_space_lock = Arc::clone(context_weak.upgrade().ok_or(Error::new(ESRCH))?.read().addr_space()?);

        if Arc::ptr_eq(&dst_space_lock, &cur_space_lock) {
            // Same address space, no need to remap anything!
            return Ok(CaptureGuard {
                destroyed: false,
                base: user_buf.addr(),
                len: user_buf.len(),
                space: None,
                head: CopyInfo { src: None, dst: None },
                tail: CopyInfo { src: None, dst: None },
            });
        }

        let (src_page, page_count, offset) = page_range_containing(user_buf.addr(), user_buf.len());

        let align_offset = if offset == 0 { 0 } else { PAGE_SIZE - offset };
        let (head_part_of_buf, middle_tail_part_of_buf) = user_buf
            .split_at(core::cmp::min(align_offset, user_buf.len()))
            .expect("split must succeed");

        let mut dst_space = dst_space_lock.write();

        let free_span = dst_space.grants.find_free(dst_space.mmap_min, page_count).ok_or(Error::new(ENOMEM))?;

        let head = if !head_part_of_buf.is_empty() {
            // FIXME: Signal context can probably recursively use head/tail.
            let mut array = BorrowedHtBuf::head()?;
            let frame = array.frame();

            let len = core::cmp::min(PAGE_SIZE - offset, user_buf.len());

            match mode {
                Mode::Ro => {
                    array.buf_mut()[..offset].fill(0_u8);
                    array.buf_mut()[offset + len..].fill(0_u8);

                    let slice = &mut array.buf_mut()[offset..][..len];
                    let head_part_of_buf = user_buf.limit(len).expect("always smaller than max len");

                    head_part_of_buf.reinterpret_unchecked::<true, false>().copy_to_slice(slice)?;
                }
                Mode::Wo => {
                    array.buf_mut().fill(0_u8);
                }
            }

            dst_space.mmap(Some(free_span.base), ONE, map_flags, move |dst_page, page_flags, mapper, flusher| {
                Ok(Grant::physmap(frame, PageSpan::new(dst_page, 1), page_flags, mapper, flusher)?)
            })?;

            let head = CopyInfo {
                src: Some(array),
                dst: (mode == Mode::Wo).then_some(head_part_of_buf.reinterpret_unchecked()),
            };

            head
        } else {
            CopyInfo {
                src: None,
                dst: None,
            }
        };
        let (first_middle_dst_page, first_middle_src_page) = if !head_part_of_buf.is_empty() { (free_span.base.next(), src_page.next()) } else { (free_span.base, src_page) };

        let middle_page_count = middle_tail_part_of_buf.len() / PAGE_SIZE;
        let tail_size = middle_tail_part_of_buf.len() % PAGE_SIZE;

        let (_middle_part_of_buf, tail_part_of_buf) = middle_tail_part_of_buf.split_at(middle_page_count * PAGE_SIZE).expect("split must succeed");

        if let Some(middle_page_count) = NonZeroUsize::new(middle_page_count) {
            dst_space.mmap_multiple(Some(first_middle_dst_page), middle_page_count, map_flags, move |dst_page, page_flags, mapper, flusher| {
                let eager = true;

                // It doesn't make sense to allow a context, that has borrowed non-RAM physical
                // memory, to DIRECTLY do scheme calls onto that memory.
                //
                // (TODO: Maybe there are some niche use cases for that, possibly PCI transfer
                // BARs, but it doesn't make sense yet.)
                let allow_phys = false;

                Ok(Grant::borrow(Arc::clone(&cur_space_lock), &mut *cur_space_lock.write(), first_middle_src_page, dst_page, middle_page_count.get(), page_flags, mapper, flusher, eager, allow_phys)?)
            })?;
        }

        let tail = if !tail_part_of_buf.is_empty() {
            let tail_dst_page = first_middle_dst_page.next_by(middle_page_count);

            // FIXME: Signal context can probably recursively use head/tail.
            let mut array = BorrowedHtBuf::tail()?;
            let frame = array.frame();

            match mode {
                Mode::Ro => {
                    let (to_copy, to_zero) = array.buf_mut().split_at_mut(tail_size);

                    to_zero.fill(0_u8);

                    // FIXME: remove reinterpret_unchecked
                    tail_part_of_buf.reinterpret_unchecked::<true, false>().copy_to_slice(to_copy)?;
                }
                Mode::Wo => {
                    array.buf_mut().fill(0_u8);
                }
            }

            dst_space.mmap(Some(tail_dst_page), ONE, map_flags, move |dst_page, page_flags, mapper, flusher| {
                Ok(Grant::physmap(frame, PageSpan::new(dst_page, 1), page_flags, mapper, flusher)?)
            })?;

            CopyInfo {
                src: Some(array),
                dst: (mode == Mode::Wo).then_some(tail_part_of_buf.reinterpret_unchecked()),
            }
        } else {
            CopyInfo {
                src: None,
                dst: None,
            }
        };

        drop(dst_space);

        Ok(CaptureGuard {
            destroyed: false,
            base: free_span.base.start_address().data() + offset,
            len: user_buf.len(),
            space: Some(dst_space_lock),
            head,
            tail,
        })
    }

    pub fn read(&self, buf: UserSliceWo) -> Result<usize> {
        // If O_NONBLOCK is used, do not block
        let nonblock = self.flags & O_NONBLOCK == O_NONBLOCK;
        // If unmounting, do not block so that EOF can be returned immediately
        let block = !(nonblock || self.unmounting.load(Ordering::SeqCst));

        match self.todo.receive_into_user(buf, block, "UserInner::read") {
            // If we received requests, return them to the scheme handler
            Ok(byte_count) => Ok(byte_count),
            // If there were no requests and we were unmounting, return EOF
            Err(Error { errno: EAGAIN }) if self.unmounting.load(Ordering::SeqCst) => Ok(0),
            // If there were no requests and O_NONBLOCK was used (EAGAIN), or some other error
            // occurred, return that.
            Err(error) => Err(error),
        }
    }

    pub fn write(&self, buf: UserSliceRo) -> Result<usize> {
        let mut packets_read = 0;

        for chunk in buf.in_exact_chunks(mem::size_of::<Packet>()) {
            match self.handle_packet(&unsafe { chunk.read_exact::<Packet>()? }) {
                Ok(()) => packets_read += 1,
                Err(_) if packets_read > 0 => break,
                Err(error) => return Err(error),
            }
        }

        Ok(packets_read * mem::size_of::<Packet>())
    }
    pub fn request_fmap(&self, id: usize, offset: u64, required_page_count: usize, flags: MapFlags) -> Result<()> {
        log::info!("REQUEST FMAP");
        self.todo.send(Packet {
            id: self.next_id(),
            pid: context::context_id().into(),
            a: KSMSG_MMAP,
            b: id,
            c: flags.bits(),
            d: required_page_count,
            uid: offset as u32,
            gid: (offset >> 32) as u32,
        });
        event::trigger(self.root_id, self.handle_id, EVENT_READ);

        Ok(())
    }
    fn handle_packet(&self, packet: &Packet) -> Result<()> {
        if packet.id == 0 {
            // TODO: Simplify logic by using SKMSG with packet.id being ignored?
            match packet.a {
                SYS_FEVENT => event::trigger(self.scheme_id.load(Ordering::SeqCst), packet.b, EventFlags::from_bits_truncate(packet.c)),
                _ => log::warn!("Unknown scheme -> kernel message {}", packet.a)
            }
        } else if Error::demux(packet.a) == Err(Error::new(ESKMSG)) {
            // The reason why the new ESKMSG mechanism was introduced, is that passing packet IDs
            // in packet.id is much cleaner than having to convert it into 1 or 2 usizes etc.
            match packet.b {
                SKMSG_FRETURNFD => {
                    let fd = packet.c;

                    let desc = context::current()?.read().remove_file(FileHandle::from(fd)).ok_or(Error::new(EINVAL))?.description;

                    self.done.send(packet.id, Response::Fd(desc));
                }
                SKMSG_PROVIDE_MMAP => {
                    log::info!("PROVIDE_MAP {:?}", packet);
                    let offset = u64::from(packet.uid) | (u64::from(packet.gid) << 32);

                    if offset % PAGE_SIZE as u64 != 0 {
                        return Err(Error::new(EINVAL));
                    }

                    let base_addr = VirtualAddress::new(packet.c);
                    if base_addr.data() % PAGE_SIZE != 0 {
                        return Err(Error::new(EINVAL));
                    }

                    let page_count = packet.d;

                    if page_count != 1 { return Err(Error::new(EINVAL)); }
                    let context = self.fmap.lock().remove(&packet.id).ok_or(Error::new(EINVAL))?.upgrade().ok_or(Error::new(ESRCH))?;

                    let (frame, _) = AddrSpace::current()?.read().table.utable.translate(base_addr).ok_or(Error::new(EFAULT))?;

                    let mut context = context.write();
                    match context.status {
                        Status::HardBlocked { reason: HardBlockedReason::AwaitingMmap { .. } } => context.status = Status::Runnable,
                        _ => (),
                    }
                    context.fmap_ret = Some(Frame::containing_address(frame));

                }
                _ => return Err(Error::new(EINVAL)),
            }
        } else {
            self.done.send(packet.id, Response::Regular(packet.a));
        }

        Ok(())
    }

    pub fn fevent(&self, _flags: EventFlags) -> Result<EventFlags> {
        Ok(EventFlags::empty())
    }

    pub fn fsync(&self) -> Result<usize> {
        Ok(0)
    }

    fn fmap_inner(&self, dst_addr_space: Arc<RwLock<AddrSpace>>, file: usize, map: &Map) -> Result<usize> {
        let aligned_size = map.size.next_multiple_of(PAGE_SIZE);
        if aligned_size != map.size {
            log::warn!("fmap passed length {:#0x} instead of {:#0x}", map.size, aligned_size);
        }

        if aligned_size == 0 {
            return Err(Error::new(EINVAL));
        }

        if map.address % PAGE_SIZE != 0 {
            return Err(Error::new(EINVAL));
        };
        let dst_base = (map.address != 0).then_some(Page::containing_address(VirtualAddress::new(map.address)));

        if map.offset % PAGE_SIZE != 0 {
            return Err(Error::new(EINVAL));
        }

        let mode = if map.flags.contains(MapFlags::MAP_SHARED) {
            MmapMode::Shared
        } else {
            MmapMode::Cow
        };

        let src_address_space = Arc::clone(
            self.context.upgrade().ok_or(Error::new(ENODEV))?
                .read().addr_space()?
        );

        let (pid, desc) = {
            let context_lock = context::current()?;
            let context = context_lock.read();
            // TODO: Faster, cleaner mechanism to get descriptor
            let scheme = self.scheme_id.load(Ordering::SeqCst);
            let mut desc_res = Err(Error::new(EBADF));
            for context_file in context.files.read().iter().flatten() {
                let (context_scheme, context_number) = {
                    let desc = context_file.description.read();
                    (desc.scheme, desc.number)
                };
                if context_scheme == scheme && context_number == file {
                    desc_res = Ok(context_file.clone());
                    break;
                }
            }
            let desc = desc_res?;
            (context.id, desc.description)
        };

        let page_count = aligned_size / PAGE_SIZE;

        let response = self.call_extended_inner(Packet {
            id: self.next_id(),
            pid: pid.into(),
            a: KSMSG_MMAP_PREP,
            b: file,
            c: map.flags.bits(),
            d: page_count,
            // The uid and gid can be obtained by the proc scheme anyway, if the pid is provided.
            uid: map.offset as u32,
            gid: (map.offset >> 32) as u32,
        })?;

        let base_page_opt = match response {
            Response::Regular(code) => (!map.flags.contains(MapFlags::MAP_LAZY))
                .then_some(Error::demux(code)?),
            Response::Fd(_) => {
                log::debug!("Scheme incorrectly returned an fd for fmap.");

                return Err(Error::new(EIO));
            }
        };

        let dst_base = match mode {
            MmapMode::Cow => todo!("mmap CoW"),
            MmapMode::Shared => {
                let file_ref = GrantFileRef {
                    description: desc,
                    base_offset: map.offset,
                };
                let src_guard = src_address_space.read();
                let src = match base_page_opt {
                    Some(base_addr) => Some(BorrowedFmapSource {
                        src_page: Page::containing_address(VirtualAddress::new(base_addr)),
                        src_mapper: &src_guard.table.utable,
                    }),
                    None => None,
                };
                let page_count_nz = NonZeroUsize::new(page_count).expect("already validated map.size != 0");
                dst_addr_space.write().mmap(dst_base, page_count_nz, map.flags, |dst_base, flags, mapper, flusher| {
                    Ok(Grant::borrow_fmap(PageSpan::new(dst_base, page_count), page_flags(map.flags), file_ref, src, mapper, flusher))
                })?
            }
        };

        Ok(dst_base.start_address().data())
    }
}
pub struct CaptureGuard<const READ: bool, const WRITE: bool> {
    destroyed: bool,
    base: usize,
    len: usize,

    space: Option<Arc<RwLock<AddrSpace>>>,

    head: CopyInfo<READ, WRITE>,
    tail: CopyInfo<READ, WRITE>,
}
impl<const READ: bool, const WRITE: bool> CaptureGuard<READ, WRITE> {
    fn base(&self) -> usize { self.base }
    fn len(&self) -> usize { self.len }
}
struct CopyInfo<const READ: bool, const WRITE: bool> {
    src: Option<BorrowedHtBuf>,

    // TODO
    dst: Option<UserSlice<true, true>>,
}
impl<const READ: bool, const WRITE: bool> CaptureGuard<READ, WRITE> {
    fn release_inner(&mut self) -> Result<()> {
        if self.destroyed {
            return Ok(());
        }
        self.destroyed = true;

        if self.base == DANGLING {
            return Ok(());
        }

        let mut result = Ok(());

        // TODO: Encode src and dst better using const generics.
        if let CopyInfo { src: Some(ref src), dst: Some(ref mut dst) } = self.head {
            result = result.and_then(|()| dst.copy_from_slice(&src.buf()[self.base % PAGE_SIZE..][..dst.len()]));
        }
        if let CopyInfo { src: Some(ref src), dst: Some(ref mut dst) } = self.tail {
            result = result.and_then(|()| dst.copy_from_slice(&src.buf()[..dst.len()]));
        }
        let Some(space) = self.space.take() else {
            return result;
        };

        let (first_page, page_count, _offset) = page_range_containing(self.base, self.len);

        space.write().munmap(PageSpan::new(first_page, page_count));

        result
    }
    pub fn release(mut self) -> Result<()> {
        self.release_inner()
    }
}
impl<const READ: bool, const WRITE: bool> Drop for CaptureGuard<READ, WRITE> {
    fn drop(&mut self) {
        let _ = self.release_inner();
    }
}
/// base..base+size => page..page+page_count*PAGE_SIZE, offset
fn page_range_containing(base: usize, size: usize) -> (Page, usize, usize) {
    let first_page = Page::containing_address(VirtualAddress::new(base));
    let offset = base - first_page.start_address().data();

    (first_page, (size + offset).div_ceil(PAGE_SIZE), offset)
}

/// `UserInner` has to be wrapped
pub struct UserScheme {
    inner: Weak<UserInner>
}

impl UserScheme {
    pub fn new(inner: Weak<UserInner>) -> UserScheme {
        UserScheme { inner }
    }
}

fn handle_open_res(res: OpenResult) -> Result<usize> {
    match res {
        OpenResult::SchemeLocal(num) => Ok(num),
        OpenResult::External(_) => {
            log::warn!("Used Scheme::open when forwarding fd!");
            Err(Error::new(EIO))
        }
    }
}

impl Scheme for UserScheme {
    fn open(&self, path: &str, flags: usize, uid: u32, gid: u32) -> Result<usize> {
        self.kopen(path, flags, CallerCtx { uid, gid, pid: context::context_id().into() }).and_then(handle_open_res)
    }

    fn rmdir(&self, path: &str, _uid: u32, _gid: u32) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let address = inner.copy_and_capture_tail(path.as_bytes())?;
        inner.call(SYS_RMDIR, address.base(), address.len(), 0)
    }

    fn unlink(&self, path: &str, _uid: u32, _gid: u32) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let address = inner.copy_and_capture_tail(path.as_bytes())?;
        inner.call(SYS_UNLINK, address.base(), address.len(), 0)
    }

    fn seek(&self, file: usize, position: isize, whence: usize) -> Result<isize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let new_offset = inner.call(SYS_LSEEK, file, position as usize, whence)?;
        isize::try_from(new_offset).or_else(|_| Err(Error::new(EOVERFLOW)))
    }

    fn fchmod(&self, file: usize, mode: u16) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        inner.call(SYS_FCHMOD, file, mode as usize, 0)
    }

    fn fchown(&self, file: usize, uid: u32, gid: u32) -> Result<usize> {
        {
            let contexts = context::contexts();
            let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
            let context = context_lock.read();
            if context.euid != 0 {
                if uid != context.euid || gid != context.egid {
                    return Err(Error::new(EPERM));
                }
            }
        }

        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        inner.call(SYS_FCHOWN, file, uid as usize, gid as usize)
    }

    fn fcntl(&self, file: usize, cmd: usize, arg: usize) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        inner.call(SYS_FCNTL, file, cmd, arg)
    }

    fn fevent(&self, file: usize, flags: EventFlags) -> Result<EventFlags> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        inner.call(SYS_FEVENT, file, flags.bits(), 0).map(EventFlags::from_bits_truncate)
    }

    /*
    fn funmap(&self, grant_address: usize, size: usize) -> Result<usize> {
        let requested_span = PageSpan::validate_nonempty(VirtualAddress::new(grant_address), size).ok_or(Error::new(EINVAL))?;

        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;

        let address_opt = {
            let context_lock = context::current()?;
            let context = context_lock.read();

            let mut addr_space = context.addr_space()?.write();
            let funmap = &mut addr_space.grants.funmap;
            let entry = funmap.range(..=Page::containing_address(VirtualAddress::new(grant_address))).next_back();

            if let Some((&grant_page, &(page_count, user_page))) = entry {
                if requested_span.base.next_by(requested_span.count) > grant_page.next_by(page_count) {
                    return Err(Error::new(EINVAL));
                }

                funmap.remove(&grant_page);

                let grant_span = PageSpan::new(grant_page, page_count);
                let user_span = PageSpan::new(user_page, page_count);

                if let Some(before) = grant_span.before(requested_span) {
                    funmap.insert(before.base, (before.count, user_page));
                }
                if let Some(after) = grant_span.after(requested_span) {
                    let start = grant_span.rebase(user_span, after.base);
                    funmap.insert(after.base, (after.count, start));
                }

                Some(grant_span.rebase(user_span,grant_span.base).start_address().data())
            } else {
                None
            }
        };
        if let Some(user_address) = address_opt {
            inner.call(SYS_FUNMAP, user_address, size, 0)
        } else {
            Err(Error::new(EINVAL))
        }
    }
    */

    fn frename(&self, file: usize, path: &str, _uid: u32, _gid: u32) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let address = inner.copy_and_capture_tail(path.as_bytes())?;
        inner.call(SYS_FRENAME, file, address.base(), address.len())
    }

    fn fsync(&self, file: usize) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        inner.call(SYS_FSYNC, file, 0, 0)
    }

    fn ftruncate(&self, file: usize, len: usize) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        inner.call(SYS_FTRUNCATE, file, len, 0)
    }

    fn close(&self, file: usize) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        inner.call(SYS_CLOSE, file, 0, 0)
    }
}
impl KernelScheme for UserScheme {
    fn kopen(&self, path: &str, flags: usize, ctx: CallerCtx) -> Result<OpenResult> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let address = inner.copy_and_capture_tail(path.as_bytes())?;
        match inner.call_extended(ctx, [SYS_OPEN, address.base(), address.len(), flags])? {
            Response::Regular(code) => Error::demux(code).map(OpenResult::SchemeLocal),
            Response::Fd(desc) => Ok(OpenResult::External(desc)),
        }
    }
    fn kdup(&self, file: usize, buf: UserSliceRo, ctx: CallerCtx) -> Result<OpenResult> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let address = inner.capture_user(buf)?;
        let result = inner.call_extended(ctx, [SYS_DUP, file, address.base(), address.len()]);

        address.release()?;

        match result? {
            Response::Regular(code) => Error::demux(code).map(OpenResult::SchemeLocal),
            Response::Fd(desc) => Ok(OpenResult::External(desc)),
        }
    }
    fn kfpath(&self, file: usize, buf: UserSliceWo) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let address = inner.capture_user(buf)?;
        let result = inner.call(SYS_FPATH, file, address.base(), address.len());
        address.release()?;
        result
    }

    fn kread(&self, file: usize, buf: UserSliceWo) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let address = inner.capture_user(buf)?;
        let result = inner.call(SYS_READ, file, address.base(), address.len());
        address.release()?;
        result
    }

    fn kwrite(&self, file: usize, buf: UserSliceRo) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let address = inner.capture_user(buf)?;
        let result = inner.call(SYS_WRITE, file, address.base(), address.len());
        address.release()?;
        result
    }
    fn kfutimens(&self, file: usize, buf: UserSliceRo) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let address = inner.capture_user(buf)?;
        let result = inner.call(SYS_FUTIMENS, file, address.base(), address.len());
        address.release()?;
        result
    }
    fn kfstat(&self, file: usize, stat: UserSliceWo) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let address = inner.capture_user(stat)?;
        let result = inner.call(SYS_FSTAT, file, address.base(), address.len());
        address.release()?;
        result
    }
    fn kfstatvfs(&self, file: usize, stat: UserSliceWo) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let address = inner.capture_user(stat)?;
        let result = inner.call(SYS_FSTATVFS, file, address.base(), address.len());
        address.release()?;
        result
    }
    fn kfmap(&self, file: usize, addr_space: &Arc<RwLock<AddrSpace>>, map: &Map, _consume: bool) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;

        inner.fmap_inner(Arc::clone(addr_space), file, map)
    }

    fn as_user_inner(&self) -> Option<Result<Arc<UserInner>>> {
        Some(self.inner.upgrade().ok_or(Error::new(ENODEV)))
    }
}

#[derive(PartialEq)]
pub enum Mode {
    Ro,
    Wo,
}
