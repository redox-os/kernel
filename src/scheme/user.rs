use alloc::{
    boxed::Box,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    mem,
    mem::size_of,
    num::NonZeroUsize,
    sync::atomic::{AtomicBool, Ordering},
    usize,
};
use hashbrown::hash_map::{Entry, HashMap};
use spin::{Mutex, RwLock};
use spinning_top::RwSpinlock;
use syscall::{
    FobtainFdFlags, MunmapFlags, SendFdFlags, MAP_FIXED_NOREPLACE, SKMSG_FOBTAINFD,
    SKMSG_FRETURNFD, SKMSG_PROVIDE_MMAP, KSMSG_CANCEL, SIGKILL,
};

use crate::{
    context::{
        self,
        context::HardBlockedReason,
        file::{FileDescription, FileDescriptor},
        memory::{
            AddrSpace, BorrowedFmapSource, Grant, GrantFileRef, MmapMode, PageSpan, DANGLING, AddrSpaceWrapper,
        },
        BorrowedHtBuf, Context, Status,
    },
    event,
    memory::Frame,
    paging::{Page, VirtualAddress, PAGE_SIZE},
    scheme::SchemeId,
    sync::WaitQueue,
    syscall::{
        data::{Map, Packet},
        error::*,
        flag::{EventFlags, MapFlags, EVENT_READ, O_NONBLOCK, PROT_READ, PROT_WRITE},
        number::*,
        usercopy::{UserSlice, UserSliceRo, UserSliceWo},
    },
};

use super::{CallerCtx, FileHandle, KernelScheme, OpenResult};

pub struct UserInner {
    root_id: SchemeId,
    handle_id: usize,
    pub name: Box<str>,
    pub flags: usize,
    pub scheme_id: SchemeId,
    next_id: Mutex<u64>,
    context: Weak<RwSpinlock<Context>>,
    todo: WaitQueue<Packet>,
    states: Mutex<HashMap<u64, State>>,
    unmounting: AtomicBool,
}

enum State {
    Waiting {
        context: Weak<RwSpinlock<Context>>,
        fd: Option<Arc<RwLock<FileDescription>>>,
        canceling: bool,
    },
    Responded(Response),
    Fmap(Weak<RwSpinlock<Context>>),
    Placeholder,
}

#[derive(Debug)]
pub enum Response {
    Regular(usize),
    Fd(Arc<RwLock<FileDescription>>),
}

const ONE: NonZeroUsize = match NonZeroUsize::new(1) {
    Some(one) => one,
    None => unreachable!(),
};

impl UserInner {
    pub fn new(
        root_id: SchemeId,
        scheme_id: SchemeId,
        handle_id: usize,
        name: Box<str>,
        flags: usize,
        context: Weak<RwSpinlock<Context>>,
    ) -> UserInner {
        UserInner {
            root_id,
            handle_id,
            name,
            flags,
            scheme_id,
            next_id: Mutex::new(1),
            context,
            todo: WaitQueue::new(),
            unmounting: AtomicBool::new(false),
            states: Mutex::new(HashMap::new()),
        }
    }

    pub fn unmount(&self) -> Result<()> {
        // First, block new requests and prepare to return EOF
        self.unmounting.store(true, Ordering::SeqCst);

        // Wake up any blocked scheme handler
        unsafe { self.todo.condition.notify_signal() };

        // Tell the scheme handler to read
        event::trigger(self.root_id, self.handle_id, EVENT_READ);

        //TODO: wait for all todo and done to be processed?
        Ok(())
    }

    fn next_id(&self) -> u64 {
        let mut guard = self.next_id.lock();
        let id = *guard;
        *guard += 1;
        id
    }

    pub fn call(&self, a: usize, b: usize, c: usize, d: usize) -> Result<usize> {
        let ctx = context::current()?.read().caller_ctx();
        match self.call_extended(ctx, None, [a, b, c, d])? {
            Response::Regular(code) => Error::demux(code),
            Response::Fd(_) => {
                if a & SYS_RET_FILE == SYS_RET_FILE {
                    log::warn!("Kernel code using UserScheme::call wrongly, as an external file descriptor was returned.");
                }

                Err(Error::new(EIO))
            }
        }
    }

    pub fn call_extended(
        &self,
        ctx: CallerCtx,
        fd: Option<Arc<RwLock<FileDescription>>>,
        [a, b, c, d]: [usize; 4],
    ) -> Result<Response> {
        self.call_extended_inner(
            fd,
            Packet {
                id: self.next_id(),
                pid: ctx.pid,
                uid: ctx.uid,
                gid: ctx.gid,
                a,
                b,
                c,
                d,
            },
        )
    }

    fn call_extended_inner(
        &self,
        fd: Option<Arc<RwLock<FileDescription>>>,
        packet: Packet,
    ) -> Result<Response> {
        if self.unmounting.load(Ordering::SeqCst) {
            return Err(Error::new(ENODEV));
        }

        let id = packet.id;

        let current_context = context::current()?;

        {
            let mut states = self.states.lock();
            current_context.write().block("UserScheme::call");
            states.insert(
                id,
                State::Waiting {
                    context: Arc::downgrade(&current_context),
                    fd,
                    canceling: false,
                },
            );
        }

        self.todo.send(packet);
        event::trigger(self.root_id, self.handle_id, EVENT_READ);

        loop {
            context::switch();

            let eintr_if_sigkill = || if context::current()?.read().sig.deliverable() & (1 << (SIGKILL - 1)) != 0 {
                // EINTR directly if SIGKILL was found without waiting for scheme. Data loss
                // doesn't matter.
                Err(Error::new(EINTR))
            } else {
                Ok(())
            };

            let mut states = self.states.lock();
            match states.entry(id) {
                // invalid state
                Entry::Vacant(_) => return Err(Error::new(EBADFD)),
                Entry::Occupied(mut o) => match mem::replace(o.get_mut(), State::Placeholder) {
                    // signal wakeup while awaiting cancelation
                    old_state @ State::Waiting { canceling: true, .. } => {
                        *o.get_mut() = old_state;
                        drop(states);
                        eintr_if_sigkill()?;
                        context::current()?.write().block("UserInner::call");
                    }
                    // spurious wakeup
                    State::Waiting { canceling: false, fd, context } => {
                        *o.get_mut() = State::Waiting { canceling: true, fd, context };

                        drop(states);
                        eintr_if_sigkill()?;

                        // TODO: Is this too dangerous when the states lock is held?
                        self.todo.send(Packet {
                            id: 0,
                            a: KSMSG_CANCEL,
                            b: packet.id as usize,
                            c: (packet.id >> 32) as usize,
                            ..packet
                        });
                        event::trigger(self.root_id, self.handle_id, EVENT_READ);
                        context::current()?.write().block("UserInner::call");
                    }

                    // invalid state
                    old_state @ (State::Placeholder | State::Fmap(_)) => {
                        *o.get_mut() = old_state;
                        return Err(Error::new(EBADFD));
                    }

                    State::Responded(response) => {
                        o.remove();
                        return Ok(response);
                    }
                },
            }
        }
    }

    /// Map a readable structure to the scheme's userspace and return the
    /// pointer
    #[must_use = "copying back to head/tail buffers can fail"]
    pub fn capture_user<const READ: bool, const WRITE: bool>(
        &self,
        buf: UserSlice<READ, WRITE>,
    ) -> Result<CaptureGuard<READ, WRITE>> {
        UserInner::capture_inner(&self.context, buf)
    }
    pub fn copy_and_capture_tail(&self, buf: &[u8]) -> Result<CaptureGuard<false, false>> {
        let dst_addr_space = Arc::clone(
            self.context
                .upgrade()
                .ok_or(Error::new(ENODEV))?
                .read()
                .addr_space()?,
        );

        let mut tail = BorrowedHtBuf::tail()?;
        let tail_frame = tail.frame();
        if buf.len() > tail.buf().len() {
            return Err(Error::new(EINVAL));
        }
        tail.buf_mut()[..buf.len()].copy_from_slice(buf);

        let is_pinned = true;
        let dst_page = dst_addr_space.acquire_write().mmap_anywhere(
            &dst_addr_space,
            ONE,
            PROT_READ,
            |dst_page, flags, mapper, flusher| {
                Ok(Grant::allocated_shared_one_page(
                    tail_frame, dst_page, flags, mapper, flusher, is_pinned,
                )?)
            },
        )?;

        Ok(CaptureGuard {
            destroyed: false,
            base: dst_page.start_address().data(),
            len: buf.len(),
            space: Some(dst_addr_space),
            head: CopyInfo {
                src: Some(tail),
                dst: None,
            },
            tail: CopyInfo {
                src: None,
                dst: None,
            },
        })
    }

    // TODO: Use an address space Arc over a context Arc. While contexts which share address spaces
    // still can access borrowed scheme pages, it would both be cleaner and would handle the case
    // where the initial context is closed.
    /// Capture a buffer owned by userspace, mapping it contiguously onto scheme memory.
    // TODO: Hypothetical accept_head_leak, accept_tail_leak options might be useful for
    // libc-controlled buffer pools.
    fn capture_inner<const READ: bool, const WRITE: bool>(
        context_weak: &Weak<RwSpinlock<Context>>,
        user_buf: UserSlice<READ, WRITE>,
    ) -> Result<CaptureGuard<READ, WRITE>> {
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
                head: CopyInfo {
                    src: None,
                    dst: None,
                },
                tail: CopyInfo {
                    src: None,
                    dst: None,
                },
            });
        }

        let cur_space_lock = AddrSpace::current()?;
        let dst_space_lock = Arc::clone(
            context_weak
                .upgrade()
                .ok_or(Error::new(ESRCH))?
                .read()
                .addr_space()?,
        );

        if Arc::ptr_eq(&dst_space_lock, &cur_space_lock) {
            // Same address space, no need to remap anything!
            return Ok(CaptureGuard {
                destroyed: false,
                base: user_buf.addr(),
                len: user_buf.len(),
                space: None,
                head: CopyInfo {
                    src: None,
                    dst: None,
                },
                tail: CopyInfo {
                    src: None,
                    dst: None,
                },
            });
        }

        let (src_page, page_count, offset) = page_range_containing(user_buf.addr(), user_buf.len());

        let align_offset = if offset == 0 { 0 } else { PAGE_SIZE - offset };
        let (head_part_of_buf, middle_tail_part_of_buf) = user_buf
            .split_at(core::cmp::min(align_offset, user_buf.len()))
            .expect("split must succeed");

        let mut dst_space = dst_space_lock.acquire_write();

        let free_span = dst_space
            .grants
            .find_free(dst_space.mmap_min, page_count)
            .ok_or(Error::new(ENOMEM))?;

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
                    let head_part_of_buf =
                        user_buf.limit(len).expect("always smaller than max len");

                    head_part_of_buf
                        .reinterpret_unchecked::<true, false>()
                        .copy_to_slice(slice)?;
                }
                Mode::Wo => {
                    array.buf_mut().fill(0_u8);
                }
            }

            dst_space.mmap(
                &dst_space_lock,
                Some(free_span.base),
                ONE,
                map_flags | MAP_FIXED_NOREPLACE,
                &mut Vec::new(),
                move |dst_page, page_flags, mapper, flusher| {
                    let is_pinned = true;
                    Ok(Grant::allocated_shared_one_page(
                        frame, dst_page, page_flags, mapper, flusher, is_pinned,
                    )?)
                },
            )?;

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
        let (first_middle_dst_page, first_middle_src_page) = if !head_part_of_buf.is_empty() {
            (free_span.base.next(), src_page.next())
        } else {
            (free_span.base, src_page)
        };

        let middle_page_count = middle_tail_part_of_buf.len() / PAGE_SIZE;
        let tail_size = middle_tail_part_of_buf.len() % PAGE_SIZE;

        let (_middle_part_of_buf, tail_part_of_buf) = middle_tail_part_of_buf
            .split_at(middle_page_count * PAGE_SIZE)
            .expect("split must succeed");

        if let Some(middle_page_count) = NonZeroUsize::new(middle_page_count) {
            dst_space.mmap(
                &dst_space_lock,
                Some(first_middle_dst_page),
                middle_page_count,
                map_flags | MAP_FIXED_NOREPLACE,
                &mut Vec::new(),
                move |dst_page, _, mapper, flusher| {
                    let eager = true;

                    // It doesn't make sense to allow a context, that has borrowed non-RAM physical
                    // memory, to DIRECTLY do scheme calls onto that memory.
                    //
                    // (TODO: Maybe there are some niche use cases for that, possibly PCI transfer
                    // BARs, but it doesn't make sense yet.)
                    let allow_phys = false;

                    // Deny any attempts by the scheme, to unmap these temporary pages. The only way to
                    // unmap them is to respond to the scheme socket.
                    let is_pinned_userscheme_borrow = true;

                    Ok(Grant::borrow(
                        Arc::clone(&cur_space_lock),
                        &mut *cur_space_lock.acquire_write(),
                        first_middle_src_page,
                        dst_page,
                        middle_page_count.get(),
                        map_flags,
                        mapper,
                        flusher,
                        eager,
                        allow_phys,
                        is_pinned_userscheme_borrow,
                    )?)
                },
            )?;
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
                    tail_part_of_buf
                        .reinterpret_unchecked::<true, false>()
                        .copy_to_slice(to_copy)?;
                }
                Mode::Wo => {
                    array.buf_mut().fill(0_u8);
                }
            }

            dst_space.mmap(
                &dst_space_lock,
                Some(tail_dst_page),
                ONE,
                map_flags | MAP_FIXED_NOREPLACE,
                &mut Vec::new(),
                move |dst_page, page_flags, mapper, flusher| {
                    let is_pinned = true;
                    Ok(Grant::allocated_shared_one_page(
                        frame, dst_page, page_flags, mapper, flusher, is_pinned,
                    )?)
                },
            )?;

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

        for chunk in buf.in_exact_chunks(size_of::<Packet>()) {
            match self.handle_packet(&unsafe { chunk.read_exact::<Packet>()? }) {
                Ok(()) => packets_read += 1,
                Err(_) if packets_read > 0 => break,
                Err(error) => return Err(error),
            }
        }

        Ok(packets_read * size_of::<Packet>())
    }
    pub fn request_fmap(
        &self,
        id: usize,
        offset: u64,
        required_page_count: usize,
        flags: MapFlags,
    ) -> Result<()> {
        log::info!("REQUEST FMAP");

        let packet_id = self.next_id();
        let mut states = self.states.lock();
        states.insert(packet_id, State::Fmap(Arc::downgrade(&context::current()?)));

        self.todo.send(Packet {
            id: packet_id,
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
                SYS_FEVENT => event::trigger(
                    self.scheme_id,
                    packet.b,
                    EventFlags::from_bits_truncate(packet.c),
                ),
                _ => log::warn!("Unknown scheme -> kernel message {} from {}", packet.a, context::current().unwrap().read().name),
            }
        } else if Error::demux(packet.a) == Err(Error::new(ESKMSG)) {
            // The reason why the new ESKMSG mechanism was introduced, is that passing packet IDs
            // in packet.id is much cleaner than having to convert it into 1 or 2 usizes etc.
            match packet.b {
                SKMSG_FRETURNFD => {
                    let fd = packet.c;

                    let desc = context::current()?
                        .read()
                        .remove_file(FileHandle::from(fd))
                        .ok_or(Error::new(EINVAL))?
                        .description;

                    self.respond(packet.id, Response::Fd(desc))?;
                }
                SKMSG_FOBTAINFD => {
                    let flags = FobtainFdFlags::from_bits(packet.d).ok_or(Error::new(EINVAL))?;
                    let description = match self
                        .states
                        .lock()
                        .get_mut(&packet.id)
                        .ok_or(Error::new(EINVAL))?
                    {
                        State::Waiting { ref mut fd, .. } => fd.take().ok_or(Error::new(ENOENT))?,
                        _ => return Err(Error::new(ENOENT)),
                    };

                    // FIXME: Description can leak if context::current() fails, or if there is no
                    // additional file table space.
                    if flags.contains(FobtainFdFlags::MANUAL_FD) {
                        context::current()?.read().insert_file(
                            FileHandle::from(packet.c),
                            FileDescriptor {
                                description,
                                cloexec: true,
                            },
                        );
                    } else {
                        let fd = context::current()?
                            .read()
                            .add_file(FileDescriptor {
                                description,
                                cloexec: true,
                            })
                            .ok_or(Error::new(EMFILE))?;
                        UserSlice::wo(packet.c, size_of::<usize>())?.write_usize(fd.get())?;
                    }
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

                    if page_count != 1 {
                        return Err(Error::new(EINVAL));
                    }

                    let context = match self.states.lock().entry(packet.id) {
                        Entry::Occupied(mut o) => {
                            match mem::replace(o.get_mut(), State::Placeholder) {
                                // invalid state
                                State::Placeholder => {
                                    return Err(Error::new(EBADFD));
                                }
                                // invalid kernel to scheme call
                                old_state @ (State::Waiting { .. } | State::Responded(_)) => {
                                    *o.get_mut() = old_state;
                                    return Err(Error::new(EINVAL));
                                }
                                State::Fmap(context) => {
                                    o.remove();
                                    context
                                }
                            }
                        }
                        Entry::Vacant(_) => return Err(Error::new(EINVAL)),
                    };

                    let context = context.upgrade().ok_or(Error::new(ESRCH))?;

                    let (frame, _) = AddrSpace::current()?
                        .acquire_read()
                        .table
                        .utable
                        .translate(base_addr)
                        .ok_or(Error::new(EFAULT))?;

                    let mut context = context.write();
                    match context.status {
                        Status::HardBlocked {
                            reason: HardBlockedReason::AwaitingMmap { .. },
                        } => context.status = Status::Runnable,
                        _ => (),
                    }
                    context.fmap_ret = Some(Frame::containing_address(frame));
                }
                _ => return Err(Error::new(EINVAL)),
            }
        } else {
            self.respond(packet.id, Response::Regular(packet.a))?;
        }

        Ok(())
    }
    fn respond(&self, id: u64, mut response: Response) -> Result<()> {
        let to_close;

        match self.states.lock().entry(id) {
            Entry::Occupied(mut o) => match mem::replace(o.get_mut(), State::Placeholder) {
                // invalid state
                State::Placeholder => return Err(Error::new(EBADFD)),
                // invalid scheme to kernel call
                old_state @ (State::Responded(_) | State::Fmap(_)) => {
                    *o.get_mut() = old_state;
                    return Err(Error::new(EINVAL));
                }

                State::Waiting { context, fd, canceling } => {
                    if let Response::Regular(ref mut code) = response && !canceling && *code == Error::mux(Err(Error::new(EINTR))) {
                        // EINTR is valid after cancelation has been requested, but not otherwise.
                        // This is because the kernel-assisted signal trampoline will be invoked
                        // after a syscall returns EINTR.
                        //
                        // TODO: Reserve another error code for user-caused vs kernel-caused EINTR?
                        *code = Error::mux(Err(Error::new(EIO)));
                    }

                    to_close = fd
                        .and_then(|f| Arc::try_unwrap(f).ok())
                        .map(RwLock::into_inner);

                    if let Some(context) = context.upgrade() {
                        context.write().unblock();
                        *o.get_mut() = State::Responded(response);
                    } else {
                        o.remove();
                    }
                }
            },
            // invalid state
            Entry::Vacant(_) => return Err(Error::new(EBADFD)),
        }

        if let Some(to_close) = to_close {
            let _ = to_close.try_close();
        }
        Ok(())
    }

    pub fn fevent(&self, _flags: EventFlags) -> Result<EventFlags> {
        Ok(EventFlags::empty())
    }

    pub fn fsync(&self) -> Result<()> {
        Ok(())
    }

    fn fmap_inner(
        &self,
        dst_addr_space: Arc<AddrSpaceWrapper>,
        file: usize,
        map: &Map,
    ) -> Result<usize> {
        let unaligned_size = map.size;

        if unaligned_size == 0 {
            return Err(Error::new(EINVAL));
        }

        let page_count = unaligned_size.div_ceil(PAGE_SIZE);

        if map.address % PAGE_SIZE != 0 {
            return Err(Error::new(EINVAL));
        };
        let dst_base = (map.address != 0)
            .then_some(Page::containing_address(VirtualAddress::new(map.address)));

        if map.offset % PAGE_SIZE != 0 {
            return Err(Error::new(EINVAL));
        }

        let src_address_space = Arc::clone(
            self.context
                .upgrade()
                .ok_or(Error::new(ENODEV))?
                .read()
                .addr_space()?,
        );
        if Arc::ptr_eq(&src_address_space, &dst_addr_space) {
            return Err(Error::new(EBUSY));
        }

        let (pid, desc) = {
            let context_lock = context::current()?;
            let context = context_lock.read();
            // TODO: Faster, cleaner mechanism to get descriptor
            let mut desc_res = Err(Error::new(EBADF));
            for context_file in context.files.read().iter().flatten() {
                let (context_scheme, context_number) = {
                    let desc = context_file.description.read();
                    (desc.scheme, desc.number)
                };
                if context_scheme == self.scheme_id && context_number == file {
                    desc_res = Ok(context_file.clone());
                    break;
                }
            }
            let desc = desc_res?;
            (context.id, desc.description)
        };

        let response = self.call_extended_inner(
            None,
            Packet {
                id: self.next_id(),
                pid: pid.into(),
                a: KSMSG_MMAP_PREP,
                b: file,
                c: unaligned_size,
                d: map.flags.bits(),
                // The uid and gid can be obtained by the proc scheme anyway, if the pid is provided.
                uid: map.offset as u32,
                #[cfg(target_pointer_width = "64")]
                gid: (map.offset >> 32) as u32,
                #[cfg(target_pointer_width = "32")]
                gid: 0,
            },
        )?;

        // TODO: I've previously tested that this works, but because the scheme trait all of
        // Redox's schemes currently rely on doesn't allow one-way messages, there's no current
        // code using it.

        //let mapping_is_lazy = map.flags.contains(MapFlags::MAP_LAZY);
        let mapping_is_lazy = false;

        let base_page_opt = match response {
            Response::Regular(code) => (!mapping_is_lazy).then_some(Error::demux(code)?),
            Response::Fd(_) => {
                log::debug!("Scheme incorrectly returned an fd for fmap.");

                return Err(Error::new(EIO));
            }
        };

        let file_ref = GrantFileRef {
            description: desc,
            base_offset: map.offset,
        };

        let src = match base_page_opt {
            Some(base_addr) => Some({
                if base_addr % PAGE_SIZE != 0 {
                    return Err(Error::new(EINVAL));
                }
                let addr_space_lock = &src_address_space;
                BorrowedFmapSource {
                    src_base: Page::containing_address(VirtualAddress::new(base_addr)),
                    addr_space_lock,
                    addr_space_guard: addr_space_lock.acquire_write(),
                    mode: if map.flags.contains(MapFlags::MAP_SHARED) {
                        MmapMode::Shared
                    } else {
                        MmapMode::Cow
                    },
                }
            }),
            None => None,
        };

        let page_count_nz = NonZeroUsize::new(page_count).expect("already validated map.size != 0");
        let mut notify_files = Vec::new();
        let dst_base = dst_addr_space.acquire_write().mmap(
            &dst_addr_space,
            dst_base,
            page_count_nz,
            map.flags,
            &mut notify_files,
            |dst_base, flags, mapper, flusher| {
                Grant::borrow_fmap(
                    PageSpan::new(dst_base, page_count),
                    flags,
                    file_ref,
                    src,
                    &dst_addr_space,
                    mapper,
                    flusher,
                )
            },
        )?;

        for map in notify_files {
            let _ = map.unmap();
        }

        Ok(dst_base.start_address().data())
    }
}
pub struct CaptureGuard<const READ: bool, const WRITE: bool> {
    destroyed: bool,
    base: usize,
    len: usize,

    space: Option<Arc<AddrSpaceWrapper>>,

    head: CopyInfo<READ, WRITE>,
    tail: CopyInfo<READ, WRITE>,
}
impl<const READ: bool, const WRITE: bool> CaptureGuard<READ, WRITE> {
    fn base(&self) -> usize {
        self.base
    }
    fn len(&self) -> usize {
        self.len
    }
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
        if let CopyInfo {
            src: Some(ref src),
            dst: Some(ref mut dst),
        } = self.head
        {
            result = result.and_then(|()| {
                dst.copy_from_slice(&src.buf()[self.base % PAGE_SIZE..][..dst.len()])
            });
        }
        if let CopyInfo {
            src: Some(ref src),
            dst: Some(ref mut dst),
        } = self.tail
        {
            result = result.and_then(|()| dst.copy_from_slice(&src.buf()[..dst.len()]));
        }
        let Some(space) = self.space.take() else {
            return result;
        };

        let (first_page, page_count, _offset) = page_range_containing(self.base, self.len);

        let unpin = true;
        space.munmap(PageSpan::new(first_page, page_count), unpin)?;

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
#[derive(Clone)]
pub struct UserScheme {
    pub(crate) inner: Weak<UserInner>,
}

impl UserScheme {
    pub fn new(inner: Weak<UserInner>) -> UserScheme {
        UserScheme { inner }
    }
}

impl KernelScheme for UserScheme {
    fn kopen(&self, path: &str, flags: usize, ctx: CallerCtx) -> Result<OpenResult> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let address = inner.copy_and_capture_tail(path.as_bytes())?;
        match inner.call_extended(ctx, None, [SYS_OPEN, address.base(), address.len(), flags])? {
            Response::Regular(code) => Error::demux(code).map(OpenResult::SchemeLocal),
            Response::Fd(desc) => Ok(OpenResult::External(desc)),
        }
    }
    fn rmdir(&self, path: &str, _ctx: CallerCtx) -> Result<()> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let address = inner.copy_and_capture_tail(path.as_bytes())?;
        inner.call(SYS_RMDIR, address.base(), address.len(), 0)?;
        Ok(())
    }

    fn unlink(&self, path: &str, _ctx: CallerCtx) -> Result<()> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let address = inner.copy_and_capture_tail(path.as_bytes())?;
        inner.call(SYS_UNLINK, address.base(), address.len(), 0)?;
        Ok(())
    }

    fn seek(&self, file: usize, position: isize, whence: usize) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        inner.call(SYS_LSEEK, file, position as usize, whence)
    }

    fn fchmod(&self, file: usize, mode: u16) -> Result<()> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        inner.call(SYS_FCHMOD, file, mode as usize, 0)?;
        Ok(())
    }

    fn fchown(&self, file: usize, uid: u32, gid: u32) -> Result<()> {
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
        inner.call(SYS_FCHOWN, file, uid as usize, gid as usize)?;
        Ok(())
    }

    fn fcntl(&self, file: usize, cmd: usize, arg: usize) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        inner.call(SYS_FCNTL, file, cmd, arg)
    }

    fn fevent(&self, file: usize, flags: EventFlags) -> Result<EventFlags> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        inner
            .call(SYS_FEVENT, file, flags.bits(), 0)
            .map(EventFlags::from_bits_truncate)
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

    fn frename(&self, file: usize, path: &str, _ctx: CallerCtx) -> Result<()> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let address = inner.copy_and_capture_tail(path.as_bytes())?;
        inner.call(SYS_FRENAME, file, address.base(), address.len())?;
        Ok(())
    }

    fn fsync(&self, file: usize) -> Result<()> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        inner.call(SYS_FSYNC, file, 0, 0)?;
        Ok(())
    }

    fn ftruncate(&self, file: usize, len: usize) -> Result<()> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        inner.call(SYS_FTRUNCATE, file, len, 0)?;
        Ok(())
    }

    fn close(&self, file: usize) -> Result<()> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        inner.call(SYS_CLOSE, file, 0, 0)?;
        Ok(())
    }
    fn kdup(&self, file: usize, buf: UserSliceRo, ctx: CallerCtx) -> Result<OpenResult> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let address = inner.capture_user(buf)?;
        let result = inner.call_extended(ctx, None, [SYS_DUP, file, address.base(), address.len()]);

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
    fn kfstat(&self, file: usize, stat: UserSliceWo) -> Result<()> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let address = inner.capture_user(stat)?;
        let result = inner.call(SYS_FSTAT, file, address.base(), address.len());
        address.release()?;
        result.map(|_| ())
    }
    fn kfstatvfs(&self, file: usize, stat: UserSliceWo) -> Result<()> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let address = inner.capture_user(stat)?;
        let result = inner.call(SYS_FSTATVFS, file, address.base(), address.len());
        address.release()?;
        result.map(|_| ())
    }
    fn kfmap(
        &self,
        file: usize,
        addr_space: &Arc<AddrSpaceWrapper>,
        map: &Map,
        _consume: bool,
    ) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;

        inner.fmap_inner(Arc::clone(addr_space), file, map)
    }
    fn kfunmap(&self, number: usize, offset: usize, size: usize, flags: MunmapFlags) -> Result<()> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;

        let res = inner.call_extended(
            CallerCtx {
                pid: context::context_id().into(),
                uid: offset as u32,
                #[cfg(target_pointer_width = "64")]
                gid: (offset >> 32) as u32,

                // TODO: saturating_shr?
                #[cfg(not(target_pointer_width = "64"))]
                gid: 0,
            },
            None,
            [KSMSG_MUNMAP, number, size, flags.bits()],
        )?;

        match res {
            Response::Regular(_) => Ok(()),
            Response::Fd(_) => Err(Error::new(EIO)),
        }
    }
    fn ksendfd(
        &self,
        number: usize,
        desc: Arc<RwLock<FileDescription>>,
        flags: SendFdFlags,
        arg: u64,
    ) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;

        let res = inner.call_extended(
            CallerCtx {
                pid: context::context_id().into(),
                uid: arg as u32,
                gid: (arg >> 32) as u32,
            },
            Some(desc),
            [SYS_SENDFD, number, flags.bits(), 0],
        )?;

        match res {
            Response::Regular(res) => Ok(res),
            Response::Fd(_) => Err(Error::new(EIO)),
        }
    }
}

#[derive(PartialEq)]
pub enum Mode {
    Ro,
    Wo,
}
