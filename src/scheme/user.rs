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
};
use slab::Slab;
use spin::{Mutex, RwLock};
use syscall::{
    schemev2::{Cqe, CqeOpcode, Opcode, Sqe, SqeFlags},
    CallFlags, FmoveFdFlags, FobtainFdFlags, MunmapFlags, RecvFdFlags, SchemeSocketCall,
    SendFdFlags, MAP_FIXED_NOREPLACE,
};

use crate::{
    context::{
        self,
        context::HardBlockedReason,
        file::{FileDescription, FileDescriptor, InternalFlags},
        memory::{
            AddrSpace, AddrSpaceWrapper, BorrowedFmapSource, Grant, GrantFileRef, MmapMode,
            PageSpan, DANGLING,
        },
        BorrowedHtBuf, ContextLock, PreemptGuard, Status,
    },
    event,
    memory::Frame,
    paging::{Page, VirtualAddress, PAGE_SIZE},
    scheme::SchemeId,
    sync::{CleanLockToken, WaitQueue},
    syscall::{
        data::Map,
        error::*,
        flag::{EventFlags, MapFlags, EVENT_READ, O_NONBLOCK, PROT_READ},
        usercopy::{UserSlice, UserSliceRo, UserSliceRw, UserSliceWo},
    },
};

use super::{CallerCtx, FileHandle, KernelScheme, OpenResult};

pub struct UserInner {
    root_id: SchemeId,
    handle_id: usize,
    pub name: Box<str>,
    pub scheme_id: SchemeId,
    supports_on_close: bool,
    context: Weak<ContextLock>,
    todo: WaitQueue<Sqe>,

    // TODO: custom packed radix tree data structure
    states: Mutex<Slab<State>>,

    unmounting: AtomicBool,
}

enum State {
    Waiting {
        context: Weak<ContextLock>,
        fds: Option<Vec<Arc<RwLock<FileDescription>>>>,
        callee_responsible: PageSpan,
        canceling: bool,
    },
    Responded(Response),
    Fmap(Weak<ContextLock>),
    Placeholder,
}

#[derive(Debug)]
pub enum Response {
    Regular(usize, u8),
    Fd(Arc<RwLock<FileDescription>>),
    MultipleFds(Option<Vec<Arc<RwLock<FileDescription>>>>),
}

const ONE: NonZeroUsize = match NonZeroUsize::new(1) {
    Some(one) => one,
    None => unreachable!(),
};

enum ParsedCqe {
    TriggerFevent {
        number: usize,
        flags: EventFlags,
    },
    RegularResponse {
        tag: u32,
        code: usize,
        extra0: u8,
    },
    ResponseWithFd {
        tag: u32,
        fd: usize,
    },
    ResponseWithMultipleFds {
        tag: u32,
        num_fds: usize,
    },
    ObtainFd {
        tag: u32,
        flags: FobtainFdFlags,
        dst_fd_or_ptr: usize,
    },
    ProvideMmap {
        tag: u32,
        offset: u64,
        base_addr: VirtualAddress,
        page_count: usize,
    },
}
impl ParsedCqe {
    fn parse_cqe(cqe: &Cqe) -> Result<Self> {
        Ok(
            match CqeOpcode::try_from_raw(cqe.flags & 0b111).ok_or(Error::new(EINVAL))? {
                CqeOpcode::RespondRegular => Self::RegularResponse {
                    tag: cqe.tag,
                    code: cqe.result as usize,
                    extra0: cqe.extra_raw[0],
                },
                CqeOpcode::RespondWithFd => Self::ResponseWithFd {
                    tag: cqe.tag,
                    fd: cqe.result as usize,
                },
                CqeOpcode::RespondWithMultipleFds => Self::ResponseWithMultipleFds {
                    tag: cqe.tag,
                    num_fds: cqe.result as usize,
                },
                CqeOpcode::SendFevent => Self::TriggerFevent {
                    number: cqe.result as usize,
                    flags: EventFlags::from_bits(cqe.tag as usize).ok_or(Error::new(EINVAL))?,
                },
                CqeOpcode::ObtainFd => Self::ObtainFd {
                    tag: cqe.tag,
                    flags: FobtainFdFlags::from_bits(cqe.extra() as usize)
                        .ok_or(Error::new(EINVAL))?,
                    dst_fd_or_ptr: cqe.result as usize,
                },
            },
        )
    }
}

impl UserInner {
    pub fn new(
        root_id: SchemeId,
        scheme_id: SchemeId,
        new_close: bool,
        handle_id: usize,
        name: Box<str>,
        _flags: usize,
        context: Weak<ContextLock>,
    ) -> UserInner {
        UserInner {
            root_id,
            handle_id,
            name,
            supports_on_close: new_close,
            scheme_id,
            context,
            todo: WaitQueue::new(),
            unmounting: AtomicBool::new(false),
            states: Mutex::new(Slab::with_capacity(32)),
        }
    }

    pub fn unmount(&self, token: &mut CleanLockToken) -> Result<()> {
        // First, block new requests and prepare to return EOF
        self.unmounting.store(true, Ordering::SeqCst);

        // Wake up any blocked scheme handler
        unsafe { self.todo.condition.notify_signal(token) };

        // Tell the scheme handler to read
        event::trigger(self.root_id, self.handle_id, EVENT_READ);

        //TODO: wait for all todo and done to be processed?
        Ok(())
    }

    fn next_id(&self) -> Result<u32> {
        let idx = {
            let mut states = self.states.lock();
            states.insert(State::Placeholder)
        };

        // TODO: implement blocking?
        u32::try_from(idx).map_err(|_| Error::new(EAGAIN))
    }

    pub fn call(
        &self,
        opcode: Opcode,
        args: impl Args,
        caller_responsible: &mut PageSpan,
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        let ctx = { context::current().read(token.token()).caller_ctx() };
        match self.call_extended(ctx, None, opcode, args, caller_responsible, token)? {
            Response::Regular(code, _) => Error::demux(code),
            Response::Fd(_) => Err(Error::new(EIO)),
            Response::MultipleFds(_) => Err(Error::new(EIO)),
        }
    }

    pub fn call_extended(
        &self,
        ctx: CallerCtx,
        fds: Option<Vec<Arc<RwLock<FileDescription>>>>,
        opcode: Opcode,
        args: impl Args,
        caller_responsible: &mut PageSpan,
        token: &mut CleanLockToken,
    ) -> Result<Response> {
        let next_id = self.next_id()?;
        self.call_extended_inner(
            fds,
            Sqe {
                opcode: opcode as u8,
                sqe_flags: SqeFlags::empty(),
                _rsvd: 0,
                tag: next_id,
                caller: ctx.pid as u64,
                args: {
                    let mut a = args.args();
                    a[5] = uid_gid_hack_merge([ctx.uid, ctx.gid]);
                    a
                },
            },
            caller_responsible,
            token,
        )
    }

    fn call_extended_inner(
        &self,
        fds: Option<Vec<Arc<RwLock<FileDescription>>>>,
        sqe: Sqe,
        caller_responsible: &mut PageSpan,
        token: &mut CleanLockToken,
    ) -> Result<Response> {
        if self.unmounting.load(Ordering::SeqCst) {
            return Err(Error::new(ENODEV));
        }

        {
            // Disable preemption to avoid context switches between setting the
            // process state and sending the scheme request. The process is made
            // runnable again when the scheme response is received. Hence, we
            // need to ensure that the following operations are atomic as
            // otherwise the process will be blocked forever.
            let current_context = context::current();
            let mut preempt = PreemptGuard::new(&current_context, token);
            let token = preempt.token();
            current_context
                .write(token.token())
                .block("UserInner::call");
            {
                let mut states = self.states.lock();
                states[sqe.tag as usize] = State::Waiting {
                    context: Arc::downgrade(&current_context),
                    fds,
                    canceling: false,

                    // This is the part that the scheme handler will deallocate when responding. It
                    // starts as empty, so the caller can unmap it (optimal for TLB), but is populated
                    // the caller is interrupted by SIGKILL.
                    callee_responsible: PageSpan::empty(),
                };
            }
            self.todo.send(sqe, token);

            event::trigger(self.root_id, self.handle_id, EVENT_READ);
        }

        loop {
            context::switch(token);

            {
                let mut eintr_if_sigkill = |callee_responsible: &mut PageSpan| {
                    // If SIGKILL was found without waiting for scheme, EINTR directly. In that
                    // case, data loss doesn't matter.
                    if context::current().read(token.token()).being_sigkilled {
                        // Callee must deallocate memory, rather than the caller. This is less optimal
                        // for TLB, but we don't really have any other choice. The scheme must be able
                        // to access the borrowed memory until it has responded to the request.
                        *callee_responsible =
                            core::mem::replace(caller_responsible, PageSpan::empty());

                        Err(Error::new(EINTR))
                    } else {
                        Ok(())
                    }
                };

                let mut states = self.states.lock();
                match states.get_mut(sqe.tag as usize) {
                    // invalid state
                    None => return Err(Error::new(EBADFD)),
                    Some(o) => match mem::replace(o, State::Placeholder) {
                        // signal wakeup while awaiting cancelation
                        State::Waiting {
                            canceling: true,
                            mut callee_responsible,
                            context,
                            fds,
                        } => {
                            let maybe_eintr = eintr_if_sigkill(&mut callee_responsible);
                            *o = State::Waiting {
                                canceling: true,
                                callee_responsible,
                                context,
                                fds,
                            };

                            maybe_eintr?;

                            context::current()
                                .write(token.token())
                                .block("UserInner::call (woken up after cancelation request)");

                            // We do not want to drop the lock before blocking
                            // as if we get preempted in between we might miss a
                            // wakeup.
                            drop(states);
                        }
                        // spurious wakeup
                        State::Waiting {
                            canceling: false,
                            fds,
                            context,
                            mut callee_responsible,
                        } => {
                            let maybe_eintr = eintr_if_sigkill(&mut callee_responsible);
                            let current_context = context::current();

                            *o = State::Waiting {
                                // Currently we treat all spurious wakeups to have the same behavior
                                // as signals (i.e., we send a cancellation request). It is not something
                                // that should happen, but it certainly can happen, for example if a context
                                // is awoken through its thread handle without setting any sig bits, or if the
                                // caller clears its own sig bits. If it actually is a signal, then it is the
                                // intended behavior.
                                canceling: true,
                                fds,
                                context,
                                callee_responsible,
                            };

                            maybe_eintr?;

                            // We do not want to preempt between sending the
                            // cancellation and blocking again where we might
                            // miss a wakeup.
                            let mut preempt = PreemptGuard::new(&current_context, token);
                            let token = preempt.token();

                            self.todo.send(
                                Sqe {
                                    opcode: Opcode::Cancel as u8,
                                    sqe_flags: SqeFlags::ONEWAY,
                                    tag: sqe.tag,
                                    ..Default::default()
                                },
                                token,
                            );
                            event::trigger(self.root_id, self.handle_id, EVENT_READ);

                            // 1. If cancellation was requested and arrived
                            // before the scheme processed the request, an
                            // acknowledgement will be sent back after the
                            // cancellation is processed and we will be woken up
                            // again. State will be State::Responded then.
                            //
                            // 2. If cancellation was requested but the scheme
                            // already processed the request, we will receive
                            // the actual response next and woken up again.
                            // State will be State::Responded then.
                            context::current()
                                .write(token.token())
                                .block("UserInner::call (spurious wakeup)");
                            drop(states);
                        }

                        // invalid state
                        old_state @ (State::Placeholder | State::Fmap(_)) => {
                            *o = old_state;
                            return Err(Error::new(EBADFD));
                        }

                        State::Responded(response) => {
                            states.remove(sqe.tag as usize);
                            return Ok(response);
                        }
                    },
                }
            }
        }
    }

    /// Map a readable structure to the scheme's userspace and return the
    /// pointer
    #[must_use = "copying back to head/tail buffers can fail"]
    pub fn capture_user<const READ: bool, const WRITE: bool>(
        &self,
        buf: UserSlice<READ, WRITE>,
        token: &mut CleanLockToken,
    ) -> Result<CaptureGuard<READ, WRITE>> {
        UserInner::capture_inner(&self.context, buf, token)
    }
    pub fn copy_and_capture_tail(
        &self,
        buf: &[u8],
        token: &mut CleanLockToken,
    ) -> Result<CaptureGuard<false, false>> {
        let dst_addr_space = {
            Arc::clone(
                self.context
                    .upgrade()
                    .ok_or(Error::new(ENODEV))?
                    .read(token.token())
                    .addr_space()?,
            )
        };

        let mut tail = BorrowedHtBuf::tail(token)?;
        let tail_frame = tail.frame();
        if buf.len() > tail.buf().len() {
            return Err(Error::new(EINVAL));
        }
        tail.buf_mut()[..buf.len()].copy_from_slice(buf);

        let is_pinned = true;
        let dst_page = {
            dst_addr_space.acquire_write().mmap_anywhere(
                &dst_addr_space,
                ONE,
                PROT_READ,
                |dst_page, flags, mapper, flusher| {
                    Grant::allocated_shared_one_page(
                        tail_frame, dst_page, flags, mapper, flusher, is_pinned,
                    )
                },
            )?
        };

        let base = dst_page.start_address().data();
        let len = buf.len();

        Ok(CaptureGuard {
            base,
            len,
            destroyed: false,
            head: CopyInfo {
                src: Some(tail),
                dst: None,
            },
            tail: CopyInfo {
                src: None,
                dst: None,
            },
            span: {
                let (first_page, page_count, _offset) = page_range_containing(base, len);
                PageSpan::new(first_page, page_count)
            },
            addrsp: Some(dst_addr_space),
        })
    }

    // TODO: Use an address space Arc over a context Arc. While contexts which share address spaces
    // still can access borrowed scheme pages, it would both be cleaner and would handle the case
    // where the initial context is closed.
    /// Capture a buffer owned by userspace, mapping it contiguously onto scheme memory.
    // TODO: Hypothetical accept_head_leak, accept_tail_leak options might be useful for
    // libc-controlled buffer pools.
    fn capture_inner<const READ: bool, const WRITE: bool>(
        context_weak: &Weak<ContextLock>,
        user_buf: UserSlice<READ, WRITE>,
        token: &mut CleanLockToken,
    ) -> Result<CaptureGuard<READ, WRITE>> {
        let mut map_flags = MapFlags::empty();
        map_flags.set(MapFlags::PROT_READ, READ);
        map_flags.set(MapFlags::PROT_WRITE, WRITE);

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
                head: CopyInfo {
                    src: None,
                    dst: None,
                },
                tail: CopyInfo {
                    src: None,
                    dst: None,
                },
                span: PageSpan::empty(),
                addrsp: None,
            });
        }

        let cur_space_lock = AddrSpace::current()?;
        let dst_space_lock = {
            Arc::clone(
                context_weak
                    .upgrade()
                    .ok_or(Error::new(ESRCH))?
                    .read(token.token())
                    .addr_space()?,
            )
        };

        if Arc::ptr_eq(&dst_space_lock, &cur_space_lock) {
            // Same address space, no need to remap anything!
            return Ok(CaptureGuard {
                destroyed: false,
                base: user_buf.addr(),
                len: user_buf.len(),
                head: CopyInfo {
                    src: None,
                    dst: None,
                },
                tail: CopyInfo {
                    src: None,
                    dst: None,
                },
                span: PageSpan::empty(),
                addrsp: Some(dst_space_lock),
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
            let mut array = BorrowedHtBuf::head(token)?;
            let frame = array.frame();

            let len = core::cmp::min(PAGE_SIZE - offset, user_buf.len());

            if READ {
                array.buf_mut()[..offset].fill(0_u8);
                array.buf_mut()[offset + len..].fill(0_u8);

                let slice = &mut array.buf_mut()[offset..][..len];
                let head_part_of_buf = user_buf.limit(len).expect("always smaller than max len");

                head_part_of_buf
                    .reinterpret_unchecked::<true, false>()
                    .copy_to_slice(slice)?;
            } else {
                array.buf_mut().fill(0_u8);
            }

            dst_space.mmap(
                &dst_space_lock,
                Some(free_span.base),
                ONE,
                map_flags | MAP_FIXED_NOREPLACE,
                &mut Vec::new(),
                move |dst_page, page_flags, mapper, flusher| {
                    let is_pinned = true;
                    Grant::allocated_shared_one_page(
                        frame, dst_page, page_flags, mapper, flusher, is_pinned,
                    )
                },
            )?;

            let head = CopyInfo {
                src: Some(array),
                dst: WRITE.then_some(head_part_of_buf.reinterpret_unchecked()),
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

                    Grant::borrow(
                        Arc::clone(&cur_space_lock),
                        &mut cur_space_lock.acquire_write(),
                        first_middle_src_page,
                        dst_page,
                        middle_page_count.get(),
                        map_flags,
                        mapper,
                        flusher,
                        eager,
                        allow_phys,
                        is_pinned_userscheme_borrow,
                    )
                },
            )?;
        }

        let tail = if !tail_part_of_buf.is_empty() {
            let tail_dst_page = first_middle_dst_page.next_by(middle_page_count);

            // FIXME: Signal context can probably recursively use head/tail.
            let mut array = BorrowedHtBuf::tail(token)?;
            let frame = array.frame();

            if READ {
                let (to_copy, to_zero) = array.buf_mut().split_at_mut(tail_size);

                to_zero.fill(0_u8);

                // FIXME: remove reinterpret_unchecked
                tail_part_of_buf
                    .reinterpret_unchecked::<true, false>()
                    .copy_to_slice(to_copy)?;
            } else {
                array.buf_mut().fill(0_u8);
            }

            dst_space.mmap(
                &dst_space_lock,
                Some(tail_dst_page),
                ONE,
                map_flags | MAP_FIXED_NOREPLACE,
                &mut Vec::new(),
                move |dst_page, page_flags, mapper, flusher| {
                    let is_pinned = true;
                    Grant::allocated_shared_one_page(
                        frame, dst_page, page_flags, mapper, flusher, is_pinned,
                    )
                },
            )?;

            CopyInfo {
                src: Some(array),
                dst: WRITE.then_some(tail_part_of_buf.reinterpret_unchecked()),
            }
        } else {
            CopyInfo {
                src: None,
                dst: None,
            }
        };

        drop(dst_space);

        let base = free_span.base.start_address().data() + offset;
        Ok(CaptureGuard {
            destroyed: false,
            base,
            len: user_buf.len(),
            head,
            tail,
            span: {
                let (first_page, page_count, _offset) = page_range_containing(base, user_buf.len());
                PageSpan::new(first_page, page_count)
            },
            addrsp: Some(dst_space_lock),
        })
    }

    pub fn read(&self, buf: UserSliceWo, flags: u32, token: &mut CleanLockToken) -> Result<usize> {
        // If O_NONBLOCK is used, do not block
        let nonblock = flags & O_NONBLOCK as u32 != 0;

        // If unmounting, do not block so that EOF can be returned immediately
        let block = !(nonblock || self.unmounting.load(Ordering::SeqCst));

        match self
            .todo
            .receive_into_user(buf, block, "UserInner::read (v2)", token)
        {
            // If we received requests, return them to the scheme handler
            Ok(byte_count) => Ok(byte_count),
            // If there were no requests and we were unmounting, return EOF
            Err(Error { errno: EAGAIN }) if self.unmounting.load(Ordering::SeqCst) => Ok(0),
            // If there were no requests and O_NONBLOCK was used (EAGAIN), or some other error
            // occurred, return that.
            Err(error) => Err(error),
        }
    }

    pub fn write(&self, buf: UserSliceRo, token: &mut CleanLockToken) -> Result<usize> {
        let mut bytes_read = 0;
        for chunk in buf.in_exact_chunks(size_of::<Cqe>()) {
            match ParsedCqe::parse_cqe(&unsafe { chunk.read_exact::<Cqe>()? })
                .and_then(|p| self.handle_parsed(&p, token))
            {
                Ok(()) => bytes_read += size_of::<Cqe>(),
                Err(_) if bytes_read > 0 => break,
                Err(error) => return Err(error),
            }
        }
        Ok(bytes_read)
    }
    pub fn request_fmap(
        &self,
        id: usize,
        _offset: u64,
        required_page_count: usize,
        flags: MapFlags,
        token: &mut CleanLockToken,
    ) -> Result<()> {
        info!("REQUEST FMAP");

        let tag = self.next_id()?;
        {
            let mut states = self.states.lock();
            states[tag as usize] = State::Fmap(Arc::downgrade(&context::current()));
        }

        self.todo.send(
            Sqe {
                opcode: Opcode::RequestMmap as u8,
                sqe_flags: SqeFlags::empty(),
                _rsvd: 0,
                tag,
                args: [
                    id as u64,
                    flags.bits() as u64,
                    required_page_count as u64,
                    0,
                    0,
                    uid_gid_hack_merge(current_uid_gid(token)),
                ],
                caller: { context::current().read(token.token()).pid as u64 },
            },
            token,
        );
        event::trigger(self.root_id, self.handle_id, EVENT_READ);

        Ok(())
    }
    fn handle_parsed(&self, cqe: &ParsedCqe, token: &mut CleanLockToken) -> Result<()> {
        match *cqe {
            ParsedCqe::RegularResponse { tag, code, extra0 } => {
                self.respond(tag, Response::Regular(code, extra0), token)?
            }
            ParsedCqe::ResponseWithFd { tag, fd } => self.respond(
                tag,
                Response::Fd({
                    context::current()
                        .read(token.token())
                        .remove_file(FileHandle::from(fd))
                        .ok_or(Error::new(EINVAL))?
                        .description
                }),
                token,
            )?,
            ParsedCqe::ResponseWithMultipleFds { tag, num_fds: _ } => {
                self.respond(tag, Response::MultipleFds(None), token)?;
            }
            ParsedCqe::ObtainFd {
                tag,
                flags,
                dst_fd_or_ptr,
            } => {
                let description = {
                    match self
                        .states
                        .lock()
                        .get_mut(tag as usize)
                        .ok_or(Error::new(EINVAL))?
                    {
                        &mut State::Waiting { ref mut fds, .. } => {
                            fds.take().ok_or(Error::new(ENOENT))?.remove(0)
                        }
                        _ => return Err(Error::new(ENOENT)),
                    }
                };

                // FIXME: Description can leak if there is no additional file table space.
                if flags.contains(FobtainFdFlags::MANUAL_FD) {
                    context::current().read(token.token()).insert_file(
                        FileHandle::from(dst_fd_or_ptr),
                        FileDescriptor {
                            description,
                            cloexec: true,
                        },
                    );
                } else {
                    let fd = context::current()
                        .read(token.token())
                        .add_file(FileDescriptor {
                            description,
                            cloexec: true,
                        })
                        .ok_or(Error::new(EMFILE))?;
                    UserSlice::wo(dst_fd_or_ptr, size_of::<usize>())?.write_usize(fd.get())?;
                }
            }
            ParsedCqe::ProvideMmap {
                tag,
                offset,
                base_addr,
                page_count,
            } => {
                info!(
                    "PROVIDE_MAP {:x} {:x} {:?} {:x}",
                    tag, offset, base_addr, page_count
                );

                if offset % PAGE_SIZE as u64 != 0 {
                    return Err(Error::new(EINVAL));
                }

                if base_addr.data() % PAGE_SIZE != 0 {
                    return Err(Error::new(EINVAL));
                }

                if page_count != 1 {
                    return Err(Error::new(EINVAL));
                }

                let context = {
                    let mut states = self.states.lock();
                    match states.get_mut(tag as usize) {
                        Some(o) => match mem::replace(o, State::Placeholder) {
                            // invalid state
                            State::Placeholder => {
                                return Err(Error::new(EBADFD));
                            }
                            // invalid kernel to scheme call
                            old_state @ (State::Waiting { .. } | State::Responded(_)) => {
                                *o = old_state;
                                return Err(Error::new(EINVAL));
                            }
                            State::Fmap(context) => {
                                states.remove(tag as usize);
                                context
                            }
                        },
                        None => return Err(Error::new(EINVAL)),
                    }
                };

                let context = context.upgrade().ok_or(Error::new(ESRCH))?;

                let (frame, _) = AddrSpace::current()?
                    .acquire_read()
                    .table
                    .utable
                    .translate(base_addr)
                    .ok_or(Error::new(EFAULT))?;

                {
                    let mut context = context.write(token.token());
                    if let Status::HardBlocked {
                        reason: HardBlockedReason::AwaitingMmap { .. },
                    } = context.status
                    {
                        context.status = Status::Runnable
                    }
                    context.fmap_ret = Some(Frame::containing(frame));
                }
            }
            ParsedCqe::TriggerFevent { number, flags } => {
                event::trigger(self.scheme_id, number, flags)
            }
        }
        Ok(())
    }
    fn respond(&self, tag: u32, mut response: Response, token: &mut CleanLockToken) -> Result<()> {
        let to_close: Vec<FileDescription>;

        {
            let mut states = self.states.lock();
            match states.get_mut(tag as usize) {
                Some(o) => match mem::replace(o, State::Placeholder) {
                    // invalid state
                    State::Placeholder => return Err(Error::new(EBADFD)),
                    // invalid scheme to kernel call
                    old_state @ (State::Responded(_) | State::Fmap(_)) => {
                        *o = old_state;
                        return Err(Error::new(EINVAL));
                    }

                    State::Waiting {
                        context,
                        mut fds,
                        canceling,
                        callee_responsible,
                    } => {
                        // Convert ECANCELED to EINTR if a request was being canceled (currently always
                        // due to signals).
                        if let Response::Regular(ref mut code, _) = response
                            && canceling
                            && *code == Error::mux(Err(Error::new(ECANCELED)))
                        {
                            *code = Error::mux(Err(Error::new(EINTR)));
                        }

                        // TODO: Require ECANCELED?
                        if let Response::Regular(ref mut code, _) = response
                            && !canceling
                            && *code == Error::mux(Err(Error::new(EINTR)))
                        {
                            // EINTR is valid after cancelation has been requested, but not otherwise.
                            // This is because the userspace signal trampoline will be invoked after a
                            // syscall returns EINTR.
                            *code = Error::mux(Err(Error::new(EIO)));
                        }

                        if let Response::MultipleFds(ref mut response_fds) = response {
                            *response_fds = fds.take();
                        }
                        to_close = fds
                            .into_iter()
                            .flatten()
                            .filter_map(|f| Arc::try_unwrap(f).ok())
                            .map(RwLock::into_inner)
                            .collect();

                        match context.upgrade() {
                            Some(context) => {
                                *o = State::Responded(response);
                                context.write(token.token()).unblock();
                            }
                            _ => {
                                states.remove(tag as usize);
                            }
                        }

                        let unpin = true;
                        AddrSpace::current()?.munmap(callee_responsible, unpin)?;
                    }
                },
                // invalid state
                None => return Err(Error::new(EBADFD)),
            }
        }

        for fd in to_close {
            let _ = fd.try_close(token);
        }
        Ok(())
    }

    pub fn fevent(&self, flags: EventFlags) -> Result<EventFlags> {
        // TODO: Should the root scheme also suppress events if `flags` does not contain
        // `EVENT_READ`?
        Ok(if self.todo.is_currently_empty() {
            EventFlags::empty()
        } else {
            EventFlags::EVENT_READ.intersection(flags)
        })
    }

    pub fn fsync(&self) -> Result<()> {
        Ok(())
    }

    fn fmap_inner(
        &self,
        dst_addr_space: Arc<AddrSpaceWrapper>,
        file: usize,
        map: &Map,
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        let unaligned_size = map.size;

        if unaligned_size == 0 {
            return Err(Error::new(EINVAL));
        }

        let page_count = unaligned_size.div_ceil(PAGE_SIZE);

        if map.address % PAGE_SIZE != 0 {
            return Err(Error::new(EINVAL));
        };

        let fixed = map.flags.contains(MapFlags::MAP_FIXED)
            || map.flags.contains(MapFlags::MAP_FIXED_NOREPLACE);
        let dst_base = (map.address != 0 || fixed)
            .then_some(Page::containing_address(VirtualAddress::new(map.address)));

        if map.offset % PAGE_SIZE != 0 {
            return Err(Error::new(EINVAL));
        }

        let src_address_space = {
            Arc::clone(
                self.context
                    .upgrade()
                    .ok_or(Error::new(ENODEV))?
                    .read(token.token())
                    .addr_space()?,
            )
        };
        if Arc::ptr_eq(&src_address_space, &dst_addr_space) {
            return Err(Error::new(EBUSY));
        }

        let (pid, desc) = {
            let context_lock = context::current();
            let context = context_lock.read(token.token());
            let desc = context.files.read().find_by_scheme(self.scheme_id, file)?;
            (context.pid, desc.description)
        };

        let response = self.call_extended_inner(
            None,
            Sqe {
                opcode: Opcode::MmapPrep as u8,
                sqe_flags: SqeFlags::empty(),
                _rsvd: 0,
                tag: self.next_id()?,
                args: [
                    file as u64,
                    unaligned_size as u64,
                    map.flags.bits() as u64,
                    map.offset as u64,
                    0,
                    uid_gid_hack_merge(current_uid_gid(token)),
                ],
                caller: pid as u64,
            },
            &mut PageSpan::empty(),
            token,
        )?;

        // TODO: I've previously tested that this works, but because the scheme trait all of
        // Redox's schemes currently rely on doesn't allow one-way messages, there's no current
        // code using it.

        //let mapping_is_lazy = map.flags.contains(MapFlags::MAP_LAZY);
        let mapping_is_lazy = false;

        let base_page_opt = match response {
            Response::Regular(code, _) => (!mapping_is_lazy).then_some(Error::demux(code)?),
            Response::Fd(_) => {
                debug!("Scheme incorrectly returned an fd for fmap.");

                return Err(Error::new(EIO));
            }
            Response::MultipleFds(_) => return Err(Error::new(EIO)),
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
        let dst_base = {
            dst_addr_space.acquire_write().mmap(
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
                        token,
                    )
                },
            )?
        };

        for map in notify_files {
            let _ = map.unmap(token);
        }

        Ok(dst_base.start_address().data())
    }

    pub fn call_fdwrite(
        &self,
        descs: Vec<Arc<RwLock<FileDescription>>>,
        flags: CallFlags,
        _arg: u64,
        metadata: &[u64],
    ) -> Result<usize> {
        if metadata.is_empty() {
            return Err(Error::new(EINVAL));
        }
        let Some(verb) = SchemeSocketCall::try_from_raw(metadata[0] as usize) else {
            return Err(Error::new(EINVAL));
        };

        match verb {
            SchemeSocketCall::MoveFd => {
                if metadata.len() != 2 {
                    return Err(Error::new(EINVAL));
                }
                let mut movefd_flags = FmoveFdFlags::empty();
                if flags.contains(CallFlags::FD_EXCLUSIVE) {
                    movefd_flags |= FmoveFdFlags::EXCLUSIVE;
                }
                if flags.contains(CallFlags::FD_CLONE) {
                    movefd_flags |= FmoveFdFlags::CLONE;
                }
                self.handle_movefd(descs, metadata[1] as usize, movefd_flags)
            }
            _ => Err(Error::new(EINVAL)),
        }
    }

    fn handle_movefd(
        &self,
        descs: Vec<Arc<RwLock<FileDescription>>>,
        request_id: usize,
        _flags: FmoveFdFlags,
    ) -> Result<usize> {
        let num_fds = descs.len();
        match self
            .states
            .lock()
            .get_mut(request_id)
            .ok_or(Error::new(EINVAL))?
        {
            &mut State::Waiting { ref mut fds, .. } => *fds = Some(descs),
            _ => return Err(Error::new(ENOENT)),
        };

        Ok(num_fds)
    }

    pub fn call_fdread(
        &self,
        payload: UserSliceRw,
        flags: CallFlags,
        metadata: &[u64],
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        if metadata.is_empty() {
            return Err(Error::new(EINVAL));
        }
        debug!(
            "call_fdread: payload: {} metadata: {}",
            payload.len(),
            metadata.len()
        );

        let Some(verb) = SchemeSocketCall::try_from_raw(metadata[0] as usize) else {
            return Err(Error::new(EINVAL));
        };

        match verb {
            SchemeSocketCall::ObtainFd => {
                if metadata.len() != 2 {
                    return Err(Error::new(EINVAL));
                }
                let mut obtainfd_flags = FobtainFdFlags::empty();
                if flags.contains(CallFlags::FD_UPPER) {
                    obtainfd_flags |= FobtainFdFlags::UPPER_TBL;
                }
                if flags.contains(CallFlags::FD_EXCLUSIVE) {
                    obtainfd_flags |= FobtainFdFlags::EXCLUSIVE;
                }
                self.handle_obtainfd(payload, metadata[1] as usize, obtainfd_flags, token)
            }
            _ => Err(Error::new(EINVAL)),
        }
    }

    fn handle_obtainfd(
        &self,
        payload: UserSliceRw,
        request_id: usize,
        flags: FobtainFdFlags,
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        let descriptions = match self
            .states
            .lock()
            .get_mut(request_id)
            .ok_or(Error::new(EINVAL))?
        {
            &mut State::Waiting { ref mut fds, .. } => fds.take().ok_or(Error::new(ENOENT))?,
            _ => return Err(Error::new(ENOENT)),
        };

        let num_fds = if flags.contains(FobtainFdFlags::UPPER_TBL) {
            Self::bulk_insert_fds(descriptions, payload, token)?
        } else {
            Self::bulk_add_fds(descriptions, payload, token)?
        };

        Ok(num_fds)
    }

    fn bulk_add_fds(
        descriptions: Vec<Arc<RwLock<FileDescription>>>,
        payload: UserSliceRw,
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        let cnt = descriptions.len();
        if payload.len() != cnt * size_of::<usize>() {
            return Err(Error::new(EINVAL));
        }
        if descriptions.is_empty() {
            return Ok(0);
        }
        let current_lock = context::current();
        let current = current_lock.write(token.token());

        let files: Vec<FileDescriptor> = descriptions
            .into_iter()
            .map(|description| FileDescriptor {
                description,
                cloexec: true,
            })
            .collect();
        let handles = current
            .bulk_add_files_posix(files)
            .ok_or(Error::new(EMFILE))?;
        let payload_chunks = payload.in_exact_chunks(size_of::<usize>());
        for (handle, chunk) in handles.iter().zip(payload_chunks) {
            chunk.copy_from_slice(&handle.get().to_ne_bytes())?;
        }
        Ok(handles.len())
    }

    fn bulk_insert_fds(
        descriptions: Vec<Arc<RwLock<FileDescription>>>,
        payload: UserSliceRw,
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        let cnt = descriptions.len();
        if payload.len() != cnt * size_of::<usize>() {
            return Err(Error::new(EINVAL));
        }
        if descriptions.is_empty() {
            return Ok(0);
        }
        let files_iter = descriptions.into_iter().map(|description| FileDescriptor {
            description,
            cloexec: true,
        });
        let first_fd = payload
            .in_exact_chunks(size_of::<usize>())
            .next()
            .ok_or(Error::new(EINVAL))?
            .read_usize()?;

        let current_lock = context::current();
        let current = current_lock.write(token.token());

        if first_fd == usize::MAX {
            let files = files_iter.collect::<Vec<_>>();
            let handles = current
                .bulk_insert_files_upper(files)
                .ok_or(Error::new(EMFILE))?;
            let payload_chunks = payload.in_exact_chunks(size_of::<usize>());
            for (handle, chunk) in handles.iter().zip(payload_chunks) {
                chunk.copy_from_slice(&handle.get().to_ne_bytes())?;
            }
            Ok(handles.len())
        } else {
            let handles: Vec<FileHandle> = payload
                .usizes()
                .map(|res| res.map(|i| FileHandle::from(i | syscall::UPPER_FDTBL_TAG)))
                .collect::<Result<_, _>>()?;
            let files = files_iter.collect::<Vec<_>>();
            current.bulk_insert_files_upper_manual(files, &handles)?;
            Ok(handles.len())
        }
    }
}
pub struct CaptureGuard<const READ: bool, const WRITE: bool> {
    destroyed: bool,
    base: usize,
    len: usize,
    span: PageSpan,

    head: CopyInfo<READ, WRITE>,
    tail: CopyInfo<READ, WRITE>,
    addrsp: Option<Arc<AddrSpaceWrapper>>,
}
impl<const READ: bool, const WRITE: bool> CaptureGuard<READ, WRITE> {
    fn base(&self) -> usize {
        self.base
    }
    fn len(&self) -> usize {
        self.len
    }
    fn span(&mut self) -> &mut PageSpan {
        &mut self.span
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

        // TODO: Encode src and dst better using const generics.
        if let CopyInfo {
            src: Some(ref src),
            dst: Some(ref mut dst),
        } = self.head
        {
            dst.copy_from_slice(&src.buf()[self.base % PAGE_SIZE..][..dst.len()])?;
        }
        if let CopyInfo {
            src: Some(ref src),
            dst: Some(ref mut dst),
        } = self.tail
        {
            dst.copy_from_slice(&src.buf()[..dst.len()])?;
        }
        let unpin = true;
        if let Some(ref addrsp) = self.addrsp
            && !self.span.is_empty()
        {
            addrsp.munmap(self.span, unpin)?;
        }

        Ok(())
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
    fn kopen(
        &self,
        path: &str,
        flags: usize,
        ctx: CallerCtx,
        token: &mut CleanLockToken,
    ) -> Result<OpenResult> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let mut address = inner.copy_and_capture_tail(path.as_bytes(), token)?;
        match inner.call_extended(
            ctx,
            None,
            Opcode::Open,
            [address.base(), address.len(), flags],
            address.span(),
            token,
        )? {
            Response::Regular(code, fl) => Ok({
                let _ = Error::demux(code)?;
                OpenResult::SchemeLocal(
                    code,
                    InternalFlags::from_extra0(fl).ok_or(Error::new(EINVAL))?,
                )
            }),
            Response::Fd(desc) => Ok(OpenResult::External(desc)),
            Response::MultipleFds(_) => Err(Error::new(EIO)),
        }
    }

    fn kopenat(
        &self,
        file: usize,
        path: super::StrOrBytes,
        flags: usize,
        fcntl_flags: u32,
        ctx: CallerCtx,
        token: &mut CleanLockToken,
    ) -> Result<OpenResult> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let mut address = inner.copy_and_capture_tail(path.as_bytes(), token)?;
        let result = inner.call_extended(
            ctx,
            None,
            Opcode::OpenAt,
            [file, address.base(), address.len(), flags, fcntl_flags as _],
            address.span(),
            token,
        );

        address.release()?;

        match result? {
            Response::Regular(code, fl) => Ok({
                let fd = Error::demux(code)?;
                OpenResult::SchemeLocal(
                    fd,
                    InternalFlags::from_extra0(fl).ok_or(Error::new(EINVAL))?,
                )
            }),
            Response::Fd(desc) => Ok(OpenResult::External(desc)),
            Response::MultipleFds(_) => Err(Error::new(EIO)),
        }
    }

    fn unlinkat(
        &self,
        file: usize,
        path: &str,
        flags: usize,
        _ctx: CallerCtx,
        token: &mut CleanLockToken,
    ) -> Result<()> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let mut address = inner.copy_and_capture_tail(path.as_bytes(), token)?;
        inner.call(
            Opcode::UnlinkAt,
            [file, address.base(), address.len(), flags],
            address.span(),
            token,
        )?;
        Ok(())
    }

    fn fsize(&self, file: usize, token: &mut CleanLockToken) -> Result<u64> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        inner
            .call(Opcode::Fsize, [file], &mut PageSpan::empty(), token)
            .map(|o| o as u64)
    }

    fn fchmod(&self, file: usize, mode: u16, token: &mut CleanLockToken) -> Result<()> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        inner.call(
            Opcode::Fchmod,
            [file, mode as usize],
            &mut PageSpan::empty(),
            token,
        )?;
        Ok(())
    }

    fn fchown(&self, file: usize, uid: u32, gid: u32, token: &mut CleanLockToken) -> Result<()> {
        {
            let ctx = context::current();
            let cx = &ctx.read(token.token());
            if cx.euid != 0 && (uid != cx.euid || gid != cx.egid) {
                return Err(Error::new(EPERM));
            }
        }

        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        inner.call(
            Opcode::Fchown,
            [file, uid as usize, gid as usize],
            &mut PageSpan::empty(),
            token,
        )?;
        Ok(())
    }

    fn fcntl(
        &self,
        file: usize,
        cmd: usize,
        arg: usize,
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        inner.call(
            Opcode::Fcntl,
            [file, cmd, arg],
            &mut PageSpan::empty(),
            token,
        )
    }

    fn fevent(
        &self,
        file: usize,
        flags: EventFlags,
        token: &mut CleanLockToken,
    ) -> Result<EventFlags> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        inner
            .call(
                Opcode::Fevent,
                [file, flags.bits()],
                &mut PageSpan::empty(),
                token,
            )
            .map(EventFlags::from_bits_truncate)
    }

    fn flink(
        &self,
        file: usize,
        path: &str,
        _ctx: CallerCtx,
        token: &mut CleanLockToken,
    ) -> Result<()> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let mut address = inner.copy_and_capture_tail(path.as_bytes(), token)?;
        inner.call(
            Opcode::Flink,
            [file, address.base(), address.len()],
            address.span(),
            token,
        )?;
        Ok(())
    }

    fn frename(
        &self,
        file: usize,
        path: &str,
        _ctx: CallerCtx,
        token: &mut CleanLockToken,
    ) -> Result<()> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let mut address = inner.copy_and_capture_tail(path.as_bytes(), token)?;
        inner.call(
            Opcode::Frename,
            [file, address.base(), address.len()],
            address.span(),
            token,
        )?;
        Ok(())
    }

    fn fsync(&self, file: usize, token: &mut CleanLockToken) -> Result<()> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        inner.call(Opcode::Fsync, [file], &mut PageSpan::empty(), token)?;
        Ok(())
    }

    fn ftruncate(&self, file: usize, len: usize, token: &mut CleanLockToken) -> Result<()> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        inner.call(
            Opcode::Ftruncate,
            [file, len],
            &mut PageSpan::empty(),
            token,
        )?;
        Ok(())
    }

    fn close(&self, id: usize, token: &mut CleanLockToken) -> Result<()> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        if !inner.supports_on_close {
            let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
            inner.call(Opcode::Close, [id], &mut PageSpan::empty(), token)?;
            return Ok(());
        }

        inner.todo.send(
            Sqe {
                opcode: Opcode::CloseMsg as u8,
                sqe_flags: SqeFlags::empty(),
                _rsvd: 0,
                tag: 0,
                args: [id as u64, 0, 0, 0, 0, 0],
                caller: 0, // TODO?
            },
            token,
        );

        event::trigger(inner.root_id, inner.handle_id, EVENT_READ);

        Ok(())
    }
    fn kdup(
        &self,
        file: usize,
        buf: UserSliceRo,
        ctx: CallerCtx,
        token: &mut CleanLockToken,
    ) -> Result<OpenResult> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let mut address = inner.capture_user(buf, token)?;
        let result = inner.call_extended(
            ctx,
            None,
            Opcode::Dup,
            [file, address.base(), address.len()],
            address.span(),
            token,
        );

        address.release()?;

        match result? {
            Response::Regular(code, fl) => Ok({
                let fd = Error::demux(code)?;
                OpenResult::SchemeLocal(
                    fd,
                    InternalFlags::from_extra0(fl).ok_or(Error::new(EINVAL))?,
                )
            }),
            Response::Fd(desc) => Ok(OpenResult::External(desc)),
            Response::MultipleFds(_) => Err(Error::new(EIO)),
        }
    }
    fn kfpath(&self, file: usize, buf: UserSliceWo, token: &mut CleanLockToken) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let mut address = inner.capture_user(buf, token)?;
        let result = inner.call(
            Opcode::Fpath,
            [file, address.base(), address.len()],
            address.span(),
            token,
        );
        address.release()?;
        result
    }

    fn kreadoff(
        &self,
        file: usize,
        buf: UserSliceWo,
        offset: u64,
        call_flags: u32,
        _stored_flags: u32,
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;

        let mut address = inner.capture_user(buf, token)?;
        let result = inner.call(
            Opcode::Read,
            [
                file as u64,
                address.base() as u64,
                address.len() as u64,
                offset,
                u64::from(call_flags),
            ],
            address.span(),
            token,
        );
        address.release()?;

        result
    }

    fn kwriteoff(
        &self,
        file: usize,
        buf: UserSliceRo,
        offset: u64,
        call_flags: u32,
        _stored_flags: u32,
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;

        let mut address = inner.capture_user(buf, token)?;
        let result = inner.call(
            Opcode::Write,
            [
                file as u64,
                address.base() as u64,
                address.len() as u64,
                offset,
                u64::from(call_flags),
            ],
            address.span(),
            token,
        );
        address.release()?;

        result
    }
    fn kfutimens(
        &self,
        file: usize,
        buf: UserSliceRo,
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let mut address = inner.capture_user(buf, token)?;
        let result = inner.call(
            Opcode::Futimens,
            [file, address.base(), address.len()],
            address.span(),
            token,
        );
        address.release()?;
        result
    }
    fn getdents(
        &self,
        file: usize,
        buf: UserSliceWo,
        header_size: u16,
        opaque_id_start: u64,
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let mut address = inner.capture_user(buf, token)?;
        // TODO: Support passing the 16-byte record_len of the last dent, to make it possible to
        // iterate backwards without first interating forward? The last entry will contain the
        // opaque id to pass to the next getdents. Since this field is small, this would fit in the
        // extra_raw field of `Cqe`s.
        let result = inner.call(
            Opcode::Getdents,
            [
                file,
                address.base(),
                address.len(),
                header_size.into(),
                opaque_id_start as usize,
            ],
            address.span(),
            token,
        );
        address.release()?;
        result
    }
    fn kfstat(&self, file: usize, stat: UserSliceWo, token: &mut CleanLockToken) -> Result<()> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let mut address = inner.capture_user(stat, token)?;
        let result = inner.call(
            Opcode::Fstat,
            [file, address.base(), address.len()],
            address.span(),
            token,
        );
        address.release()?;
        result.map(|_| ())
    }
    fn kfstatvfs(&self, file: usize, stat: UserSliceWo, token: &mut CleanLockToken) -> Result<()> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let mut address = inner.capture_user(stat, token)?;
        let result = inner.call(
            Opcode::Fstatvfs,
            [file, address.base(), address.len()],
            address.span(),
            token,
        );
        address.release()?;
        result.map(|_| ())
    }
    fn kfmap(
        &self,
        file: usize,
        addr_space: &Arc<AddrSpaceWrapper>,
        map: &Map,
        _consume: bool,
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;

        inner.fmap_inner(Arc::clone(addr_space), file, map, token)
    }
    fn kfunmap(
        &self,
        number: usize,
        offset: usize,
        size: usize,
        flags: MunmapFlags,
        token: &mut CleanLockToken,
    ) -> Result<()> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;

        let ctx = { context::current().read(token.token()).caller_ctx() };
        let res = inner.call_extended(
            ctx,
            None,
            Opcode::Munmap,
            [number, size, flags.bits(), offset],
            &mut PageSpan::empty(),
            token,
        )?;

        match res {
            Response::Regular(_, _) => Ok(()),
            Response::Fd(_) => Err(Error::new(EIO)),
            Response::MultipleFds(_) => Err(Error::new(EIO)),
        }
    }
    fn kcall(
        &self,
        id: usize,
        payload: UserSliceRw,
        _flags: CallFlags,
        metadata: &[u64],
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;

        let mut address = inner.capture_user(payload, token)?;
        let ctx = { context::current().read(token.token()).caller_ctx() };

        let mut sqe = Sqe {
            opcode: Opcode::Call as u8,
            sqe_flags: SqeFlags::empty(),
            _rsvd: 0,
            tag: inner.next_id()?,
            caller: ctx.pid as u64,
            args: [
                id as u64,
                address.base() as u64,
                address.len() as u64,
                0,
                0,
                0,
            ],
        };
        {
            let dst = &mut sqe.args[3..];
            let len = dst.len().min(metadata.len());
            dst[..len].copy_from_slice(&metadata[..len]);
        }
        let res = inner.call_extended_inner(None, sqe, address.span(), token)?;

        match res {
            Response::Regular(res, _) => Error::demux(res),
            Response::Fd(_) => Err(Error::new(EIO)),
            Response::MultipleFds(_) => Err(Error::new(EIO)),
        }
    }
    fn kfdwrite(
        &self,
        number: usize,
        descs: Vec<Arc<RwLock<FileDescription>>>,
        flags: CallFlags,
        arg: u64,
        _metadata: &[u64],
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;

        let mut sendfd_flags = SendFdFlags::empty();
        if flags.contains(CallFlags::FD_EXCLUSIVE) {
            sendfd_flags |= SendFdFlags::EXCLUSIVE;
        }

        let ctx = { context::current().read(token.token()).caller_ctx() };
        let len = descs.len();
        let res = inner.call_extended(
            ctx,
            Some(descs),
            Opcode::Sendfd,
            [number, sendfd_flags.bits(), arg as usize, len],
            &mut PageSpan::empty(),
            token,
        )?;

        match res {
            Response::Regular(res, _) => Error::demux(res),
            Response::Fd(_) => Err(Error::new(EIO)),
            Response::MultipleFds(_) => Err(Error::new(EIO)),
        }
    }
    fn kfdread(
        &self,
        id: usize,
        payload: UserSliceRw,
        flags: CallFlags,
        _metadata: &[u64],
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        if payload.len() % mem::size_of::<usize>() != 0 {
            return Err(Error::new(EINVAL));
        }

        let mut recvfd_flags = RecvFdFlags::empty();
        if flags.contains(CallFlags::FD_UPPER) {
            recvfd_flags |= RecvFdFlags::UPPER_TBL;
        }

        let ctx = { context::current().read(token.token()).caller_ctx() };
        let len = payload.len() / mem::size_of::<usize>();
        let res = inner.call_extended(
            ctx,
            None,
            Opcode::Recvfd,
            [id, recvfd_flags.bits(), len],
            &mut PageSpan::empty(),
            token,
        )?;

        let descriptions_opt = match res {
            Response::Regular(res, _) => {
                return match Error::demux(res) {
                    Ok(_) => Err(Error::new(EIO)),
                    Err(e) => Err(e),
                }
            }
            Response::Fd(_) => return Err(Error::new(EIO)),
            Response::MultipleFds(fds) => fds,
        };

        let num_fds = if let Some(descriptions) = descriptions_opt {
            if recvfd_flags.contains(RecvFdFlags::UPPER_TBL) {
                UserInner::bulk_insert_fds(descriptions, payload, token)?
            } else {
                UserInner::bulk_add_fds(descriptions, payload, token)?
            }
        } else {
            0
        };

        Ok(num_fds)
    }
}

pub trait Args: Copy {
    fn args(self) -> [u64; 6];
}
impl<const N: usize> Args for [u64; N] {
    fn args(self) -> [u64; 6] {
        assert!(self.len() <= N);
        core::array::from_fn(|i| self.get(i).copied().unwrap_or(0))
    }
}
impl<const N: usize> Args for [usize; N] {
    fn args(self) -> [u64; 6] {
        self.map(|s| s as u64).args()
    }
}

// TODO: Find a better way to do authentication. No scheme call currently uses arg 5 but this will
// likely change. Ideally this mechanism would also allow the scheme to query the supplementary
// group list.
fn uid_gid_hack_merge([uid, gid]: [u32; 2]) -> u64 {
    u64::from(uid) | (u64::from(gid) << 32)
}
fn current_uid_gid(token: &mut CleanLockToken) -> [u32; 2] {
    let ctx = context::current();
    let p = &ctx.read(token.token());
    [p.euid, p.egid]
}
