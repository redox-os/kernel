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
use slab::Slab;
use spin::{Mutex, RwLock};
use spinning_top::RwSpinlock;
use syscall::{
    schemev2::{Cqe, CqeOpcode, Opcode, Sqe, SqeFlags},
    FobtainFdFlags, MunmapFlags, SendFdFlags, F_SETFL, KSMSG_CANCEL, MAP_FIXED_NOREPLACE,
    SKMSG_FOBTAINFD, SKMSG_FRETURNFD, SKMSG_PROVIDE_MMAP,
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
        process, BorrowedHtBuf, Context, Status,
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
    pub scheme_id: SchemeId,
    v2: bool,
    context: Weak<RwSpinlock<Context>>,
    todo: WaitQueue<Sqe>,

    // TODO: custom packed radix tree data structure
    states: Mutex<Slab<State>>,

    unmounting: AtomicBool,
}

enum State {
    Waiting {
        context: Weak<RwSpinlock<Context>>,
        fd: Option<Arc<RwLock<FileDescription>>>,
        callee_responsible: PageSpan,
        canceling: bool,
    },
    Responded(Response),
    Fmap(Weak<RwSpinlock<Context>>),
    Placeholder,
}

#[derive(Debug)]
pub enum Response {
    Regular(usize, u8),
    Fd(Arc<RwLock<FileDescription>>),
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
    NoOp, // TODO: remove
}
impl ParsedCqe {
    fn parse_packet(packet: &Packet) -> Result<Self> {
        Ok(if packet.id == 0 {
            match packet.a {
                SYS_FEVENT => Self::TriggerFevent {
                    number: packet.b,
                    flags: EventFlags::from_bits_truncate(packet.c),
                },
                _ => {
                    log::warn!(
                        "Unknown scheme -> kernel message {} from {}",
                        packet.a,
                        context::current().read().name
                    );

                    // Some schemes don't implement cancellation properly yet, so we temporarily
                    // ignore their responses to the cancellation message, rather than EINVAL.
                    if packet.a == Error::mux(Err(Error::new(ENOSYS))) {
                        return Ok(Self::NoOp);
                    }

                    return Err(Error::new(EINVAL));
                }
            }
        } else if Error::demux(packet.a) == Err(Error::new(ESKMSG)) {
            // The reason why the new ESKMSG mechanism was introduced, is that passing packet IDs
            // in packet.id is much cleaner than having to convert it into 1 or 2 usizes etc.
            match packet.b {
                SKMSG_FRETURNFD => Self::ResponseWithFd {
                    tag: (packet.id - 1) as u32,
                    fd: packet.d,
                },
                SKMSG_FOBTAINFD => Self::ObtainFd {
                    tag: (packet.id - 1) as u32,
                    flags: FobtainFdFlags::from_bits(packet.d).ok_or(Error::new(EINVAL))?,
                    dst_fd_or_ptr: packet.c,
                },
                SKMSG_PROVIDE_MMAP => Self::ProvideMmap {
                    tag: (packet.id - 1) as u32,
                    offset: u64::from(packet.uid) | (u64::from(packet.gid) << 32),
                    base_addr: VirtualAddress::new(packet.c),
                    page_count: packet.d,
                },
                _ => return Err(Error::new(EINVAL)),
            }
        } else {
            ParsedCqe::RegularResponse {
                tag: (packet.id - 1) as u32,
                code: packet.a,
                extra0: 0,
            }
        })
    }
    fn parse_cqe(cqe: &Cqe) -> Result<Self> {
        Ok(
            match CqeOpcode::try_from_raw(cqe.flags & 0b11).ok_or(Error::new(EINVAL))? {
                CqeOpcode::RespondRegular => Self::RegularResponse {
                    tag: cqe.tag,
                    code: cqe.result as usize,
                    extra0: cqe.extra_raw[0],
                },
                CqeOpcode::RespondWithFd => Self::ResponseWithFd {
                    tag: cqe.tag,
                    fd: cqe.result as usize,
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
        v2: bool,
        handle_id: usize,
        name: Box<str>,
        _flags: usize,
        context: Weak<RwSpinlock<Context>>,
    ) -> UserInner {
        UserInner {
            root_id,
            handle_id,
            name,
            v2,
            scheme_id,
            context,
            todo: WaitQueue::new(),
            unmounting: AtomicBool::new(false),
            states: Mutex::new(Slab::with_capacity(32)),
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

    fn next_id(&self) -> Result<u32> {
        let mut states = self.states.lock();
        let idx = states.insert(State::Placeholder);

        // TODO: implement blocking?
        u32::try_from(idx).map_err(|_| Error::new(EAGAIN))
    }

    pub fn call(
        &self,
        opcode: Opcode,
        args: impl Args,
        caller_responsible: &mut PageSpan,
    ) -> Result<usize> {
        let ctx = process::current()?.read().caller_ctx();
        match self.call_extended(ctx, None, opcode, args, caller_responsible)? {
            Response::Regular(code, _) => Error::demux(code),
            Response::Fd(_) => Err(Error::new(EIO)),
        }
    }

    pub fn call_extended(
        &self,
        ctx: CallerCtx,
        fd: Option<Arc<RwLock<FileDescription>>>,
        opcode: Opcode,
        args: impl Args,
        caller_responsible: &mut PageSpan,
    ) -> Result<Response> {
        self.call_extended_inner(
            fd,
            Sqe {
                opcode: opcode as u8,
                sqe_flags: SqeFlags::empty(),
                _rsvd: 0,
                tag: self.next_id()?,
                caller: ctx.pid as u64,
                args: {
                    let mut a = args.args();
                    a[5] = uid_gid_hack_merge([ctx.uid, ctx.gid]);
                    a
                },
            },
            caller_responsible,
        )
    }

    fn call_extended_inner(
        &self,
        fd: Option<Arc<RwLock<FileDescription>>>,
        sqe: Sqe,
        caller_responsible: &mut PageSpan,
    ) -> Result<Response> {
        if self.unmounting.load(Ordering::SeqCst) {
            return Err(Error::new(ENODEV));
        }

        let current_context = context::current();

        {
            let mut states = self.states.lock();
            current_context.write().block("UserScheme::call");
            states[sqe.tag as usize] = State::Waiting {
                context: Arc::downgrade(&current_context),
                fd,
                canceling: false,

                // This is the part that the scheme handler will deallocate when responding. It
                // starts as empty, so the caller can unmap it (optimal for TLB), but is populated
                // the caller is interrupted by SIGKILL.
                callee_responsible: PageSpan::empty(),
            };
        }

        self.todo.send(sqe);
        event::trigger(self.root_id, self.handle_id, EVENT_READ);

        loop {
            context::switch();

            let mut states = self.states.lock();

            let mut eintr_if_sigkill = |callee_responsible: &mut PageSpan| {
                // If SIGKILL was found without waiting for scheme, EINTR directly. In that
                // case, data loss doesn't matter.
                if context::current().read().being_sigkilled {
                    // Callee must deallocate memory, rather than the caller. This is less optimal
                    // for TLB, but we don't really have any other choice. The scheme must be able
                    // to access the borrowed memory until it has responded to the request.
                    *callee_responsible = core::mem::replace(caller_responsible, PageSpan::empty());

                    Err(Error::new(EINTR))
                } else {
                    Ok(())
                }
            };

            match states.get_mut(sqe.tag as usize) {
                // invalid state
                None => return Err(Error::new(EBADFD)),
                Some(o) => match mem::replace(o, State::Placeholder) {
                    // signal wakeup while awaiting cancelation
                    State::Waiting {
                        canceling: true,
                        mut callee_responsible,
                        context,
                        fd,
                    } => {
                        let maybe_eintr = eintr_if_sigkill(&mut callee_responsible);
                        *o = State::Waiting {
                            canceling: true,
                            callee_responsible,
                            context,
                            fd,
                        };
                        drop(states);
                        maybe_eintr?;

                        context::current().write().block("UserInner::call");
                    }
                    // spurious wakeup
                    State::Waiting {
                        canceling: false,
                        fd,
                        context,
                        mut callee_responsible,
                    } => {
                        let maybe_eintr = eintr_if_sigkill(&mut callee_responsible);
                        *o = State::Waiting {
                            canceling: true,
                            fd,
                            context,
                            callee_responsible,
                        };

                        drop(states);
                        maybe_eintr?;

                        // TODO: Is this too dangerous when the states lock is held?
                        self.todo.send(Sqe {
                            opcode: Opcode::Cancel as u8,
                            sqe_flags: SqeFlags::ONEWAY,
                            tag: sqe.tag,
                            ..Default::default()
                        });
                        event::trigger(self.root_id, self.handle_id, EVENT_READ);
                        context::current().write().block("UserInner::call");
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
                head: CopyInfo {
                    src: None,
                    dst: None,
                },
                tail: CopyInfo {
                    src: None,
                    dst: None,
                },
                span: {
                    let (first_page, page_count, _offset) =
                        page_range_containing(user_buf.addr(), user_buf.len());
                    PageSpan::new(first_page, page_count)
                },
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

    pub fn read(&self, buf: UserSliceWo, flags: u32) -> Result<usize> {
        // If O_NONBLOCK is used, do not block
        let nonblock = flags & O_NONBLOCK as u32 != 0;

        // If unmounting, do not block so that EOF can be returned immediately
        let block = !(nonblock || self.unmounting.load(Ordering::SeqCst));

        if self.v2 {
            return match self
                .todo
                .receive_into_user(buf, block, "UserInner::read (v2)")
            {
                // If we received requests, return them to the scheme handler
                Ok(byte_count) => Ok(byte_count),
                // If there were no requests and we were unmounting, return EOF
                Err(Error { errno: EAGAIN }) if self.unmounting.load(Ordering::SeqCst) => Ok(0),
                // If there were no requests and O_NONBLOCK was used (EAGAIN), or some other error
                // occurred, return that.
                Err(error) => Err(error),
            };
        } else {
            let mut bytes_read = 0;

            for dst in buf.in_exact_chunks(size_of::<Packet>()) {
                match self
                    .todo
                    .receive(block && bytes_read == 0, "UserInner::read (legacy)")
                {
                    Ok(sqe) => {
                        dst.copy_exactly(&self.translate_sqe_to_packet(&sqe)?)?;
                        bytes_read += size_of::<Packet>();
                    }
                    Err(_) if bytes_read > 0 => return Ok(bytes_read),
                    Err(Error { errno: EAGAIN }) if self.unmounting.load(Ordering::SeqCst) => {
                        return Ok(bytes_read)
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok(bytes_read)
        }
    }
    fn translate_sqe_to_packet(&self, sqe: &Sqe) -> Result<Packet> {
        let opc = Opcode::try_from_raw(sqe.opcode)
            .expect("passed scheme opcode not internally recognized by kernel");

        let uid = sqe.args[5] as u32;
        let gid = (sqe.args[5] >> 32) as u32;

        Ok(Packet {
            id: u64::from(sqe.tag) + 1,
            pid: sqe.caller as usize,
            a: match opc {
                Opcode::Open => SYS_OPEN,
                Opcode::Rmdir => SYS_RMDIR,
                Opcode::Unlink => SYS_UNLINK,
                Opcode::Close => SYS_CLOSE,
                Opcode::Dup => SYS_DUP,
                Opcode::Read => SYS_READ,
                Opcode::Write => SYS_WRITE,
                Opcode::Fsize => SYS_LSEEK, // lseek reuses the fsize "opcode", must be !v2
                Opcode::Fchmod => SYS_FCHMOD,
                Opcode::Fchown => SYS_FCHOWN,
                Opcode::Fcntl => SYS_FCNTL,
                Opcode::Fevent => SYS_FEVENT,
                Opcode::Sendfd => SYS_SENDFD,
                Opcode::Fpath => SYS_FPATH,
                Opcode::Frename => SYS_FRENAME,
                Opcode::Fstat => SYS_FSTAT,
                Opcode::Fstatvfs => SYS_FSTATVFS,
                Opcode::Fsync => SYS_FSYNC,
                Opcode::Ftruncate => SYS_FTRUNCATE,
                Opcode::Futimens => SYS_FUTIMENS,

                Opcode::MmapPrep => {
                    return Ok(Packet {
                        id: u64::from(sqe.tag) + 1,
                        pid: sqe.caller as usize,
                        a: KSMSG_MMAP_PREP,
                        b: sqe.args[0] as usize,
                        c: sqe.args[1] as usize,
                        d: sqe.args[2] as usize,
                        uid: sqe.args[3] as u32,
                        gid: (sqe.args[3] >> 32) as u32,
                    })
                }
                Opcode::RequestMmap => {
                    return Ok(Packet {
                        id: u64::from(sqe.tag) + 1,
                        pid: sqe.caller as usize,
                        a: KSMSG_MMAP,
                        b: sqe.args[0] as usize,
                        c: sqe.args[1] as usize,
                        d: sqe.args[2] as usize,
                        uid: sqe.args[3] as u32,
                        gid: (sqe.args[3] >> 32) as u32,
                    })
                }
                Opcode::Munmap => {
                    return Ok(Packet {
                        id: u64::from(sqe.tag) + 1,
                        pid: sqe.caller as usize,
                        a: KSMSG_MUNMAP,
                        b: sqe.args[0] as usize,         // fd
                        c: sqe.args[1] as usize,         // size
                        d: sqe.args[2] as usize,         // flags
                        uid: sqe.args[3] as u32,         // offset lo
                        gid: (sqe.args[3] >> 32) as u32, // offset hi
                    });
                }
                Opcode::Getdents => {
                    return Ok(Packet {
                        id: u64::from(sqe.tag) + 1,
                        pid: sqe.caller as usize,
                        a: SYS_GETDENTS,
                        b: sqe.args[0] as usize,
                        c: sqe.args[1] as usize,
                        d: sqe.args[2] as usize,
                        uid: sqe.args[3] as u32,
                        gid: (sqe.args[3] >> 32) as u32,
                    });
                }

                Opcode::Mremap => SYS_MREMAP,
                Opcode::Msync => KSMSG_MSYNC,

                Opcode::Cancel => {
                    return Ok(Packet {
                        id: 0,
                        a: KSMSG_CANCEL,
                        b: sqe.tag as usize,
                        c: 0,
                        d: 0,
                        pid: sqe.caller as usize,
                        uid,
                        gid,
                    })
                }

                _ => return Err(Error::new(EOPNOTSUPP)),
            },
            b: sqe.args[0] as usize,
            c: sqe.args[1] as usize,
            d: sqe.args[2] as usize,

            uid,
            gid,
        })
    }

    pub fn write(&self, buf: UserSliceRo) -> Result<usize> {
        let mut bytes_read = 0;
        if self.v2 {
            for chunk in buf.in_exact_chunks(size_of::<Cqe>()) {
                match ParsedCqe::parse_cqe(&unsafe { chunk.read_exact::<Cqe>()? })
                    .and_then(|p| self.handle_parsed(&p))
                {
                    Ok(()) => bytes_read += size_of::<Cqe>(),
                    Err(_) if bytes_read > 0 => break,
                    Err(error) => return Err(error),
                }
            }
        } else {
            for chunk in buf.in_exact_chunks(size_of::<Packet>()) {
                match ParsedCqe::parse_packet(&unsafe { chunk.read_exact::<Packet>()? })
                    .and_then(|p| self.handle_parsed(&p))
                {
                    Ok(()) => bytes_read += size_of::<Packet>(),
                    Err(_) if bytes_read > 0 => break,
                    Err(error) => return Err(error),
                }
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
    ) -> Result<()> {
        log::info!("REQUEST FMAP");

        let tag = self.next_id()?;
        let mut states = self.states.lock();
        states[tag as usize] = State::Fmap(Arc::downgrade(&context::current()));

        /*self.todo.send(Packet {
            id: packet_id,
            pid: context::context_id().into(),
            a: KSMSG_MMAP,
            b: id,
            c: flags.bits(),
            d: required_page_count,
            uid: offset as u32,
            gid: (offset >> 32) as u32,
        });*/
        self.todo.send(Sqe {
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
                uid_gid_hack_merge(current_uid_gid()?),
            ],
            caller: context::current().read().pid.get() as u64,
        });
        event::trigger(self.root_id, self.handle_id, EVENT_READ);

        Ok(())
    }
    fn handle_parsed(&self, cqe: &ParsedCqe) -> Result<()> {
        match *cqe {
            ParsedCqe::RegularResponse { tag, code, extra0 } => {
                self.respond(tag, Response::Regular(code, extra0))?
            }
            ParsedCqe::ResponseWithFd { tag, fd } => self.respond(
                tag,
                Response::Fd(
                    context::current()
                        .read()
                        .remove_file(FileHandle::from(fd))
                        .ok_or(Error::new(EINVAL))?
                        .description,
                ),
            )?,
            ParsedCqe::ObtainFd {
                tag,
                flags,
                dst_fd_or_ptr,
            } => {
                let description = match self
                    .states
                    .lock()
                    .get_mut(tag as usize)
                    .ok_or(Error::new(EINVAL))?
                {
                    State::Waiting { ref mut fd, .. } => fd.take().ok_or(Error::new(ENOENT))?,
                    _ => return Err(Error::new(ENOENT)),
                };

                // FIXME: Description can leak if there is no additional file table space.
                if flags.contains(FobtainFdFlags::MANUAL_FD) {
                    context::current().read().insert_file(
                        FileHandle::from(dst_fd_or_ptr),
                        FileDescriptor {
                            description,
                            cloexec: true,
                        },
                    );
                } else {
                    let fd = context::current()
                        .read()
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
                log::info!(
                    "PROVIDE_MAP {:x} {:x} {:?} {:x}",
                    tag,
                    offset,
                    base_addr,
                    page_count
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

                let mut context = context.write();
                match context.status {
                    Status::HardBlocked {
                        reason: HardBlockedReason::AwaitingMmap { .. },
                    } => context.status = Status::Runnable,
                    _ => (),
                }
                context.fmap_ret = Some(Frame::containing(frame));
            }
            ParsedCqe::TriggerFevent { number, flags } => {
                event::trigger(self.scheme_id, number, flags)
            }
            ParsedCqe::NoOp => (),
        }
        Ok(())
    }
    fn respond(&self, tag: u32, mut response: Response) -> Result<()> {
        let to_close;

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
                    fd,
                    canceling,
                    callee_responsible,
                } => {
                    if let Response::Regular(ref mut code, _) = response
                        && !canceling
                        && *code == Error::mux(Err(Error::new(EINTR)))
                    {
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
                        *o = State::Responded(response);
                    } else {
                        states.remove(tag as usize);
                    }

                    let unpin = true;
                    AddrSpace::current()?.munmap(callee_responsible, unpin)?;
                }
            },
            // invalid state
            None => return Err(Error::new(EBADFD)),
        }

        if let Some(to_close) = to_close {
            let _ = to_close.try_close();
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
            let context_lock = context::current();
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
            (context.pid, desc.description)
        };

        let response = self.call_extended_inner(
            None,
            /*
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
            */
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
                    uid_gid_hack_merge(current_uid_gid()?),
                ],
                caller: pid.get() as u64,
            },
            &mut PageSpan::empty(),
        )?;

        // TODO: I've previously tested that this works, but because the scheme trait all of
        // Redox's schemes currently rely on doesn't allow one-way messages, there's no current
        // code using it.

        //let mapping_is_lazy = map.flags.contains(MapFlags::MAP_LAZY);
        let mapping_is_lazy = false;

        let base_page_opt = match response {
            Response::Regular(code, _) => (!mapping_is_lazy).then_some(Error::demux(code)?),
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
        if let Some(ref addrsp) = self.addrsp {
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
    fn kopen(&self, path: &str, flags: usize, ctx: CallerCtx) -> Result<OpenResult> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let mut address = inner.copy_and_capture_tail(path.as_bytes())?;
        match inner.call_extended(
            ctx,
            None,
            Opcode::Open,
            [address.base(), address.len(), flags],
            address.span(),
        )? {
            Response::Regular(code, fl) => Ok({
                let _ = Error::demux(code)?;
                OpenResult::SchemeLocal(
                    code,
                    InternalFlags::from_extra0(fl).ok_or(Error::new(EINVAL))?,
                )
            }),
            Response::Fd(desc) => Ok(OpenResult::External(desc)),
        }
    }
    fn rmdir(&self, path: &str, _ctx: CallerCtx) -> Result<()> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let mut address = inner.copy_and_capture_tail(path.as_bytes())?;
        inner.call(
            Opcode::Rmdir,
            [address.base(), address.len()],
            address.span(),
        )?;
        Ok(())
    }

    fn unlink(&self, path: &str, _ctx: CallerCtx) -> Result<()> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let mut address = inner.copy_and_capture_tail(path.as_bytes())?;
        inner.call(
            Opcode::Unlink,
            [address.base(), address.len()],
            address.span(),
        )?;
        Ok(())
    }

    fn fsize(&self, file: usize) -> Result<u64> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        if !inner.v2 {
            return Err(Error::new(ESPIPE));
        }
        inner
            .call(Opcode::Fsize, [file], &mut PageSpan::empty())
            .map(|o| o as u64)
    }

    fn fchmod(&self, file: usize, mode: u16) -> Result<()> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        inner.call(
            Opcode::Fchmod,
            [file, mode as usize],
            &mut PageSpan::empty(),
        )?;
        Ok(())
    }

    fn fchown(&self, file: usize, uid: u32, gid: u32) -> Result<()> {
        {
            let process_lock = process::current()?;
            let process = process_lock.read();
            if process.euid != 0 {
                if uid != process.euid || gid != process.egid {
                    return Err(Error::new(EPERM));
                }
            }
        }

        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        inner.call(
            Opcode::Fchown,
            [file, uid as usize, gid as usize],
            &mut PageSpan::empty(),
        )?;
        Ok(())
    }

    fn fcntl(&self, file: usize, cmd: usize, arg: usize) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        inner.call(Opcode::Fcntl, [file, cmd, arg], &mut PageSpan::empty())
    }

    fn fevent(&self, file: usize, flags: EventFlags) -> Result<EventFlags> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        inner
            .call(Opcode::Fevent, [file, flags.bits()], &mut PageSpan::empty())
            .map(EventFlags::from_bits_truncate)
    }

    fn frename(&self, file: usize, path: &str, _ctx: CallerCtx) -> Result<()> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let mut address = inner.copy_and_capture_tail(path.as_bytes())?;
        inner.call(
            Opcode::Frename,
            [file, address.base(), address.len()],
            address.span(),
        )?;
        Ok(())
    }

    fn fsync(&self, file: usize) -> Result<()> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        inner.call(Opcode::Fsync, [file], &mut PageSpan::empty())?;
        Ok(())
    }

    fn ftruncate(&self, file: usize, len: usize) -> Result<()> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        inner.call(Opcode::Ftruncate, [file, len], &mut PageSpan::empty())?;
        Ok(())
    }

    fn close(&self, file: usize) -> Result<()> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        inner.call(Opcode::Close, [file], &mut PageSpan::empty())?;
        Ok(())
    }
    fn kdup(&self, file: usize, buf: UserSliceRo, ctx: CallerCtx) -> Result<OpenResult> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let mut address = inner.capture_user(buf)?;
        let result = inner.call_extended(
            ctx,
            None,
            Opcode::Dup,
            [file, address.base(), address.len()],
            address.span(),
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
        }
    }
    fn kfpath(&self, file: usize, buf: UserSliceWo) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let mut address = inner.capture_user(buf)?;
        let result = inner.call(
            Opcode::Fpath,
            [file, address.base(), address.len()],
            address.span(),
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
        stored_flags: u32,
    ) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;

        if call_flags != stored_flags && !inner.v2 {
            self.fcntl(file, F_SETFL, call_flags as usize)?;
        }

        let mut address = inner.capture_user(buf)?;
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
        );
        address.release()?;

        if call_flags != stored_flags && !inner.v2 {
            self.fcntl(file, F_SETFL, stored_flags as usize)?;
        }

        result
    }

    fn kwriteoff(
        &self,
        file: usize,
        buf: UserSliceRo,
        offset: u64,
        call_flags: u32,
        stored_flags: u32,
    ) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        if call_flags != stored_flags && !inner.v2 {
            self.fcntl(file, F_SETFL, call_flags as usize)?;
        }

        let mut address = inner.capture_user(buf)?;
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
        );
        address.release()?;

        if call_flags != stored_flags && !inner.v2 {
            self.fcntl(file, F_SETFL, stored_flags as usize)?;
        }

        result
    }
    fn legacy_seek(&self, id: usize, pos: isize, whence: usize) -> Option<Result<usize>> {
        let inner = self.inner.upgrade()?;
        if inner.v2 {
            return None;
        }
        Some(inner.call(
            Opcode::Fsize,
            [id, pos as usize, whence],
            &mut PageSpan::empty(),
        ))
    }
    fn kfutimens(&self, file: usize, buf: UserSliceRo) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let mut address = inner.capture_user(buf)?;
        let result = inner.call(
            Opcode::Futimens,
            [file, address.base(), address.len()],
            address.span(),
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
    ) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let mut address = inner.capture_user(buf)?;
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
        );
        address.release()?;
        result
    }
    fn kfstat(&self, file: usize, stat: UserSliceWo) -> Result<()> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let mut address = inner.capture_user(stat)?;
        let result = inner.call(
            Opcode::Fstat,
            [file, address.base(), address.len()],
            address.span(),
        );
        address.release()?;
        result.map(|_| ())
    }
    fn kfstatvfs(&self, file: usize, stat: UserSliceWo) -> Result<()> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let mut address = inner.capture_user(stat)?;
        let result = inner.call(
            Opcode::Fstatvfs,
            [file, address.base(), address.len()],
            address.span(),
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
    ) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;

        inner.fmap_inner(Arc::clone(addr_space), file, map)
    }
    fn kfunmap(&self, number: usize, offset: usize, size: usize, flags: MunmapFlags) -> Result<()> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;

        let ctx = process::current()?.read().caller_ctx();
        let res = inner.call_extended(
            ctx,
            None,
            Opcode::Munmap,
            [number, size, flags.bits(), offset],
            &mut PageSpan::empty(),
        )?;

        match res {
            Response::Regular(_, _) => Ok(()),
            Response::Fd(_) => Err(Error::new(EIO)),
        }
    }
    fn ksendfd(
        &self,
        number: usize,
        desc: Arc<RwLock<FileDescription>>,
        flags: SendFdFlags,
        _arg: u64,
    ) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;

        let ctx = process::current()?.read().caller_ctx();
        let res = inner.call_extended(
            ctx,
            Some(desc),
            Opcode::Sendfd,
            [number, flags.bits()],
            &mut PageSpan::empty(),
        )?;

        match res {
            Response::Regular(res, _) => Ok(res),
            Response::Fd(_) => Err(Error::new(EIO)),
        }
    }
}

#[derive(PartialEq)]
pub enum Mode {
    Ro,
    Wo,
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
fn current_uid_gid() -> Result<[u32; 2]> {
    Ok(match process::current()?.read() {
        ref p => [p.euid, p.egid],
    })
}
