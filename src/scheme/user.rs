use alloc::sync::{Arc, Weak};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use syscall::{SKMSG_FRETURNFD, CallerCtx};
use core::sync::atomic::{AtomicBool, Ordering};
use core::{mem, slice, usize};
use core::convert::TryFrom;
use spin::{Mutex, RwLock};

use crate::context::{self, Context};
use crate::context::file::{FileDescriptor, FileDescription};
use crate::context::memory::{AddrSpace, DANGLING, Grant, Region, GrantFileRef};
use crate::event;
use crate::paging::{PAGE_SIZE, mapper::InactiveFlusher, Page, round_down_pages, round_up_pages, VirtualAddress};
use crate::scheme::{AtomicSchemeId, SchemeId};
use crate::sync::{WaitQueue, WaitMap};
use crate::syscall::data::{Map, Packet, Stat, StatVfs, TimeSpec};
use crate::syscall::error::*;
use crate::syscall::flag::{EventFlags, EVENT_READ, O_NONBLOCK, MapFlags, PROT_READ, PROT_WRITE};
use crate::syscall::number::*;
use crate::syscall::scheme::Scheme;

use super::{FileHandle, OpenResult, KernelScheme};

pub struct UserInner {
    root_id: SchemeId,
    handle_id: usize,
    pub name: Box<str>,
    pub flags: usize,
    pub scheme_id: AtomicSchemeId,
    next_id: Mutex<u64>,
    context: Weak<RwLock<Context>>,
    todo: WaitQueue<Packet>,
    fmap: Mutex<BTreeMap<u64, (Weak<RwLock<Context>>, FileDescriptor, Map)>>,
    done: WaitMap<u64, Response>,
    unmounting: AtomicBool,
}
pub enum Response {
    Regular(usize),
    Fd(Arc<RwLock<FileDescription>>),
}

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
            fmap: Mutex::new(BTreeMap::new()),
            done: WaitMap::new(),
            unmounting: AtomicBool::new(false),
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

    fn current_caller_ctx() -> Result<CallerCtx> {
        match context::current()?.read() {
            ref context => Ok(CallerCtx { pid: context.id.into(), uid: context.euid, gid: context.egid }),
        }
    }

    pub fn call(&self, a: usize, b: usize, c: usize, d: usize) -> Result<usize> {
        match self.call_extended(Self::current_caller_ctx()?, [a, b, c, d])? {
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
    pub fn capture(&self, buf: &[u8]) -> Result<usize> {
        UserInner::capture_inner(
            &self.context,
            0,
            buf.as_ptr() as usize,
            buf.len(),
            PROT_READ,
            None
        ).map(|addr| addr.data())
    }

    /// Map a writeable structure to the scheme's userspace and return the
    /// pointer
    pub fn capture_mut(&self, buf: &mut [u8]) -> Result<usize> {
        UserInner::capture_inner(
            &self.context,
            0,
            buf.as_mut_ptr() as usize,
            buf.len(),
            PROT_WRITE,
            None
        ).map(|addr| addr.data())
    }

    // TODO: Use an address space Arc over a context Arc. While contexts which share address spaces
    // still can access borrowed scheme pages, it would both be cleaner and would handle the case
    // where the initial context is closed.
    fn capture_inner(context_weak: &Weak<RwLock<Context>>, dst_address: usize, address: usize, size: usize, flags: MapFlags, desc_opt: Option<GrantFileRef>)
                     -> Result<VirtualAddress> {
        if size == 0 {
            // NOTE: Rather than returning NULL, we return a dummy dangling address, that is also
            // non-canonical on x86. This means that scheme handlers do not need to check the
            // length before creating a Rust slice (which cannot have NULL as address regardless of
            // the length; this actually made nulld think that an empty path was invalid UTF-8
            // because of enum layout optimization), independent of whatever alignment this slice
            // will have.  Additionally, they would generate a general protection fault immediately
            // if they ever tried to access this dangling address.

            // Set the most significant bit.
            return Ok(VirtualAddress::new(DANGLING));
        }

        let src_page = Page::containing_address(VirtualAddress::new(round_down_pages(address)));
        let offset = address - src_page.start_address().data();
        let page_count = round_up_pages(offset + size) / PAGE_SIZE;
        let requested_dst_page = (dst_address != 0).then_some(Page::containing_address(VirtualAddress::new(round_down_pages(dst_address))));

        let dst_space_lock = Arc::clone(context_weak.upgrade().ok_or(Error::new(ESRCH))?.read().addr_space()?);
        let cur_space_lock = AddrSpace::current()?;

        //TODO: Use syscall_head and syscall_tail to avoid leaking data
        let dst_page = if Arc::ptr_eq(
            &dst_space_lock,
            &cur_space_lock,
        ) {
            let mut dst_space = dst_space_lock.write();
            dst_space.mmap(requested_dst_page, page_count, flags, |dst_page, page_flags, mapper, flusher| {
                //TODO: remove hack to use same mapper for borrow
                let src_mapper = unsafe { &mut *(mapper as *mut _) };
                let dst_mapper = unsafe { &mut *(mapper as *mut _) };
                Ok(Grant::borrow(src_page, dst_page, page_count, page_flags, desc_opt, src_mapper, dst_mapper, flusher)?)
            })?
        } else {
            let mut dst_space = dst_space_lock.write();
            dst_space.mmap(requested_dst_page, page_count, flags, move |dst_page, page_flags, mapper, flusher| {
                let mut cur_space = cur_space_lock.write();
                Ok(Grant::borrow(src_page, dst_page, page_count, page_flags, desc_opt, &mut cur_space.table.utable, mapper, flusher)?)
            })?
        };

        Ok(dst_page.start_address().add(offset))
    }

    pub fn release(&self, address: usize) -> Result<()> {
        if address == DANGLING {
            return Ok(());
        }
        let context_lock = self.context.upgrade().ok_or(Error::new(ESRCH))?;
        let context = context_lock.write();

        let mut addr_space = context.addr_space()?.write();

        let region = match addr_space.grants.contains(VirtualAddress::new(address)).map(Region::from) {
            Some(region) => region,
            None => return Err(Error::new(EFAULT)),
        };
        addr_space.grants.take(&region).unwrap().unmap(&mut addr_space.table.utable, InactiveFlusher::new());
        Ok(())
    }

    pub fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let packet_buf = unsafe { slice::from_raw_parts_mut(
            buf.as_mut_ptr() as *mut Packet,
            buf.len()/mem::size_of::<Packet>())
        };

        // If O_NONBLOCK is used, do not block
        let nonblock = self.flags & O_NONBLOCK == O_NONBLOCK;
        // If unmounting, do not block so that EOF can be returned immediately
        let block = !(nonblock || self.unmounting.load(Ordering::SeqCst));
        if let Some(count) = self.todo.receive_into(packet_buf, block, "UserInner::read") {
            if count > 0 {
                // If we received requests, return them to the scheme handler
                Ok(count * mem::size_of::<Packet>())
            } else if self.unmounting.load(Ordering::SeqCst) {
                // If there were no requests and we were unmounting, return EOF
                Ok(0)
            } else {
                // If there were no requests and O_NONBLOCK was used, return EAGAIN
                Err(Error::new(EAGAIN))
            }
        } else if self.unmounting.load(Ordering::SeqCst) {
            // If we are unmounting and there are no pending requests, return EOF
            //   Unmounting is read again because the previous value
            //   may have changed since we first blocked for packets
            Ok(0)
        } else {
            // A signal was received, return EINTR
            Err(Error::new(EINTR))
        }
    }

    pub fn write(&self, buf: &[u8]) -> Result<usize> {
        // TODO: Alignment

        let packets = unsafe { core::slice::from_raw_parts(buf.as_ptr().cast::<Packet>(), buf.len() / mem::size_of::<Packet>()) };
        let mut packets_read = 0;

        for packet in packets {
            match self.handle_packet(packet) {
                Ok(()) => packets_read += 1,
                Err(_) if packets_read > 0 => break,
                Err(error) => return Err(error),
            }
        }

        Ok(packets_read * mem::size_of::<Packet>())
    }
    fn handle_packet(&self, packet: &Packet) -> Result<()> {
        if packet.id == 0 {
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

                    let desc = context::current()?.read().get_file(FileHandle::from(fd)).ok_or(Error::new(EINVAL))?.description;

                    self.done.send(packet.id, Response::Fd(desc));
                }
                _ => return Err(Error::new(EINVAL)),
            }
        } else {
            let mut retcode = packet.a;

            // The motivation of doing this here instead of within the fmap handler, is that we
            // can operate on an inactive table. This reduces the number of page table reloads
            // from two (context switch + active TLB flush) to one (context switch).
            if let Some((context_weak, desc, map)) = self.fmap.lock().remove(&packet.id) {
                if let Ok(address) = Error::demux(packet.a) {
                    if address % PAGE_SIZE > 0 {
                        log::warn!("scheme returned unaligned address, causing extra frame to be allocated");
                    }
                    let file_ref = GrantFileRef { desc, offset: map.offset, flags: map.flags };
                    let res = UserInner::capture_inner(&context_weak, map.address, address, map.size, map.flags, Some(file_ref));
                    if let Ok(grant_address) = res {
                        if let Some(context_lock) = context_weak.upgrade() {
                            let context = context_lock.read();
                            let mut addr_space = context.addr_space()?.write();
                            //TODO: ensure all mappings are aligned!
                            let map_pages = (map.size + PAGE_SIZE - 1) / PAGE_SIZE;
                            addr_space.grants.funmap.insert(
                                Region::new(grant_address, map_pages * PAGE_SIZE),
                                VirtualAddress::new(address)
                            );
                        } else {
                            //TODO: packet.pid is an assumption
                            println!("UserInner::write: failed to find context {} for fmap", packet.pid);
                        }
                    }
                    retcode = Error::mux(res.map(|addr| addr.data()));
                } else {
                    let _ = desc.close();
                }
            }

            self.done.send(packet.id, Response::Regular(retcode));
        }

        Ok(())
    }

    pub fn fevent(&self, _flags: EventFlags) -> Result<EventFlags> {
        Ok(EventFlags::empty())
    }

    pub fn fsync(&self) -> Result<usize> {
        Ok(0)
    }

    fn fmap_inner(&self, file: usize, map: &Map) -> Result<usize> {
        let (pid, uid, gid, context_weak, desc) = {
            let context_lock = Arc::clone(context::contexts().current().ok_or(Error::new(ESRCH))?);
            let context = context_lock.read();
            if map.size % PAGE_SIZE != 0 {
                log::warn!("Unaligned map size for context `{}`", context.name);
            }
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
            (context.id, context.euid, context.egid, Arc::downgrade(&context_lock), desc)
        };

        let address = self.capture(map)?;

        let id = self.next_id();

        self.fmap.lock().insert(id, (context_weak, desc, *map));

        let result = self.call_extended_inner(Packet {
            id,
            pid: pid.into(),
            uid,
            gid,
            a: SYS_FMAP,
            b: file,
            c: address,
            d: mem::size_of::<Map>()
        });

        let _ = self.release(address);

        result.and_then(|response| match response {
            Response::Regular(code) => Error::demux(code),
            Response::Fd(_) => {
                log::debug!("Scheme incorrectly returned an fd for fmap.");

                Err(Error::new(EIO))
            }
        })
    }
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
        let address = inner.capture(path.as_bytes())?;
        let result = inner.call(SYS_RMDIR, address, path.len(), 0);
        let _ = inner.release(address);
        result
    }

    fn unlink(&self, path: &str, _uid: u32, _gid: u32) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let address = inner.capture(path.as_bytes())?;
        let result = inner.call(SYS_UNLINK, address, path.len(), 0);
        let _ = inner.release(address);
        result
    }

    fn dup(&self, old_id: usize, buf: &[u8]) -> Result<usize> {
        self.kdup(old_id, buf, UserInner::current_caller_ctx()?).and_then(handle_open_res)
    }

    fn read(&self, file: usize, buf: &mut [u8]) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let address = inner.capture_mut(buf)?;
        let result = inner.call(SYS_READ, file, address, buf.len());
        let _ = inner.release(address);
        result
    }

    fn write(&self, file: usize, buf: &[u8]) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let address = inner.capture(buf)?;
        let result = inner.call(SYS_WRITE, file, address, buf.len());
        let _ = inner.release(address);
        result
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

    fn fmap(&self, file: usize, map: &Map) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;

        inner.fmap_inner(file, map)
    }

    fn funmap(&self, grant_address: usize, size: usize) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let address_opt = {
            let contexts = context::contexts();
            let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
            let context = context_lock.read();
            let mut addr_space = context.addr_space()?.write();
            let funmap = &mut addr_space.grants.funmap;
            let entry = funmap.range(..=Region::byte(VirtualAddress::new(grant_address))).next_back();

            let grant_address = VirtualAddress::new(grant_address);

            if let Some((&grant, &user_base)) = entry {
                let grant_requested = Region::new(grant_address, size);
                if grant_requested.end_address() > grant.end_address() {
                    return Err(Error::new(EINVAL));
                }

                funmap.remove(&grant);

                let user = Region::new(user_base, grant.size());

                if let Some(before) = grant.before(grant_requested) {
                    funmap.insert(before, user_base);
                }
                if let Some(after) = grant.after(grant_requested) {
                    let start = grant.rebase(user, after.start_address());
                    funmap.insert(after, start);
                }

                Some(grant.rebase(user, grant_address).data())
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

    fn fpath(&self, file: usize, buf: &mut [u8]) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let address = inner.capture_mut(buf)?;
        let result = inner.call(SYS_FPATH, file, address, buf.len());
        let _ = inner.release(address);
        result
    }

    fn frename(&self, file: usize, path: &str, _uid: u32, _gid: u32) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let address = inner.capture(path.as_bytes())?;
        let result = inner.call(SYS_FRENAME, file, address, path.len());
        let _ = inner.release(address);
        result
    }

    fn fstat(&self, file: usize, stat: &mut Stat) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let address = inner.capture_mut(stat)?;
        let result = inner.call(SYS_FSTAT, file, address, mem::size_of::<Stat>());
        let _ = inner.release(address);
        result
    }

    fn fstatvfs(&self, file: usize, stat: &mut StatVfs) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let address = inner.capture_mut(stat)?;
        let result = inner.call(SYS_FSTATVFS, file, address, mem::size_of::<StatVfs>());
        let _ = inner.release(address);
        result
    }

    fn fsync(&self, file: usize) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        inner.call(SYS_FSYNC, file, 0, 0)
    }

    fn ftruncate(&self, file: usize, len: usize) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        inner.call(SYS_FTRUNCATE, file, len, 0)
    }

    fn futimens(&self, file: usize, times: &[TimeSpec]) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let buf = unsafe { slice::from_raw_parts(times.as_ptr() as *const u8, mem::size_of::<TimeSpec>() * times.len()) };
        let address = inner.capture(buf)?;
        let result = inner.call(SYS_FUTIMENS, file, address, buf.len());
        let _ = inner.release(address);
        result
    }

    fn close(&self, file: usize) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        inner.call(SYS_CLOSE, file, 0, 0)
    }
}
impl KernelScheme for UserScheme {
    fn kopen(&self, path: &str, flags: usize, ctx: CallerCtx) -> Result<OpenResult> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let address = inner.capture(path.as_bytes())?;
        let result = inner.call_extended(ctx, [SYS_OPEN, address, path.len(), flags]);
        let _ = inner.release(address);

        match result? {
            Response::Regular(code) => Error::demux(code).map(OpenResult::SchemeLocal),
            Response::Fd(desc) => Ok(OpenResult::External(desc)),
        }
    }
    fn kdup(&self, file: usize, buf: &[u8], ctx: CallerCtx) -> Result<OpenResult> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let address = inner.capture(buf)?;
        let result = inner.call_extended(ctx, [SYS_DUP, file, address, buf.len()]);
        let _ = inner.release(address);

        match result? {
            Response::Regular(code) => Error::demux(code).map(OpenResult::SchemeLocal),
            Response::Fd(desc) => Ok(OpenResult::External(desc)),
        }
    }
}
