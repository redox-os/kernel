use alloc::sync::{Arc, Weak};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::{mem, slice, usize};
use spin::{Mutex, RwLock};

use crate::context::{self, Context};
use crate::context::file::FileDescriptor;
use crate::context::memory::Grant;
use crate::event;
use crate::paging::{InactivePageTable, Page, VirtualAddress};
use crate::paging::entry::EntryFlags;
use crate::paging::temporary_page::TemporaryPage;
use crate::scheme::{AtomicSchemeId, ATOMIC_SCHEMEID_INIT, SchemeId};
use crate::sync::{WaitQueue, WaitMap};
use crate::syscall::data::{Map, Packet, Stat, StatVfs, TimeSpec};
use crate::syscall::error::*;
use crate::syscall::flag::{EVENT_READ, O_NONBLOCK, PROT_EXEC, PROT_READ, PROT_WRITE};
use crate::syscall::number::*;
use crate::syscall::scheme::Scheme;

pub struct UserInner {
    root_id: SchemeId,
    handle_id: usize,
    pub name: Box<[u8]>,
    pub flags: usize,
    pub scheme_id: AtomicSchemeId,
    next_id: AtomicU64,
    context: Weak<RwLock<Context>>,
    todo: WaitQueue<Packet>,
    fmap: Mutex<BTreeMap<u64, (Weak<RwLock<Context>>, FileDescriptor, Map)>>,
    funmap: Mutex<BTreeMap<usize, usize>>,
    done: WaitMap<u64, usize>,
    unmounting: AtomicBool,
}

impl UserInner {
    pub fn new(root_id: SchemeId, handle_id: usize, name: Box<[u8]>, flags: usize, context: Weak<RwLock<Context>>) -> UserInner {
        UserInner {
            root_id: root_id,
            handle_id: handle_id,
            name: name,
            flags: flags,
            scheme_id: ATOMIC_SCHEMEID_INIT,
            next_id: AtomicU64::new(1),
            context: context,
            todo: WaitQueue::new(),
            fmap: Mutex::new(BTreeMap::new()),
            funmap: Mutex::new(BTreeMap::new()),
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

    pub fn call(&self, a: usize, b: usize, c: usize, d: usize) -> Result<usize> {
        let (pid, uid, gid) = {
            let contexts = context::contexts();
            let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
            let context = context_lock.read();
            (context.id, context.euid, context.egid)
        };

        self.call_inner(Packet {
            id: self.next_id.fetch_add(1, Ordering::SeqCst),
            pid: pid.into(),
            uid: uid,
            gid: gid,
            a: a,
            b: b,
            c: c,
            d: d
        })
    }

    fn call_inner(&self, packet: Packet) -> Result<usize> {
        if self.unmounting.load(Ordering::SeqCst) {
            return Err(Error::new(ENODEV));
        }

        let id = packet.id;

        self.todo.send(packet);
        event::trigger(self.root_id, self.handle_id, EVENT_READ);

        Error::demux(self.done.receive(&id))
    }

    pub fn capture(&self, buf: &[u8]) -> Result<usize> {
        UserInner::capture_inner(&self.context, buf.as_ptr() as usize, buf.len(), PROT_READ, None)
    }

    pub fn capture_mut(&self, buf: &mut [u8]) -> Result<usize> {
        UserInner::capture_inner(&self.context, buf.as_mut_ptr() as usize, buf.len(), PROT_WRITE, None)
    }

    fn capture_inner(context_weak: &Weak<RwLock<Context>>, address: usize, size: usize, flags: usize, desc_opt: Option<FileDescriptor>) -> Result<usize> {
        //TODO: Abstract with other grant creation
        if size == 0 {
            Ok(0)
        } else {
            let context_lock = context_weak.upgrade().ok_or(Error::new(ESRCH))?;
            let context = context_lock.read();

            let mut grants = context.grants.lock();

            let mut new_table = unsafe { InactivePageTable::from_address(context.arch.get_page_table()) };
            let mut temporary_page = TemporaryPage::new(Page::containing_address(VirtualAddress::new(crate::USER_TMP_GRANT_OFFSET)));

            let from_address = (address/4096) * 4096;
            let offset = address - from_address;
            let full_size = ((offset + size + 4095)/4096) * 4096;
            let mut to_address = crate::USER_GRANT_OFFSET;

            let mut entry_flags = EntryFlags::PRESENT | EntryFlags::USER_ACCESSIBLE;
            if flags & PROT_EXEC == 0 {
                entry_flags |= EntryFlags::NO_EXECUTE;
            }
            if flags & PROT_READ > 0 {
                //TODO: PROT_READ
            }
            if flags & PROT_WRITE > 0 {
                entry_flags |= EntryFlags::WRITABLE;
            }

            let mut i = 0;
            while i < grants.len() {
                let start = grants[i].start_address().get();
                if to_address + full_size < start {
                    break;
                }

                let pages = (grants[i].size() + 4095) / 4096;
                let end = start + pages * 4096;
                to_address = end;
                i += 1;
            }

            //TODO: Use syscall_head and syscall_tail to avoid leaking data
            grants.insert(i, Grant::map_inactive(
                VirtualAddress::new(from_address),
                VirtualAddress::new(to_address),
                full_size,
                entry_flags,
                desc_opt,
                &mut new_table,
                &mut temporary_page
            ));

            Ok(to_address + offset)
        }
    }

    pub fn release(&self, address: usize) -> Result<()> {
        if address == 0 {
            Ok(())
        } else {
            let context_lock = self.context.upgrade().ok_or(Error::new(ESRCH))?;
            let context = context_lock.read();

            let mut grants = context.grants.lock();

            let mut new_table = unsafe { InactivePageTable::from_address(context.arch.get_page_table()) };
            let mut temporary_page = TemporaryPage::new(Page::containing_address(VirtualAddress::new(crate::USER_TMP_GRANT_OFFSET)));

            for i in 0 .. grants.len() {
                let start = grants[i].start_address().get();
                let end = start + grants[i].size();
                if address >= start && address < end {
                    grants.remove(i).unmap_inactive(&mut new_table, &mut temporary_page);

                    return Ok(());
                }
            }

            Err(Error::new(EFAULT))
        }
    }

    pub fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let packet_buf = unsafe { slice::from_raw_parts_mut(
            buf.as_mut_ptr() as *mut Packet,
            buf.len()/mem::size_of::<Packet>())
        };

        // If O_NONBLOCK is used, do not block
        let nonblock = self.flags & O_NONBLOCK == O_NONBLOCK;
        // If unmounting, do not block so that EOF can be returned immediately
        let unmounting = self.unmounting.load(Ordering::SeqCst);
        let block = !(nonblock || unmounting);
        if let Some(count) = self.todo.receive_into(packet_buf, block) {
            if count > 0 {
                // If we received requests, return them to the scheme handler
                Ok(count * mem::size_of::<Packet>())
            } else if unmounting {
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
        let packet_size = mem::size_of::<Packet>();
        let len = buf.len()/packet_size;
        let mut i = 0;
        while i < len {
            let mut packet = unsafe { *(buf.as_ptr() as *const Packet).offset(i as isize) };
            if packet.id == 0 {
                match packet.a {
                    SYS_FEVENT => event::trigger(self.scheme_id.load(Ordering::SeqCst), packet.b, packet.c),
                    _ => println!("Unknown scheme -> kernel message {}", packet.a)
                }
            } else {
                if let Some((context_weak, desc, map)) = self.fmap.lock().remove(&packet.id) {
                    if let Ok(address) = Error::demux(packet.a) {
                        //TODO: Protect against sharing addresses that are not page aligned
                        let res = UserInner::capture_inner(&context_weak, address, map.size, map.flags, Some(desc));
                        if let Ok(new_address) = res {
                            self.funmap.lock().insert(new_address, address);
                        }
                        packet.a = Error::mux(res);
                    } else {
                        let _ = desc.close();
                    }
                }

                self.done.send(packet.id, packet.a);
            }
            i += 1;
        }

        Ok(i * packet_size)
    }

    pub fn fevent(&self, _flags: usize) -> Result<usize> {
        Ok(0)
    }

    pub fn fsync(&self) -> Result<usize> {
        Ok(0)
    }
}

/// `UserInner` has to be wrapped
pub struct UserScheme {
    inner: Weak<UserInner>
}

impl UserScheme {
    pub fn new(inner: Weak<UserInner>) -> UserScheme {
        UserScheme {
            inner: inner
        }
    }
}

impl Scheme for UserScheme {
    fn open(&self, path: &[u8], flags: usize, _uid: u32, _gid: u32) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let address = inner.capture(path)?;
        let result = inner.call(SYS_OPEN, address, path.len(), flags);
        let _ = inner.release(address);
        result
    }

    fn chmod(&self, path: &[u8], mode: u16, _uid: u32, _gid: u32) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let address = inner.capture(path)?;
        let result = inner.call(SYS_CHMOD, address, path.len(), mode as usize);
        let _ = inner.release(address);
        result
    }

    fn rmdir(&self, path: &[u8], _uid: u32, _gid: u32) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let address = inner.capture(path)?;
        let result = inner.call(SYS_RMDIR, address, path.len(), 0);
        let _ = inner.release(address);
        result
    }

    fn unlink(&self, path: &[u8], _uid: u32, _gid: u32) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let address = inner.capture(path)?;
        let result = inner.call(SYS_UNLINK, address, path.len(), 0);
        let _ = inner.release(address);
        result
    }

    fn dup(&self, file: usize, buf: &[u8]) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let address = inner.capture(buf)?;
        let result = inner.call(SYS_DUP, file, address, buf.len());
        let _ = inner.release(address);
        result
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

    fn seek(&self, file: usize, position: usize, whence: usize) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        inner.call(SYS_LSEEK, file, position, whence)
    }

    fn fchmod(&self, file: usize, mode: u16) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        inner.call(SYS_FCHMOD, file, mode as usize, 0)
    }

    fn fchown(&self, file: usize, uid: u32, gid: u32) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        inner.call(SYS_FCHOWN, file, uid as usize, gid as usize)
    }

    fn fcntl(&self, file: usize, cmd: usize, arg: usize) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        inner.call(SYS_FCNTL, file, cmd, arg)
    }

    fn fevent(&self, file: usize, flags: usize) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        inner.call(SYS_FEVENT, file, flags, 0)
    }

    fn fmap(&self, file: usize, map: &Map) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;

        let (pid, uid, gid, context_lock, desc) = {
            let contexts = context::contexts();
            let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
            let context = context_lock.read();
            // TODO: Faster, cleaner mechanism to get descriptor
            let scheme = inner.scheme_id.load(Ordering::SeqCst);
            let mut desc_res = Err(Error::new(EBADF));
            for context_file_opt in context.files.lock().iter() {
                if let Some(context_file) = context_file_opt {
                    let (context_scheme, context_number) = {
                        let desc = context_file.description.read();
                        (desc.scheme, desc.number)
                    };
                    if context_scheme == scheme && context_number == file {
                        desc_res = Ok(context_file.clone());
                        break;
                    }
                }
            }
            let desc = desc_res?;
            (context.id, context.euid, context.egid, Arc::downgrade(&context_lock), desc)
        };

        let address = inner.capture(map)?;

        let id = inner.next_id.fetch_add(1, Ordering::SeqCst);

        inner.fmap.lock().insert(id, (context_lock, desc, *map));

        let result = inner.call_inner(Packet {
            id: id,
            pid: pid.into(),
            uid: uid,
            gid: gid,
            a: SYS_FMAP,
            b: file,
            c: address,
            d: mem::size_of::<Map>()
        });

        let _ = inner.release(address);

        result
    }

    fn funmap(&self, new_address: usize) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let address_opt = {
            let mut funmap = inner.funmap.lock();
            funmap.remove(&new_address)
        };
        if let Some(address) = address_opt {
            inner.call(SYS_FUNMAP, address, 0, 0)
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

    fn frename(&self, file: usize, path: &[u8], _uid: u32, _gid: u32) -> Result<usize> {
        let inner = self.inner.upgrade().ok_or(Error::new(ENODEV))?;
        let address = inner.capture(path)?;
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
