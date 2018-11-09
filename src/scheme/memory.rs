use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use memory::{free_frames, used_frames};
use spin::Mutex;

use syscall::data::StatVfs;
use syscall::error::*;
use syscall::scheme::Scheme;
use syscall;

struct Address {
    phys: usize,
    len: usize,
    virt: usize
}
pub struct MemoryScheme {
    handles: Mutex<BTreeMap<usize, Vec<Address>>>,
    next_id: AtomicUsize
}

impl MemoryScheme {
    pub fn new() -> Self {
        Self {
            handles: Mutex::new(BTreeMap::new()),
            next_id: AtomicUsize::new(0)
        }
    }
}
impl Scheme for MemoryScheme {
    fn open(&self, _path: &[u8], _flags: usize, _uid: u32, _gid: u32) -> Result<usize> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        self.handles.lock().insert(id, Vec::new());
        Ok(0)
    }

    fn fstatvfs(&self, _file: usize, stat: &mut StatVfs) -> Result<usize> {
        let used = used_frames() as u64;
        let free = free_frames() as u64;

        stat.f_bsize = 4096;
        stat.f_blocks = used + free;
        stat.f_bfree = free;
        stat.f_bavail = stat.f_bfree;

        Ok(0)
    }

    fn fmap(&self, id: usize, _offset: usize, len: usize) -> Result<usize> {
        let mut handles = self.handles.lock();
        let handle = handles.get_mut(&id).ok_or(Error::new(ENOENT))?;

        // Warning: These functions are bypassing the root check.
        let phys = syscall::inner_physalloc(len)?;
        let virt = syscall::inner_physmap(phys, len, syscall::flag::MAP_WRITE).map_err(|err| {
            syscall::inner_physfree(phys, len).expect("newly allocated region failed to free");
            err
        })?;

        handle.push(Address {
            phys,
            len,
            virt
        });

        Ok(virt)
    }

    fn fcntl(&self, _id: usize, _cmd: usize, _arg: usize) -> Result<usize> {
        Ok(0)
    }

    fn fpath(&self, _id: usize, buf: &mut [u8]) -> Result<usize> {
        let mut i = 0;
        let scheme_path = b"memory:";
        while i < buf.len() && i < scheme_path.len() {
            buf[i] = scheme_path[i];
            i += 1;
        }
        Ok(i)
    }

    fn close(&self, id: usize) -> Result<usize> {
        let allocations = self.handles.lock()
            .remove(&id)
            .ok_or(Error::new(ENOENT))?;

        for addr in allocations {
            // physunmap fails if already unmapped
            // physfree can't currently fail
            //
            // What if somebody with root already freed the physical address?
            // (But left the mapping, which means we attempt to free it again)
            // I'd rather not think about it.
            // (Still, that requires root)
            let _ = syscall::inner_physunmap(addr.virt)
                .and_then(|_| syscall::inner_physfree(addr.phys, addr.len));
        }

        Ok(0)
    }
}
