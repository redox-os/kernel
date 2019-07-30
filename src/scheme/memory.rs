use crate::context;
use crate::context::memory::Grant;
use crate::memory::{free_frames, used_frames};
use crate::paging::VirtualAddress;
use crate::paging::entry::EntryFlags;
use crate::syscall::data::{Map, StatVfs};
use crate::syscall::error::*;
use crate::syscall::flag::{PROT_EXEC, PROT_READ, PROT_WRITE};
use crate::syscall::scheme::Scheme;

pub struct MemoryScheme;

impl MemoryScheme {
    pub fn new() -> Self {
        MemoryScheme
    }
}
impl Scheme for MemoryScheme {
    fn open(&self, _path: &[u8], _flags: usize, _uid: u32, _gid: u32) -> Result<usize> {
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

    fn fmap(&self, _id: usize, map: &Map) -> Result<usize> {
        //TODO: Abstract with other grant creation
        if map.size == 0 {
            Ok(0)
        } else {
            let contexts = context::contexts();
            let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
            let context = context_lock.read();

            let mut grants = context.grants.lock();

            let full_size = ((map.size + 4095)/4096) * 4096;
            let mut to_address = crate::USER_GRANT_OFFSET;

            let mut entry_flags = EntryFlags::PRESENT | EntryFlags::USER_ACCESSIBLE;
            if !map.flags.contains(PROT_EXEC) {
                entry_flags |= EntryFlags::NO_EXECUTE;
            }
            if map.flags.contains(PROT_READ) {
                //TODO: PROT_READ
            }
            if map.flags.contains(PROT_WRITE) {
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

            grants.insert(i, Grant::map(
                VirtualAddress::new(to_address),
                full_size,
                entry_flags
            ));

            Ok(to_address)
        }
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

    fn close(&self, _id: usize) -> Result<usize> {
        Ok(0)
    }
}
