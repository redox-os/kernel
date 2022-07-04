use crate::context;
use crate::context::memory::{page_flags, Grant};
use crate::memory::{free_frames, used_frames, PAGE_SIZE};
use crate::paging::{ActivePageTable, mapper::PageFlushAll, Page, VirtualAddress};
use crate::syscall::data::{Map, OldMap, StatVfs};
use crate::syscall::error::*;
use crate::syscall::flag::MapFlags;
use crate::syscall::scheme::Scheme;

pub struct MemoryScheme;

impl MemoryScheme {
    pub fn new() -> Self {
        MemoryScheme
    }

    pub fn fmap_anonymous(map: &Map) -> Result<usize> {
        //TODO: Abstract with other grant creation
        if map.size == 0 {
            return Ok(0);
        }
        let contexts = context::contexts();
        let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
        let context = context_lock.read();

        let mut addr_space = context.addr_space()?.write();

        let region = addr_space.grants.find_free_at(VirtualAddress::new(map.address), map.size, map.flags)?.round();

        addr_space.grants.insert(Grant::zeroed(Page::containing_address(region.start_address()), map.size / PAGE_SIZE, page_flags(map.flags), &mut *unsafe { ActivePageTable::new(rmm::TableKind::User) }, PageFlushAll::new())?);

        Ok(region.start_address().data())
    }
}
impl Scheme for MemoryScheme {
    fn open(&self, _path: &str, _flags: usize, _uid: u32, _gid: u32) -> Result<usize> {
        Ok(0)
    }

    fn fstatvfs(&self, _file: usize, stat: &mut StatVfs) -> Result<usize> {
        let used = used_frames() as u64;
        let free = free_frames() as u64;

        stat.f_bsize = PAGE_SIZE as u32;
        stat.f_blocks = used + free;
        stat.f_bfree = free;
        stat.f_bavail = stat.f_bfree;

        Ok(0)
    }

    fn fmap(&self, _id: usize, map: &Map) -> Result<usize> {
        Self::fmap_anonymous(map)
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
impl crate::scheme::KernelScheme for MemoryScheme {}
