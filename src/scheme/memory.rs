use alloc::sync::Arc;
use spin::RwLock;

use crate::context;
use crate::context::memory::{AddrSpace, Grant};
use crate::memory::{free_frames, used_frames, PAGE_SIZE};

use crate::syscall::data::{Map, StatVfs};
use crate::syscall::error::*;
use crate::syscall::scheme::Scheme;
use crate::syscall::usercopy::UserSliceWo;

pub struct MemoryScheme;

impl MemoryScheme {
    pub fn new() -> Self {
        MemoryScheme
    }

    pub fn fmap_anonymous(addr_space: &Arc<RwLock<AddrSpace>>, map: &Map) -> Result<usize> {
        let (requested_page, page_count) = crate::syscall::usercopy::validate_region(map.address, map.size)?;

        let page = addr_space
            .write()
            .mmap((map.address != 0).then_some(requested_page), page_count, map.flags, |page, flags, mapper, flusher| {
                Ok(Grant::zeroed(page, page_count, flags, mapper, flusher)?)
            })?;

        Ok(page.start_address().data())
    }
}
impl Scheme for MemoryScheme {
    fn open(&self, _path: &str, _flags: usize, _uid: u32, _gid: u32) -> Result<usize> {
        Ok(0)
    }

    fn fmap(&self, _id: usize, map: &Map) -> Result<usize> {
        Self::fmap_anonymous(&Arc::clone(context::current()?.read().addr_space()?), map)
    }

    fn fcntl(&self, _id: usize, _cmd: usize, _arg: usize) -> Result<usize> {
        Ok(0)
    }

    fn close(&self, _id: usize) -> Result<usize> {
        Ok(0)
    }
}
impl crate::scheme::KernelScheme for MemoryScheme {
    fn kfmap(&self, _number: usize, addr_space: &Arc<RwLock<AddrSpace>>, map: &Map, _consume: bool) -> Result<usize> {
        Self::fmap_anonymous(addr_space, map)
    }
    fn kfpath(&self, _id: usize, dst: UserSliceWo) -> Result<usize> {
        // TODO: Copy scheme name elsewhere in the kernel?
        const SRC: &[u8] = b"memory:";
        let byte_count = core::cmp::min(SRC.len(), dst.len());
        dst.limit(byte_count).ok_or(Error::new(EINVAL))?.copy_from_slice(SRC)?;
        Ok(0)
    }
    fn kfstatvfs(&self, _file: usize, dst: UserSliceWo) -> Result<usize> {
        let used = used_frames() as u64;
        let free = free_frames() as u64;

        let stat = StatVfs {
            f_bsize: PAGE_SIZE.try_into().map_err(|_| Error::new(EOVERFLOW))?,
            f_blocks: used + free,
            f_bfree: free,
            f_bavail: free,
        };
        dst.limit(core::mem::size_of::<StatVfs>()).ok_or(Error::new(EINVAL))?.copy_from_slice(&stat)?;

        Ok(0)
    }

}
