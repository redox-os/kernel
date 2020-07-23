use crate::context;
use crate::context::memory::{Grant, Region};
use crate::memory::{free_frames, used_frames, PAGE_SIZE};
use crate::paging::{ActivePageTable, Page, VirtualAddress};
use crate::paging::entry::EntryFlags;
use crate::syscall::data::{Map, Map2, StatVfs};
use crate::syscall::error::*;
use crate::syscall::flag::{MapFlags, PROT_EXEC, PROT_READ, PROT_WRITE};
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

        stat.f_bsize = PAGE_SIZE as u32;
        stat.f_blocks = used + free;
        stat.f_bfree = free;
        stat.f_bavail = stat.f_bfree;

        Ok(0)
    }

    fn fmap2(&self, _id: usize, map: &Map2) -> Result<usize> {
        //TODO: Abstract with other grant creation
        if map.size == 0 {
            Ok(0)
        } else {
            let contexts = context::contexts();
            let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
            let context = context_lock.read();

            let fixed = map.flags.contains(MapFlags::MAP_FIXED);
            let fixed_noreplace = map.flags.contains(MapFlags::MAP_FIXED_NOREPLACE);

            let mut grants = context.grants.lock();

            let requested = if map.address == 0 {
                grants.find_free(map.size).round()
            } else {
                let mut requested = Region::new(VirtualAddress::new(map.address), map.size);

                if
                    requested.end_address().get() >= crate::PML4_SIZE * 256 // There are 256 PML4 entries reserved for userspace
                    && map.address % PAGE_SIZE != 0
                {
                    return Err(Error::new(EINVAL));
                }

                if let Some(grant) = grants.contains(requested.start_address()) {
                    if fixed_noreplace {
                        println!("grant: conflicts with: {:#x} - {:#x}", grant.start_address().get(), grant.end_address().get());
                        return Err(Error::new(EEXIST));
                    } else if fixed {
                        // TODO: Overwrite existing grant
                        return Err(Error::new(EOPNOTSUPP));
                    } else {
                        requested = grants.find_free(requested.size());
                    }
                }

                requested.round()
            };

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

            let start_address = requested.start_address();
            let end_address = requested.end_address();

            // Make sure it's *absolutely* not mapped already
            // TODO: Keep track of all allocated memory so this isn't necessary

            let active_table = unsafe { ActivePageTable::new() };

            for page in Page::range_inclusive(Page::containing_address(start_address), Page::containing_address(end_address)) {
                if active_table.translate_page(page).is_some() {
                    return Err(Error::new(EEXIST))
                }
            }

            grants.insert(Grant::map(start_address, requested.size(), entry_flags));

            Ok(start_address.get())
        }
    }
    fn fmap(&self, id: usize, map: &Map) -> Result<usize> {
        if map.flags.contains(MapFlags::MAP_FIXED) {
            // not supported for fmap, which lacks the address argument.
            return Err(Error::new(EINVAL));
        }
        self.fmap2(id, &Map2 {
            offset: map.offset,
            size: map.size,
            flags: map.flags,
            address: 0,
        })
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
