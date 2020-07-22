use core::cmp;
use crate::context;
use crate::context::memory::{round_pages, Grant};
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

            let full_size = round_pages(map.size);

            let mut to_address = if map.address == 0 { crate::USER_GRANT_OFFSET } else {
                if
                    map.address + full_size >= crate::PML4_SIZE * 256 // There are 256 PML4 entries reserved for userspace
                    && map.address % PAGE_SIZE != 0
                {
                    return Err(Error::new(EINVAL));
                }
                map.address
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

            for grant in grants.iter() {
                let grant_start = grant.start_address().get();
                let grant_len = grant.full_size();
                let grant_end = grant_start + grant_len;

                if !grant.occupies(VirtualAddress::new(to_address), full_size) {
                    // grant has nothing to do with the memory to map, and thus we can safely just
                    // go on to the next one.

                    if !fixed {
                        // Use the default grant offset, or if we've already passed it, anything after that.
                        to_address = cmp::max(
                            cmp::max(crate::USER_GRANT_OFFSET, grant_end),
                            to_address,
                        );
                    }

                    continue;
                } else {
                    // the range overlaps, thus we'll have to continue to the next grant, or to
                    // insert a new grant at the end (if not MapFlags::MAP_FIXED).

                    if fixed_noreplace {
                        println!("grant: conflicts with: {:#x} - {:#x}", grant_start, grant_end);
                        return Err(Error::new(EEXIST));
                    } else if fixed {
                        /*
                        // shrink the grant, removing it if necessary. since the to_address isn't
                        // changed at all when mapping to a fixed address, we can just continue to
                        // the next grant and shrink or remove that one if it was also overlapping.
                        if to_address + full_size > grant_start {
                        let new_start = core::cmp::min(grant_end, to_address + full_size);

                            let new_size = grant.size() - (new_start - grant_start);
                            unsafe { grant.set_size(new_size) };
                            grant_len = ((new_size + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE;

                            let new_start = VirtualAddress::new(new_start);
                            unsafe { grant.set_start_address(new_start) };
                            grant_start = new_start;

                            grant_end = grant_start + grant_len;
                        }
                        */
                        // TODO
                        return Err(Error::new(EOPNOTSUPP));
                    } else {
                        to_address = grant_end;
                    }
                    continue;
                }
            }

            let start_address = VirtualAddress::new(to_address);
            let end_address = VirtualAddress::new(to_address + full_size);

            // Make sure it's absolutely not mapped already
            let active_table = unsafe { ActivePageTable::new() };

            for page in Page::range_inclusive(Page::containing_address(start_address), Page::containing_address(end_address)) {
                if active_table.translate_page(page).is_some() {
                    return Err(Error::new(EEXIST))
                }
            }

            grants.insert(Grant::map(start_address, full_size, entry_flags));

            Ok(to_address)
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
