use core::{marker::PhantomData, mem};

use crate::{
    Arch, BumpAllocator, FrameAllocator, FrameCount, FrameUsage, PhysicalAddress, VirtualAddress,
};

#[repr(transparent)]
struct BuddyUsage(u8);

#[repr(C, packed)]
struct BuddyEntry<A> {
    base: PhysicalAddress,
    size: usize,
    // Number of first free page
    skip: usize,
    // Count of used pages
    used: usize,
    phantom: PhantomData<A>,
}

impl<A> Clone for BuddyEntry<A> {
    fn clone(&self) -> Self {
        Self {
            base: self.base,
            size: self.size,
            skip: self.skip,
            used: self.used,
            phantom: PhantomData,
        }
    }
}
impl<A> Copy for BuddyEntry<A> {}

impl<A: Arch> BuddyEntry<A> {
    fn empty() -> Self {
        Self {
            base: PhysicalAddress::new(0),
            size: 0,
            skip: 0,
            used: 0,
            phantom: PhantomData,
        }
    }

    #[inline(always)]
    fn pages(&self) -> usize {
        self.size >> A::PAGE_SHIFT
    }

    fn usage_pages(&self) -> usize {
        let bytes = self.pages() * mem::size_of::<BuddyUsage>();
        // Round bytes used for usage to next page
        (bytes + A::PAGE_OFFSET_MASK) >> A::PAGE_SHIFT
    }

    unsafe fn usage_addr(&self, page: usize) -> Option<VirtualAddress> {
        unsafe {
            if page < self.pages() {
                let phys = self.base.add(page * mem::size_of::<BuddyUsage>());
                Some(A::phys_to_virt(phys))
            } else {
                None
            }
        }
    }

    unsafe fn usage(&self, page: usize) -> Option<BuddyUsage> {
        unsafe {
            let addr = self.usage_addr(page)?;
            Some(A::read(addr))
        }
    }

    unsafe fn set_usage(&self, page: usize, usage: BuddyUsage) -> Option<()> {
        unsafe {
            let addr = self.usage_addr(page)?;
            Some(A::write(addr, usage))
        }
    }
}

pub struct BuddyAllocator<A> {
    table_virt: VirtualAddress,
    phantom: PhantomData<A>,
}

impl<A: Arch> BuddyAllocator<A> {
    const BUDDY_ENTRIES: usize = A::PAGE_SIZE / mem::size_of::<BuddyEntry<A>>();

    pub unsafe fn new(mut bump_allocator: BumpAllocator<A>) -> Option<Self> {
        unsafe {
            // Allocate buddy table
            let table_phys = bump_allocator.allocate_one()?;
            let table_virt = A::phys_to_virt(table_phys);
            for i in 0..(A::PAGE_SIZE / mem::size_of::<BuddyEntry<A>>()) {
                let virt = table_virt.add(i * mem::size_of::<BuddyEntry<A>>());
                A::write(virt, BuddyEntry::<A>::empty());
            }

            let allocator = Self {
                table_virt,
                phantom: PhantomData,
            };

            // Add areas to buddy table, combining areas when possible, and skipping frames used
            // by the bump allocator
            let mut offset = bump_allocator.offset();
            for old_area in bump_allocator.areas().iter() {
                let mut area = old_area.clone();
                if offset >= area.size {
                    offset -= area.size;
                    continue;
                } else if offset > 0 {
                    area.base = area.base.add(offset);
                    area.size -= offset;
                    offset = 0;
                }
                for i in 0..(A::PAGE_SIZE / mem::size_of::<BuddyEntry<A>>()) {
                    let virt = table_virt.add(i * mem::size_of::<BuddyEntry<A>>());
                    let mut entry = A::read::<BuddyEntry<A>>(virt);
                    let inserted = if area.base.add(area.size) == { entry.base } {
                        // Combine entry at start
                        entry.base = area.base;
                        entry.size += area.size;
                        true
                    } else if area.base == entry.base.add(entry.size) {
                        // Combine entry at end
                        entry.size += area.size;
                        true
                    } else if entry.size == 0 {
                        // Create new entry
                        entry.base = area.base;
                        entry.size = area.size;
                        true
                    } else {
                        false
                    };
                    if inserted {
                        A::write(virt, entry);
                        break;
                    }
                }
            }

            //TODO: sort areas?

            // Allocate buddy maps
            for i in 0..Self::BUDDY_ENTRIES {
                let virt = table_virt.add(i * mem::size_of::<BuddyEntry<A>>());
                let mut entry = A::read::<BuddyEntry<A>>(virt);

                // Only set up entries that have enough space for their own usage map
                let usage_pages = entry.usage_pages();
                if entry.pages() > usage_pages {
                    // Mark all usage bytes as unused
                    let usage_start = entry.usage_addr(0)?;
                    for page in 0..usage_pages {
                        A::write_bytes(usage_start.add(page << A::PAGE_SHIFT), 0, A::PAGE_SIZE);
                    }

                    // Mark bytes used for usage as used
                    for page in 0..usage_pages {
                        entry.set_usage(page, BuddyUsage(1))?;
                    }
                }

                // Skip the pages used for usage
                entry.skip = usage_pages;

                // Set used pages to pages used for usage
                entry.used = usage_pages;

                // Write updated entry
                A::write(virt, entry);
            }

            Some(allocator)
        }
    }
}

impl<A: Arch> FrameAllocator for BuddyAllocator<A> {
    unsafe fn allocate(&mut self, count: FrameCount) -> Option<PhysicalAddress> {
        unsafe {
            if self.table_virt.data() == 0 {
                return None;
            }

            for entry_i in 0..Self::BUDDY_ENTRIES {
                let virt = self
                    .table_virt
                    .add(entry_i * mem::size_of::<BuddyEntry<A>>());
                let mut entry = A::read::<BuddyEntry<A>>(virt);

                let mut free_page = entry.skip;
                let mut free_count = 0;
                for page in entry.skip..entry.pages() {
                    let usage = entry.usage(page)?;
                    if usage.0 == 0 {
                        free_count += 1;

                        if free_count == count.data() {
                            break;
                        }
                    } else {
                        free_page = page + 1;
                        free_count = 0;
                    }
                }

                if free_count == count.data() {
                    for page in free_page..free_page + free_count {
                        // Update usage
                        let mut usage = entry.usage(page)?;
                        usage.0 += 1;
                        entry.set_usage(page, usage);

                        // Zero page
                        let page_phys = entry.base.add(page << A::PAGE_SHIFT);
                        let page_virt = A::phys_to_virt(page_phys);
                        A::write_bytes(page_virt, 0, A::PAGE_SIZE);
                    }

                    // Update skip if necessary
                    if entry.skip == free_page {
                        entry.skip = free_page + free_count;
                    }

                    // Update used page count
                    entry.used += free_count;

                    // Write updated entry
                    A::write(virt, entry);

                    return Some(entry.base.add(free_page << A::PAGE_SHIFT));
                }
            }

            None
        }
    }

    unsafe fn free(&mut self, base: PhysicalAddress, count: FrameCount) {
        unsafe {
            if self.table_virt.data() == 0 {
                return;
            }

            let size = count.data() * A::PAGE_SIZE;
            for i in 0..Self::BUDDY_ENTRIES {
                let virt = self.table_virt.add(i * mem::size_of::<BuddyEntry<A>>());
                let mut entry = A::read::<BuddyEntry<A>>(virt);

                if base >= { entry.base } && base.add(size) <= entry.base.add(entry.size) {
                    let start_page = (base.data() - { entry.base }.data()) >> A::PAGE_SHIFT;
                    for page in start_page..start_page + count.data() {
                        let mut usage = entry.usage(page).expect("failed to get usage during free");

                        if usage.0 > 0 {
                            usage.0 -= 1;
                        } else {
                            panic!("tried to free already free frame");
                        }

                        // If page was freed
                        if usage.0 == 0 {
                            // Update skip if necessary
                            if page < entry.skip {
                                entry.skip = page;
                            }

                            // Update used page count
                            entry.used -= 1;
                        }

                        entry
                            .set_usage(page, usage)
                            .expect("failed to set usage during free");
                    }

                    // Write updated entry
                    A::write(virt, entry);

                    return;
                }
            }
        }
    }

    unsafe fn usage(&self) -> FrameUsage {
        unsafe {
            let mut total = 0;
            let mut used = 0;
            for i in 0..Self::BUDDY_ENTRIES {
                let virt = self.table_virt.add(i * mem::size_of::<BuddyEntry<A>>());
                let entry = A::read::<BuddyEntry<A>>(virt);
                total += entry.size >> A::PAGE_SHIFT;
                used += entry.used;
            }
            FrameUsage::new(FrameCount::new(used), FrameCount::new(total))
        }
    }
}
