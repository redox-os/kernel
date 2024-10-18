use crate::{
    arch::{consts::KERNEL_OFFSET, paging::entry::EntryFlags, rmm::page_flags, CurrentRmmArch},
    memory::PAGE_SIZE,
    startup::memory::BootloaderMemoryKind::Null,
};
use core::{
    cmp::{max, min},
    mem, slice,
    slice::Iter,
};
use rmm::{
    Arch, BumpAllocator, MemoryArea, PageFlags, PageMapper, PhysicalAddress, TableKind,
    VirtualAddress, KILOBYTE, MEGABYTE,
};

// Keep synced with OsMemoryKind in bootloader
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
#[allow(dead_code)]
pub enum BootloaderMemoryKind {
    Null = 0,
    Free = 1,
    Reclaim = 2,
    Reserved = 3,

    // These are local to kernel
    Kernel = 0x100,
    Device = 0x101,
    IdentityMap = 0x102,
}

// Keep synced with OsMemoryEntry in bootloader
#[derive(Clone, Copy, Debug)]
#[repr(C, packed(8))]
struct BootloaderMemoryEntry {
    pub base: u64,
    pub size: u64,
    pub kind: BootloaderMemoryKind,
}

#[derive(Clone, Copy, Debug)]
struct MemoryEntry {
    pub start: usize,
    pub end: usize,
    pub kind: BootloaderMemoryKind,
}

impl MemoryEntry {
    fn intersect(&self, other: &Self) -> Option<Self> {
        let start = max(self.start, other.start);
        let end = min(self.end, other.end);
        if start < end {
            Some(Self {
                start,
                end,
                kind: self.kind,
            })
        } else {
            None
        }
    }

    fn combine(&self, other: &Self) -> Option<Self> {
        if self.start <= other.end && self.end >= other.start {
            Some(Self {
                start: min(self.start, other.start),
                end: max(self.end, other.end),
                kind: self.kind,
            })
        } else {
            None
        }
    }
}

struct MemoryMap {
    entries: [MemoryEntry; 512],
    size: usize,
}

impl MemoryMap {
    fn register(&mut self, base: usize, size: usize, kind: BootloaderMemoryKind) {
        if self.size >= self.entries.len() {
            panic!("Early memory map overflow!");
        }
        let start = if kind == BootloaderMemoryKind::Free {
            align_up(base)
        } else {
            align_down(base)
        };
        let end = base.saturating_add(size);
        let end = if kind == BootloaderMemoryKind::Free {
            align_down(end)
        } else {
            align_up(end)
        };
        if start < end {
            self.entries[self.size] = MemoryEntry { start, end, kind };
            self.size += 1;
        }
    }

    fn iter(&self) -> Iter<MemoryEntry> {
        return self.entries[0..self.size].iter();
    }

    pub fn free(&self) -> impl Iterator<Item = &MemoryEntry> {
        self.iter().filter(|x| x.kind == BootloaderMemoryKind::Free)
    }

    pub fn non_free(&self) -> impl Iterator<Item = &MemoryEntry> {
        self.iter().filter(|x| x.kind != BootloaderMemoryKind::Free)
    }

    pub fn kernel(&self) -> Option<&MemoryEntry> {
        self.iter().find(|x| x.kind == BootloaderMemoryKind::Kernel)
    }

    pub fn devices(&self) -> impl Iterator<Item = &MemoryEntry> {
        self.iter()
            .filter(|x| x.kind == BootloaderMemoryKind::Device)
    }

    pub fn identity_mapped(&self) -> impl Iterator<Item = &MemoryEntry> {
        self.iter()
            .filter(|x| x.kind == BootloaderMemoryKind::IdentityMap)
    }
}

static mut MEMORY_MAP: MemoryMap = MemoryMap {
    entries: [MemoryEntry {
        start: 0,
        end: 0,
        kind: BootloaderMemoryKind::Null,
    }; 512],
    size: 0,
};

fn align_up(x: usize) -> usize {
    (x.saturating_add(PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE
}
fn align_down(x: usize) -> usize {
    x / PAGE_SIZE * PAGE_SIZE
}

pub fn register_memory_region(base: usize, size: usize, kind: BootloaderMemoryKind) {
    if kind != Null && size != 0 {
        log::debug!("Registering {:?} memory {:X} size {:X}", kind, base, size);
        unsafe { MEMORY_MAP.register(base, size, kind) }
    }
}

pub fn register_bootloader_areas(areas_base: usize, areas_size: usize) {
    let bootloader_areas = unsafe {
        slice::from_raw_parts(
            areas_base as *const BootloaderMemoryEntry,
            areas_size / mem::size_of::<BootloaderMemoryEntry>(),
        )
    };
    for bootloader_area in bootloader_areas.iter() {
        register_memory_region(
            bootloader_area.base as usize,
            bootloader_area.size as usize,
            bootloader_area.kind,
        )
    }
}

unsafe fn add_memory(areas: &mut [MemoryArea], area_i: &mut usize, mut area: MemoryEntry) {
    for reservation in MEMORY_MAP.non_free() {
        if area.end > reservation.start && area.end <= reservation.end {
            log::info!(
                "Memory {:X}:{:X} overlaps with reservation {:X}:{:X}",
                area.start,
                area.end,
                reservation.start,
                reservation.end
            );
            area.end = reservation.start;
        }
        if area.start >= area.end {
            return;
        }

        if area.start >= reservation.start && area.start < reservation.end {
            log::info!(
                "Memory {:X}:{:X} overlaps with reservation {:X}:{:X}",
                area.start,
                area.end,
                reservation.start,
                reservation.end
            );
            area.start = reservation.end;
        }
        if area.start >= area.end {
            return;
        }

        if area.start <= reservation.start && area.end > reservation.start {
            log::info!(
                "Memory {:X}:{:X} contains reservation {:X}:{:X}",
                area.start,
                area.end,
                reservation.start,
                reservation.end
            );
            debug_assert!(area.start < reservation.start && reservation.end < area.end,
                    "Should've contained reservation entirely: memory block {:X}:{:X} reservation {:X}:{:X}",
                    area.start, area.end,
                    reservation.start, reservation.end
            );
            // recurse on first part of split memory block

            add_memory(
                areas,
                area_i,
                MemoryEntry {
                    end: reservation.start,
                    ..area
                },
            );

            // and continue with the second part
            area.start = reservation.end;
        }
        debug_assert!(
            area.intersect(reservation).is_none(),
            "Intersects with reservation! memory block {:X}:{:X} reservation {:X}:{:X}",
            area.start,
            area.end,
            reservation.start,
            reservation.end
        );
        debug_assert!(
            area.start < area.end,
            "Empty memory block {:X}:{:X}",
            area.start,
            area.end
        );
    }

    // Combine overlapping memory areas
    let mut other_i = 0;
    while other_i < *area_i {
        let other = &areas[other_i];
        let other = MemoryEntry {
            start: other.base.data(),
            end: other.base.data().saturating_add(other.size),
            kind: BootloaderMemoryKind::Free,
        };
        if let Some(union) = area.combine(&other) {
            log::debug!(
                "{:X}:{:X} overlaps with area {:X}:{:X}, combining into {:X}:{:X}",
                area.start,
                area.end,
                other.start,
                other.end,
                union.start,
                union.end
            );
            area = union;
            *area_i -= 1; // delete the original memory chunk
            areas[other_i] = areas[*area_i];
        } else {
            other_i += 1;
        }
    }

    areas[*area_i].base = PhysicalAddress::new(area.start);
    areas[*area_i].size = area.end - area.start;
    *area_i += 1;
}

unsafe fn map_memory<A: Arch>(areas: &[MemoryArea], mut bump_allocator: &mut BumpAllocator<A>) {
    let mut mapper = PageMapper::<A, _>::create(TableKind::Kernel, &mut bump_allocator)
        .expect("failed to create Mapper");

    #[cfg(target_arch = "i686")]
    {
        // Pre-allocate all kernel PD entries so that when the page table is copied,
        // these entries are synced between processes
        for i in 512..1024 {
            let phys = mapper
                .allocator_mut()
                .allocate_one()
                .expect("failed to map page table");
            let flags = A::ENTRY_FLAG_READWRITE | A::ENTRY_FLAG_DEFAULT_TABLE;
            mapper
                .table()
                .set_entry(i, PageEntry::new(phys.data(), flags));
        }
    }

    // Map all physical areas at PHYS_OFFSET
    for area in areas.iter() {
        for i in 0..area.size / PAGE_SIZE {
            let phys = area.base.add(i * PAGE_SIZE);
            let virt = A::phys_to_virt(phys);
            let flags = page_flags::<A>(virt);
            let flush = mapper
                .map_phys(virt, phys, flags)
                .expect("failed to map frame");
            flush.ignore(); // Not the active table
        }
    }

    let kernel_area = MEMORY_MAP.kernel().unwrap();
    let kernel_base = kernel_area.start;
    let kernel_size = kernel_area.end - kernel_area.start;
    // Map kernel at KERNEL_OFFSET and identity map too
    for i in 0..kernel_size / A::PAGE_SIZE {
        let phys = PhysicalAddress::new(kernel_base + i * PAGE_SIZE);
        let virt = VirtualAddress::new(KERNEL_OFFSET + i * PAGE_SIZE);
        let flags = page_flags::<A>(virt);
        let flush = mapper
            .map_phys(virt, phys, flags)
            .expect("failed to map frame");
        flush.ignore(); // Not the active table

        let virt = A::phys_to_virt(phys);
        let flush = mapper
            .map_phys(virt, phys, flags)
            .expect("failed to map frame");
        flush.ignore(); // Not the active table
    }

    for area in MEMORY_MAP.identity_mapped() {
        let base = area.start;
        let size = area.end - area.start;
        for i in 0..size / PAGE_SIZE {
            let phys = PhysicalAddress::new(base + i * PAGE_SIZE);
            let virt = A::phys_to_virt(phys);
            let flags = page_flags::<A>(virt);
            let flush = mapper
                .map_phys(virt, phys, flags)
                .expect("failed to map frame");
            flush.ignore(); // Not the active table
        }
    }

    //map dev mem
    for area in MEMORY_MAP.devices() {
        let base = area.start;
        let size = area.end - area.start;
        for i in 0..size / PAGE_SIZE {
            let phys = PhysicalAddress::new(base + i * PAGE_SIZE);
            let virt = A::phys_to_virt(phys);
            // use the same mair_el1 value with bootloader,
            // mair_el1 == 0x00000000000044FF
            // set mem_attr == device memory
            let flags = page_flags::<A>(virt).custom_flag(EntryFlags::DEV_MEM.bits(), true);
            let flush = mapper
                .map_phys(virt, phys, flags)
                .expect("failed to map frame");
            flush.ignore(); // Not the active table
        }
    }

    // Ensure graphical debug region remains paged
    #[cfg(feature = "graphical_debug")]
    {
        use crate::devices::graphical_debug::FRAMEBUFFER;

        let (phys, virt, size) = *FRAMEBUFFER.lock();

        let pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
        for i in 0..pages {
            let phys = PhysicalAddress::new(phys + i * PAGE_SIZE);
            let virt = VirtualAddress::new(virt + i * PAGE_SIZE);
            let flags = PageFlags::new().write(true).write_combining(true);
            let flush = mapper
                .map_phys(virt, phys, flags)
                .expect("failed to map frame");
            flush.ignore(); // Not the active table
        }
    }

    log::debug!("Table: {:X}", mapper.table().phys().data());
    for i in 0..A::PAGE_ENTRIES {
        if let Some(entry) = mapper.table().entry(i) {
            if entry.present() {
                log::debug!("{}: {:X}", i, entry.data());
            }
        }
    }

    // Use the new table
    mapper.make_current();
}

pub unsafe fn init(low_limit: Option<usize>, high_limit: Option<usize>) {
    let physmem_limit = MemoryEntry {
        start: align_up(low_limit.unwrap_or(0)),
        end: align_down(high_limit.unwrap_or(usize::MAX)),
        kind: BootloaderMemoryKind::Free,
    };

    let areas = &mut *crate::memory::AREAS.get();
    let mut area_i = 0;

    // Copy initial memory map, and page align it
    for area in MEMORY_MAP.free() {
        log::debug!("{:X}:{:X}", area.start, area.end);

        if let Some(area) = area.intersect(&physmem_limit) {
            add_memory(areas, &mut area_i, area);
        }
    }

    areas[..area_i].sort_unstable_by_key(|area| area.base);
    crate::memory::AREA_COUNT.get().write(area_i as u16);

    // free memory map in now ready
    let areas = crate::memory::areas();

    // First, calculate how much memory we have
    let mut size = 0;
    for area in areas.iter() {
        if area.size > 0 {
            log::debug!("{:X?}", area);
            size += area.size;
        }
    }

    log::info!("Memory: {} MB", (size + (MEGABYTE - 1)) / MEGABYTE);

    // Create a basic allocator for the first pages
    let mut bump_allocator = BumpAllocator::<CurrentRmmArch>::new(areas, 0);

    map_memory(areas, &mut bump_allocator);

    // Create the physical memory map
    let offset = bump_allocator.offset();
    log::info!(
        "Permanently used: {} KB",
        (offset + (KILOBYTE - 1)) / KILOBYTE
    );

    crate::memory::init_mm(bump_allocator);
}
