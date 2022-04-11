use core::{
    cmp,
    mem,
    slice,
};
use rmm::{
    KILOBYTE,
    MEGABYTE,
    Arch,
    BuddyAllocator,
    BumpAllocator,
    FrameAllocator,
    FrameCount,
    FrameUsage,
    MemoryArea,
    PageFlags,
    PageMapper,
    PhysicalAddress,
    VirtualAddress,
    X8664Arch as RmmA,
};

use spin::Mutex;

extern "C" {
    /// The starting byte of the text (code) data segment.
    static mut __text_start: u8;
    /// The ending byte of the text (code) data segment.
    static mut __text_end: u8;
    /// The starting byte of the _.rodata_ (read-only data) segment.
    static mut __rodata_start: u8;
    /// The ending byte of the _.rodata_ (read-only data) segment.
    static mut __rodata_end: u8;
}

// Keep synced with OsMemoryKind in bootloader
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum BootloaderMemoryKind {
    Null = 0,
    Free = 1,
    Reclaim = 2,
    Reserved = 3,
}

// Keep synced with OsMemoryEntry in bootloader
#[derive(Clone, Copy, Debug)]
#[repr(packed)]
pub struct BootloaderMemoryEntry {
    pub base: u64,
    pub size: u64,
    pub kind: BootloaderMemoryKind,
}

unsafe fn page_flags<A: Arch>(virt: VirtualAddress) -> PageFlags<A> {
    let virt_addr = virt.data();

    // Test for being inside a region
    macro_rules! in_section {
        ($n: ident) => {
            virt_addr >= &concat_idents!(__, $n, _start) as *const u8 as usize
                && virt_addr < &concat_idents!(__, $n, _end) as *const u8 as usize
        };
    }

    if in_section!(text) {
        // Remap text read-only, execute
        PageFlags::new().execute(true)
    } else if in_section!(rodata) {
        // Remap rodata read-only, no execute
        PageFlags::new()
    } else {
        // Remap everything else read-write, no execute
        PageFlags::new().write(true)
    }
}

unsafe fn inner<A: Arch>(
    areas: &'static [MemoryArea],
    kernel_base: usize, kernel_size_aligned: usize,
    stack_base: usize, stack_size_aligned: usize,
    env_base: usize, env_size_aligned: usize,
    acpi_base: usize, acpi_size_aligned: usize,
    initfs_base: usize, initfs_size_aligned: usize,
) -> BuddyAllocator<A> {
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
    let mut bump_allocator = BumpAllocator::<A>::new(areas, 0);

    {
        let mut mapper = PageMapper::<A, _>::create(
            &mut bump_allocator
        ).expect("failed to create Mapper");

        // Map all physical areas at PHYS_OFFSET
        for area in areas.iter() {
            for i in 0..area.size / A::PAGE_SIZE {
                let phys = area.base.add(i * A::PAGE_SIZE);
                let virt = A::phys_to_virt(phys);
                let flags = page_flags::<A>(virt);
                let flush = mapper.map_phys(
                    virt,
                    phys,
                    flags
                ).expect("failed to map frame");
                flush.ignore(); // Not the active table
            }
        }

        // Map kernel at KERNEL_OFFSET and identity map too
        for i in 0..kernel_size_aligned / A::PAGE_SIZE {
            let phys = PhysicalAddress::new(kernel_base + i * A::PAGE_SIZE);
            let virt = VirtualAddress::new(crate::KERNEL_OFFSET + i * A::PAGE_SIZE);
            let flags = page_flags::<A>(virt);
            let flush = mapper.map_phys(
                virt,
                phys,
                flags
            ).expect("failed to map frame");
            flush.ignore(); // Not the active table

            let virt = A::phys_to_virt(phys);
            let flush = mapper.map_phys(
                virt,
                phys,
                flags
            ).expect("failed to map frame");
            flush.ignore(); // Not the active table
        }

        let mut identity_map = |base, size_aligned| {
            // Map stack with identity mapping
            for i in 0..size / A::PAGE_SIZE {
                let phys = PhysicalAddress::new(base + i * A::PAGE_SIZE);
                let virt = A::phys_to_virt(phys);
                let flags = page_flags::<A>(virt);
                let flush = mapper.map_phys(
                    virt,
                    phys,
                    flags
                ).expect("failed to map frame");
                flush.ignore(); // Not the active table
            }
        };


        identity_map(stack_base, stack_size_aligned);
        identity_map(env_base, env_size_aligned);
        identity_map(acpi_base, acpi_size_aligned);
        identity_map(initfs_base, initfs_size_aligned);

        // Ensure graphical debug region remains paged
        #[cfg(feature = "graphical_debug")]
        {
            use super::graphical_debug::DEBUG_DISPLAY;
            use super::paging::entry::EntryFlags;

            let (base, size) = if let Some(debug_display) = &*DEBUG_DISPLAY.lock() {
                let data = &debug_display.display.onscreen;
                (
                    data.as_ptr() as usize - crate::PHYS_OFFSET,
                    data.len() * 4
                )
            } else {
                (0, 0)
            };

            let pages = (size + A::PAGE_SIZE - 1) / A::PAGE_SIZE;
            for i in 0..pages {
                let phys = PhysicalAddress::new(base + i * A::PAGE_SIZE);
                let virt = A::phys_to_virt(phys);
                let flags = PageFlags::new().write(true)
                    .custom_flag(EntryFlags::HUGE_PAGE.bits(), true);
                let flush = mapper.map_phys(
                    virt,
                    phys,
                    flags
                ).expect("failed to map frame");
                flush.ignore(); // Not the active table
            }
        }

        log::debug!("Table: {:X}", mapper.table().phys().data());
        for i in 0..512 {
            if let Some(entry) = mapper.table().entry(i) {
                if entry.present() {
                    log::debug!("{}: {:X}", i, entry.data());
                }
            }
        }

        // Use the new table
        mapper.make_current();
    }

    // Create the physical memory map
    let offset = bump_allocator.offset();
    log::info!("Permanently used: {} KB", (offset + (KILOBYTE - 1)) / KILOBYTE);

    BuddyAllocator::<A>::new(bump_allocator).expect("failed to create BuddyAllocator")
}

pub struct LockedAllocator {
    inner: Mutex<Option<BuddyAllocator<RmmA>>>,
}

impl LockedAllocator {
    const fn new() -> Self {
        Self {
            inner: Mutex::new(None)
        }
    }
}

impl FrameAllocator for LockedAllocator {
    unsafe fn allocate(&mut self, count: FrameCount) -> Option<PhysicalAddress> {
        if let Some(ref mut allocator) = *self.inner.lock() {
            allocator.allocate(count)
        } else {
            None
        }
    }

    unsafe fn free(&mut self, address: PhysicalAddress, count: FrameCount) {
        if let Some(ref mut allocator) = *self.inner.lock() {
            allocator.free(address, count)
        }
    }

    unsafe fn usage(&self) -> FrameUsage {
        if let Some(ref allocator) = *self.inner.lock() {
            allocator.usage()
        } else {
            FrameUsage::new(FrameCount::new(0), FrameCount::new(0))
        }
    }
}

static mut AREAS: [MemoryArea; 512] = [MemoryArea {
    base: PhysicalAddress::new(0),
    size: 0,
}; 512];

pub static mut FRAME_ALLOCATOR: LockedAllocator = LockedAllocator::new();

pub unsafe fn mapper_new(table_addr: PhysicalAddress) -> PageMapper<'static, RmmA, LockedAllocator> {
    PageMapper::new(table_addr, &mut FRAME_ALLOCATOR)
}

//TODO: global paging lock?
pub unsafe fn mapper_create() -> Option<PageMapper<'static, RmmA, LockedAllocator>> {
    PageMapper::create(&mut FRAME_ALLOCATOR)
}

pub unsafe fn mapper_current() -> PageMapper<'static, RmmA, LockedAllocator> {
    PageMapper::current(&mut FRAME_ALLOCATOR)
}

pub unsafe fn init(
    kernel_base: usize, kernel_size: usize,
    stack_base: usize, stack_size: usize,
    env_base: usize, env_size: usize,
    acpi_base: usize, acpi_size: usize,
    areas_base: usize, areas_size: usize,
    initfs_base: usize, initfs_size: usize,
) {
    type A = RmmA;

    let real_base = 0;
    let real_size = 0x100000;
    let real_end = real_base + real_size;

    let kernel_size_aligned = ((kernel_size + (A::PAGE_SIZE - 1))/A::PAGE_SIZE) * A::PAGE_SIZE;
    let kernel_end = kernel_base + kernel_size_aligned;

    let stack_size_aligned = ((stack_size + (A::PAGE_SIZE - 1))/A::PAGE_SIZE) * A::PAGE_SIZE;
    let stack_end = stack_base + stack_size_aligned;

    let env_size_aligned = ((env_size + (A::PAGE_SIZE - 1))/A::PAGE_SIZE) * A::PAGE_SIZE;
    let env_end = env_base + env_size_aligned;

    let acpi_size_aligned = ((acpi_size + (A::PAGE_SIZE - 1))/A::PAGE_SIZE) * A::PAGE_SIZE;
    let acpi_end = acpi_base + acpi_size_aligned;

    let initfs_size_aligned = ((initfs_size + (A::PAGE_SIZE - 1))/A::PAGE_SIZE) * A::PAGE_SIZE;
    let initfs_end = initfs_base + initfs_size_aligned;

    let bootloader_areas = slice::from_raw_parts(
        areas_base as *const BootloaderMemoryEntry,
        areas_size / mem::size_of::<BootloaderMemoryEntry>()
    );

    // Copy memory map from bootloader location, and page align it
    let mut area_i = 0;
    for bootloader_area in bootloader_areas.iter() {
        if bootloader_area.kind != BootloaderMemoryKind::Free {
            // Not a free area
            continue;
        }

        let mut base = bootloader_area.base as usize;
        let mut size = bootloader_area.size as usize;

        log::debug!("{:X}:{:X}", base, size);

        // Page align base
        let base_offset = (A::PAGE_SIZE - (base & A::PAGE_OFFSET_MASK)) & A::PAGE_OFFSET_MASK;
        if base_offset > size {
            // Area is too small to page align base
            continue;
        }
        base += base_offset;
        size -= base_offset;

        // Page align size
        size &= !A::PAGE_OFFSET_MASK;
        log::debug!(" => {:X}:{:X}", base, size);

        let mut new_base = base;

        // Ensure real-mode areas are not used
        if base < real_end && base + size > real_base {
            log::warn!("{:X}:{:X} overlaps with real mode {:X}:{:X}", base, size, real_base, real_size);
            new_base = cmp::max(new_base, real_end);
        }

        // Ensure kernel areas are not used
        if base < kernel_end && base + size > kernel_base {
            log::warn!("{:X}:{:X} overlaps with kernel {:X}:{:X}", base, size, kernel_base, kernel_size);
            new_base = cmp::max(new_base, kernel_end);
        }

        // Ensure stack areas are not used
        if base < stack_end && base + size > stack_base {
            log::warn!("{:X}:{:X} overlaps with stack {:X}:{:X}", base, size, stack_base, stack_size);
            new_base = cmp::max(new_base, stack_end);
        }

        // Ensure env areas are not used
        if base < env_end && base + size > env_base {
            log::warn!("{:X}:{:X} overlaps with env {:X}:{:X}", base, size, env_base, env_size);
            new_base = cmp::max(new_base, env_end);
        }

        // Ensure acpi areas are not used
        if base < acpi_end && base + size > acpi_base {
            log::warn!("{:X}:{:X} overlaps with acpi {:X}:{:X}", base, size, acpi_base, acpi_size);
            new_base = cmp::max(new_base, acpi_end);
        }
        if base < initfs_end && base + size > initfs_base {
            log::warn!("{:X}:{:X} overlaps with initfs {:X}:{:X}", base, size, initfs_base, initfs_size);
            new_base = cmp::max(new_base, initfs_end);
        }

        if new_base != base {
            let end = base + size;
            let new_size = end.checked_sub(new_base).unwrap_or(0);
            log::info!("{:X}:{:X} moved to {:X}:{:X}", base, size, new_base, new_size);
            base = new_base;
            size = new_size;
        }

        if size == 0 {
            // Area is zero sized
            continue;
        }

        AREAS[area_i].base = PhysicalAddress::new(base);
        AREAS[area_i].size = size;
        area_i += 1;
    }

    let allocator = inner::<A>(
        &AREAS,
        kernel_base, kernel_size_aligned,
        stack_base, stack_size_aligned,
        env_base, env_size_aligned,
        acpi_base, acpi_size_aligned,
        initfs_base, initfs_size_aligned,
    );
    *FRAME_ALLOCATOR.inner.lock() = Some(allocator);
}
