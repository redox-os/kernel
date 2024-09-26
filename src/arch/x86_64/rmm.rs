use core::{cell::SyncUnsafeCell, cmp, mem, slice};
use rmm::{
    Arch, BumpAllocator, MemoryArea, PageFlags, PageMapper, PhysicalAddress, TableKind,
    VirtualAddress, KILOBYTE, MEGABYTE,
};

use super::CurrentRmmArch as RmmA;

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
#[repr(C, packed)]
pub struct BootloaderMemoryEntry {
    pub base: u64,
    pub size: u64,
    pub kind: BootloaderMemoryKind,
}

unsafe fn page_flags<A: Arch>(virt: VirtualAddress) -> PageFlags<A> {
    use crate::kernel_executable_offsets::*;
    let virt_addr = virt.data();

    (if virt_addr >= __text_start() && virt_addr < __text_end() {
        // Remap text read-only, execute
        PageFlags::new().execute(true)
    } else if virt_addr >= __rodata_start() && virt_addr < __rodata_end() {
        // Remap rodata read-only, no execute
        PageFlags::new()
    } else {
        // Remap everything else read-write, no execute
        PageFlags::new().write(true)
    })
    .global(cfg!(not(feature = "pti")))
}

unsafe fn inner(
    areas: &'static [MemoryArea],
    kernel_base: usize,
    kernel_size_aligned: usize,
    stack_base: usize,
    stack_size_aligned: usize,
    env_base: usize,
    env_size_aligned: usize,
    acpi_base: usize,
    acpi_size_aligned: usize,
    initfs_base: usize,
    initfs_size_aligned: usize,
) {
    type A = RmmA;

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
        let mut mapper = PageMapper::<A, _>::create(TableKind::Kernel, &mut bump_allocator)
            .expect("failed to create Mapper");

        // Map all physical areas at PHYS_OFFSET
        for area in areas.iter() {
            for i in 0..area.size / A::PAGE_SIZE {
                let phys = area.base.add(i * A::PAGE_SIZE);
                let virt = A::phys_to_virt(phys);
                let flags = page_flags::<A>(virt);
                let flush = mapper
                    .map_phys(virt, phys, flags)
                    .expect("failed to map frame");
                flush.ignore(); // Not the active table
            }
        }

        // Map kernel at KERNEL_OFFSET and map linearly too
        for i in 0..kernel_size_aligned / A::PAGE_SIZE {
            let phys = PhysicalAddress::new(kernel_base + i * A::PAGE_SIZE);
            let virt = VirtualAddress::new(crate::KERNEL_OFFSET + i * A::PAGE_SIZE);
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

        let mut identity_map = |base, size_aligned| {
            // Map with identity mapping
            for i in 0..size_aligned / A::PAGE_SIZE {
                let phys = PhysicalAddress::new(base + i * A::PAGE_SIZE);
                let virt = A::phys_to_virt(phys);
                let flags = page_flags::<A>(virt);
                let flush = mapper
                    .map_phys(virt, phys, flags)
                    .expect("failed to map frame");
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
            use super::paging::entry::EntryFlags;
            use crate::devices::graphical_debug::FRAMEBUFFER;

            let (phys, virt, size) = *FRAMEBUFFER.lock();

            let pages = (size + A::PAGE_SIZE - 1) / A::PAGE_SIZE;
            for i in 0..pages {
                let phys = PhysicalAddress::new(phys + i * A::PAGE_SIZE);
                let virt = VirtualAddress::new(virt + i * A::PAGE_SIZE);
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

    // Create the physical memory map
    let offset = bump_allocator.offset();
    log::info!(
        "Permanently used: {} KB",
        (offset + (KILOBYTE - 1)) / KILOBYTE
    );

    crate::memory::init_mm(bump_allocator);
}

static AREAS: SyncUnsafeCell<[MemoryArea; 512]> = SyncUnsafeCell::new(
    [MemoryArea {
        base: PhysicalAddress::new(0),
        size: 0,
    }; 512],
);
static AREA_COUNT: SyncUnsafeCell<u16> = SyncUnsafeCell::new(0);

pub fn areas() -> &'static [MemoryArea] {
    // SAFETY: Both AREAS and AREA_COUNT are initialized once and then never changed.
    //
    // TODO: Memory hotplug?
    unsafe { &(&*AREAS.get())[..AREA_COUNT.get().read().into()] }
}

pub unsafe fn init(
    kernel_base: usize,
    kernel_size: usize,
    stack_base: usize,
    stack_size: usize,
    env_base: usize,
    env_size: usize,
    acpi_base: usize,
    acpi_size: usize,
    areas_base: usize,
    areas_size: usize,
    initfs_base: usize,
    initfs_size: usize,
) {
    type A = RmmA;

    let real_base = 0;
    let real_size = 0x100000;
    let real_end = real_base + real_size;

    let kernel_size_aligned = kernel_size.next_multiple_of(A::PAGE_SIZE);
    let kernel_end = kernel_base + kernel_size_aligned;

    let stack_size_aligned = stack_size.next_multiple_of(A::PAGE_SIZE);
    let stack_end = stack_base + stack_size_aligned;

    let env_size_aligned = env_size.next_multiple_of(A::PAGE_SIZE);
    let env_end = env_base + env_size_aligned;

    let acpi_size_aligned = acpi_size.next_multiple_of(A::PAGE_SIZE);
    let acpi_end = acpi_base + acpi_size_aligned;

    let initfs_size_aligned = initfs_size.next_multiple_of(A::PAGE_SIZE);
    let initfs_end = initfs_base + initfs_size_aligned;

    let bootloader_areas = slice::from_raw_parts(
        areas_base as *const BootloaderMemoryEntry,
        areas_size / mem::size_of::<BootloaderMemoryEntry>(),
    );

    // Copy memory map from bootloader location, and page align it
    let mut area_i = 0;
    let areas_raw = &mut *AREAS.get();

    for bootloader_area in bootloader_areas.iter() {
        if { bootloader_area.kind } != BootloaderMemoryKind::Free {
            // Not a free area
            continue;
        }

        let mut base = bootloader_area.base as usize;
        let mut size = bootloader_area.size as usize;

        log::info!("{:X}:{:X}", base, size);

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
            log::warn!(
                "{:X}:{:X} overlaps with real mode {:X}:{:X}",
                base,
                size,
                real_base,
                real_size
            );
            new_base = cmp::max(new_base, real_end);
        }

        // Ensure kernel areas are not used
        if base < kernel_end && base + size > kernel_base {
            log::warn!(
                "{:X}:{:X} overlaps with kernel {:X}:{:X}",
                base,
                size,
                kernel_base,
                kernel_size
            );
            new_base = cmp::max(new_base, kernel_end);
        }

        // Ensure stack areas are not used
        if base < stack_end && base + size > stack_base {
            log::warn!(
                "{:X}:{:X} overlaps with stack {:X}:{:X}",
                base,
                size,
                stack_base,
                stack_size
            );
            new_base = cmp::max(new_base, stack_end);
        }

        // Ensure env areas are not used
        if base < env_end && base + size > env_base {
            log::warn!(
                "{:X}:{:X} overlaps with env {:X}:{:X}",
                base,
                size,
                env_base,
                env_size
            );
            new_base = cmp::max(new_base, env_end);
        }

        // Ensure acpi areas are not used
        if base < acpi_end && base + size > acpi_base {
            log::warn!(
                "{:X}:{:X} overlaps with acpi {:X}:{:X}",
                base,
                size,
                acpi_base,
                acpi_size
            );
            new_base = cmp::max(new_base, acpi_end);
        }

        // Ensure initfs areas are not used
        if base < initfs_end && base + size > initfs_base {
            log::warn!(
                "{:X}:{:X} overlaps with initfs {:X}:{:X}",
                base,
                size,
                initfs_base,
                initfs_size
            );
            new_base = cmp::max(new_base, initfs_end);
        }

        if new_base != base {
            let end = base + size;
            let new_size = end.checked_sub(new_base).unwrap_or(0);
            log::info!(
                "{:X}:{:X} moved to {:X}:{:X}",
                base,
                size,
                new_base,
                new_size
            );
            base = new_base;
            size = new_size;
        }

        if size == 0 {
            // Area is zero sized, skip
            continue;
        }

        areas_raw[area_i].base = PhysicalAddress::new(base);
        areas_raw[area_i].size = size;
        area_i += 1;
    }
    for i in area_i..areas_raw.len() {
        areas_raw[i] = MemoryArea {
            base: PhysicalAddress::new(!0),
            size: 0,
        };
    }

    areas_raw.sort_unstable_by_key(|area| area.base);

    AREA_COUNT.get().write(area_i as u16);

    inner(
        areas(),
        kernel_base,
        kernel_size_aligned,
        stack_base,
        stack_size_aligned,
        env_base,
        env_size_aligned,
        acpi_base,
        acpi_size_aligned,
        initfs_base,
        initfs_size_aligned,
    );
}
