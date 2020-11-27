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
    PageMapper,
    PhysicalAddress,
    VirtualAddress,
    X8664Arch,
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

unsafe fn page_flags<A: Arch>(virt: VirtualAddress) -> usize {
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
        0
    } else if in_section!(rodata) {
        // Remap rodata read-only, no execute
        A::ENTRY_FLAG_NO_EXEC
    } else {
        // Remap everything else writable, no execute
        A::ENTRY_FLAG_WRITABLE | A::ENTRY_FLAG_NO_EXEC
    }
}

unsafe fn inner<A: Arch>(areas: &'static [MemoryArea], bump_offset: usize) -> BuddyAllocator<A> {
    // First, calculate how much memory we have
    let mut size = 0;
    for area in areas.iter() {
        if area.size > 0 {
            println!("{:X?}", area);
            size += area.size;
        }
    }

    println!("Memory: {} MB", (size + (MEGABYTE - 1)) / MEGABYTE);

    // Create a basic allocator for the first pages
    let mut bump_allocator = BumpAllocator::<A>::new(areas, bump_offset);

    //TODO: memory protection
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

        //TODO: remove backwards compatible recursive mapping
        mapper.table().set_entry(511, rmm::PageEntry::new(
            mapper.table().phys().data() | A::ENTRY_FLAG_WRITABLE | A::ENTRY_FLAG_PRESENT | A::ENTRY_FLAG_NO_EXEC
        ));

        println!("Table: {:X}", mapper.table().phys().data());
        for i in 0..512 {
            if let Some(entry) = mapper.table().entry(i) {
                if entry.present() {
                    println!("{}: {:X}", i, entry.data());
                }
            }
        }

        // Use the new table
        mapper.make_current();
    }

    // Create the physical memory map
    let offset = bump_allocator.offset();
    println!("Permanently used: {} KB", (offset + (KILOBYTE - 1)) / KILOBYTE);

    BuddyAllocator::<A>::new(bump_allocator).expect("failed to create BuddyAllocator")
}

pub struct LockedAllocator {
    inner: Mutex<Option<BuddyAllocator<X8664Arch>>>,
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

pub unsafe fn mapper_new(table_addr: PhysicalAddress) -> PageMapper<'static, X8664Arch, LockedAllocator> {
    PageMapper::new(table_addr, &mut FRAME_ALLOCATOR)
}

//TODO: global paging lock?
pub unsafe fn mapper_create() -> Option<PageMapper<'static, X8664Arch, LockedAllocator>> {
    PageMapper::create(&mut FRAME_ALLOCATOR)
}

pub unsafe fn mapper_current() -> PageMapper<'static, X8664Arch, LockedAllocator> {
    PageMapper::current(&mut FRAME_ALLOCATOR)
}

pub unsafe fn init(kernel_end: usize) {
    type A = X8664Arch;

    println!("kernel_end: {:X}", kernel_end);

    // Copy memory map from bootloader location, and page align it
    let mut area_i = 0;
    let mut bump_offset = 0;
    for i in 0..512 {
        let old = *(0x500 as *const crate::memory::MemoryArea).add(i);
        if old._type != 1 {
            // Not a free area
            continue;
        }

        let mut base = old.base_addr as usize;
        let mut size = old.length as usize;

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
        if size == 0 {
            // Area is zero sized
            continue;
        }

        if base + size < kernel_end {
            // Area is below static kernel data
            bump_offset += size;
        } else if base < kernel_end {
            // Area contains static kernel data
            bump_offset += kernel_end - base;
        }

        AREAS[area_i].base = PhysicalAddress::new(base);
        AREAS[area_i].size = size;
        area_i += 1;
    }

    println!("bump_offset: {:X}", bump_offset);

    let allocator = inner::<A>(&AREAS, bump_offset);
    *FRAME_ALLOCATOR.inner.lock() = Some(allocator);
}
