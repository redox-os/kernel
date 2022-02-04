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
    env_base: usize, env_size_aligned: usize
) -> BuddyAllocator<A> {
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

        // Map stack with identity mapping
        for i in 0..stack_size_aligned / A::PAGE_SIZE {
            let phys = PhysicalAddress::new(stack_base + i * A::PAGE_SIZE);
            let virt = A::phys_to_virt(phys);
            let flags = page_flags::<A>(virt);
            let flush = mapper.map_phys(
                virt,
                phys,
                flags
            ).expect("failed to map frame");
            flush.ignore(); // Not the active table
        }

        // Map env with identity mapping
        for i in 0..env_size_aligned / A::PAGE_SIZE {
            let phys = PhysicalAddress::new(env_base + i * A::PAGE_SIZE);
            let virt = A::phys_to_virt(phys);
            let flags = page_flags::<A>(virt);
            let flush = mapper.map_phys(
                virt,
                phys,
                flags
            ).expect("failed to map frame");
            flush.ignore(); // Not the active table
        }

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
    env_base: usize, env_size: usize
) {
    type A = RmmA;

    let kernel_size_aligned = ((kernel_size + (A::PAGE_SIZE - 1))/A::PAGE_SIZE) * A::PAGE_SIZE;
    let kernel_end = kernel_base + kernel_size_aligned;
    println!("kernel_end: {:X}", kernel_end);

    let stack_size_aligned = ((stack_size + (A::PAGE_SIZE - 1))/A::PAGE_SIZE) * A::PAGE_SIZE;
    let stack_end = stack_base + stack_size_aligned;
    println!("stack_end: {:X}", stack_end);

    let env_size_aligned = ((env_size + (A::PAGE_SIZE - 1))/A::PAGE_SIZE) * A::PAGE_SIZE;
    let env_end = env_base + env_size_aligned;
    println!("env_end: {:X}", env_end);

    // Copy memory map from bootloader location, and page align it
    let mut area_i = 0;
    for i in 0..512 {
        let old = *(0x500 as *const crate::memory::MemoryArea).add(i);
        if old._type != 1 {
            // Not a free area
            continue;
        }

        let mut base = old.base_addr as usize;
        let mut size = old.length as usize;

        print!("{:X}:{:X}", base, size);

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
        println!(" => {:X}:{:X}", base, size);

        // Ensure kernel areas are not used
        if base < kernel_end && base + size > kernel_base {
            panic!("{:X}:{:X} overlaps with kernel {:X}:{:X}", base, size, kernel_base, kernel_size);
        }

        // Ensure stack areas are not used
        if base < stack_end && base + size > stack_base {
            panic!("{:X}:{:X} overlaps with stack {:X}:{:X}", base, size, stack_base, stack_size);
        }

        // Ensure env areas are not used
        if base < env_end && base + size > env_base {
            panic!("{:X}:{:X} overlaps with env {:X}:{:X}", base, size, env_base, env_size);
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
        env_base, env_size_aligned
    );
    *FRAME_ALLOCATOR.inner.lock() = Some(allocator);
}
