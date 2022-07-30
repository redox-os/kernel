// Because the memory map is so important to not be aliased, it is defined here, in one place
// The lower 256 PML4 entries are reserved for userspace
// Each PML4 entry references up to 512 GB of memory
// The second from the top (510) PML4 is reserved for the kernel

    /// Offset of kernel
    pub const KERNEL_OFFSET: usize = 0xC000_0000;

    /// Offset to kernel heap
    pub const KERNEL_HEAP_OFFSET: usize = 0xE000_0000;
    /// Size of kernel heap
    pub const KERNEL_HEAP_SIZE: usize = rmm::MEGABYTE;

    /// Offset to kernel percpu variables
    pub const KERNEL_PERCPU_OFFSET: usize = 0xF000_0000;
    /// Size of kernel percpu variables
    pub const KERNEL_PERCPU_SHIFT: u8 = 16; // 2^16 = 64 KiB
    pub const KERNEL_PERCPU_SIZE: usize = 1_usize << KERNEL_PERCPU_SHIFT;

    /// Offset of physmap
    // This needs to match RMM's PHYS_OFFSET
    pub const PHYS_OFFSET: usize = 0x8000_0000;

    /// Offset to user image
    pub const USER_OFFSET: usize = 0;

    /// End offset of the user image, i.e. kernel start
    pub const USER_END_OFFSET: usize = 0x8000_0000;
