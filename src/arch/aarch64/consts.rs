// Because the memory map is so important to not be aliased, it is defined here, in one place
// The lower 256 PML4 entries are reserved for userspace
// Each PML4 entry references up to 512 GB of memory
// The second from the top (510) PML4 is reserved for the kernel
/// The size of a single PML4
pub const PML4_SIZE: usize = 0x0000_0080_0000_0000;

/// Offset of recursive paging (deprecated, but still reserved)
pub const RECURSIVE_PAGE_OFFSET: usize = (-(PML4_SIZE as isize)) as usize;

/// Offset of kernel
pub const KERNEL_OFFSET: usize = RECURSIVE_PAGE_OFFSET - PML4_SIZE;

/// Offset to kernel heap
pub const KERNEL_HEAP_OFFSET: usize = KERNEL_OFFSET - PML4_SIZE;
/// Size of kernel heap
pub const KERNEL_HEAP_SIZE: usize = 1 * 1024 * 1024; // 1 MB

/// Offset of physmap
// This needs to match RMM's PHYS_OFFSET
pub const PHYS_OFFSET: usize = 0xFFFF_8000_0000_0000;

/// End offset of the user image, i.e. kernel start
pub const USER_END_OFFSET: usize = 256 * PML4_SIZE;
