// Because the memory map is so important to not be aliased, it is defined here, in one place
// The lower 256 PML4 entries are reserved for userspace
// Each PML4 entry references up to 512 GB of memory
// The second from the top (510) PML4 is reserved for the kernel
/// The size of a single PML4
pub const PML4_SIZE: usize = 0x0000_0080_0000_0000;

/// Offset to kernel heap
#[inline(always)]
pub fn kernel_heap_offset() -> usize {
    crate::kernel_executable_offsets::KERNEL_OFFSET() - PML4_SIZE
}

/// End offset of the user image, i.e. kernel start
pub const USER_END_OFFSET: usize = 256 * PML4_SIZE;
