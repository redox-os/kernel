// Because the memory map is so important to not be aliased, it is defined here, in one place.
//
// - The lower half (256 PML4 entries; 128 TiB) is reserved for userspace. These mappings are
//   associated with _address spaces_, and change when context switching, unless the address spaces
//   match.
// - The upper half is reserved for the kernel. Kernel mappings are preserved across context
//   switches.
//
// Each PML4 entry references 512 GiB of virtual memory.

/// The size of a single PML4
pub const PML4_SIZE: usize = 0x0000_0080_0000_0000;

/// Offset of kernel
const KERNEL_OFFSET: usize = (1_usize << 31).wrapping_neg();

/// Offset to kernel heap
#[inline(always)]
pub fn kernel_heap_offset() -> usize {
    crate::kernel_executable_offsets::KERNEL_OFFSET() - PML4_SIZE
}

/// End offset of the user image, i.e. kernel start
// TODO: Make this offset at least PAGE_SIZE less? There are known hardware bugs on some arches,
// for example on x86 if instructions execute near the 48-bit canonical address boundary.
pub const USER_END_OFFSET: usize = 256 * PML4_SIZE;
