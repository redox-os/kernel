use super::CurrentRmmArch;
use rmm::Arch;

const PML4_SHIFT: usize = (CurrentRmmArch::PAGE_LEVELS - 1) * CurrentRmmArch::PAGE_ENTRY_SHIFT
    + CurrentRmmArch::PAGE_SHIFT;
/// The size of a single PML4
pub const PML4_SIZE: usize = 1_usize << PML4_SHIFT;

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
pub const PHYS_OFFSET: usize = (-1_isize << (CurrentRmmArch::PAGE_ADDRESS_SHIFT - 1)) as usize;

/// End offset of the user image, i.e. kernel start
pub const USER_END_OFFSET: usize = 1_usize << (CurrentRmmArch::PAGE_ADDRESS_SHIFT - 1);
