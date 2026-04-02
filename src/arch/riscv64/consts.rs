use super::CurrentRmmArch;
use rmm::Arch;

const PML4_SHIFT: usize = (CurrentRmmArch::PAGE_LEVELS - 1) * CurrentRmmArch::PAGE_ENTRY_SHIFT
    + CurrentRmmArch::PAGE_SHIFT;
/// The size of a single PML4
pub const PML4_SIZE: usize = 1_usize << PML4_SHIFT;

/// Offset of kernel
pub const KERNEL_OFFSET: usize = (2 * PML4_SIZE).wrapping_neg();

/// Offset to kernel heap
pub const KERNEL_HEAP_OFFSET: usize = KERNEL_OFFSET - PML4_SIZE;

/// End offset of the user image, i.e. kernel start
pub const USER_END_OFFSET: usize = 1_usize << (CurrentRmmArch::PAGE_ADDRESS_SHIFT - 1);
