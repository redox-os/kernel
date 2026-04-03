use super::CurrentRmmArch;
use rmm::Arch;

const PML4_SHIFT: usize = (CurrentRmmArch::PAGE_LEVELS - 1) * CurrentRmmArch::PAGE_ENTRY_SHIFT
    + CurrentRmmArch::PAGE_SHIFT;
/// The size of a single PML4
pub const PML4_SIZE: usize = 1_usize << PML4_SHIFT;

/// Offset to kernel heap
#[inline(always)]
pub fn kernel_heap_offset() -> usize {
    crate::kernel_executable_offsets::KERNEL_OFFSET() - PML4_SIZE
}

/// End offset of the user image, i.e. kernel start
pub const USER_END_OFFSET: usize = 1_usize << (CurrentRmmArch::PAGE_ADDRESS_SHIFT - 1);
