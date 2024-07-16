#![allow(unused)]

// Because the memory map is so important to not be aliased, it is defined here, in one place
// The lower 256 PML4 entries are reserved for userspace
// Each PML4 entry references up to 512 GB of memory
// The second from the top (510) PML4 is reserved for the kernel
/// The size of a single PML4
pub const PML4_SIZE: usize = 0x0000_0080_0000_0000;
pub const PML4_MASK: usize = 0x0000_ff80_0000_0000;

/// Offset of recursive paging (deprecated, but still reserved)
pub const RECURSIVE_PAGE_OFFSET: usize = (-(PML4_SIZE as isize)) as usize;
pub const RECURSIVE_PAGE_PML4: usize = (RECURSIVE_PAGE_OFFSET & PML4_MASK) / PML4_SIZE;

/// Offset of kernel
pub const KERNEL_OFFSET: usize = RECURSIVE_PAGE_OFFSET - PML4_SIZE;
pub const KERNEL_PML4: usize = (KERNEL_OFFSET & PML4_MASK) / PML4_SIZE;

/// Offset to kernel heap
pub const KERNEL_HEAP_OFFSET: usize = KERNEL_OFFSET - PML4_SIZE;
pub const KERNEL_HEAP_PML4: usize = (KERNEL_HEAP_OFFSET & PML4_MASK) / PML4_SIZE;
/// Size of kernel heap
pub const KERNEL_HEAP_SIZE: usize = 1 * 1024 * 1024; // 1 MB

/// Offset of temporary mapping for misc kernel bring-up actions
pub const KERNEL_TMP_MISC_OFFSET: usize = KERNEL_HEAP_OFFSET - PML4_SIZE;

/// Offset to kernel percpu variables
pub const KERNEL_PERCPU_OFFSET: usize = KERNEL_TMP_MISC_OFFSET - PML4_SIZE;
pub const KERNEL_PERCPU_PML4: usize = (KERNEL_PERCPU_OFFSET & PML4_MASK) / PML4_SIZE;
/// Size of kernel percpu variables
pub const KERNEL_PERCPU_SHIFT: u8 = 16; // 2^16 = 64 KiB
pub const KERNEL_PERCPU_SIZE: usize = 1_usize << KERNEL_PERCPU_SHIFT;

/// Offset of physmap
// This needs to match RMM's PHYS_OFFSET
pub const PHYS_OFFSET: usize = 0xFFFF_8000_0000_0000;
pub const PHYS_PML4: usize = (PHYS_OFFSET & PML4_MASK) / PML4_SIZE;

/// End offset of the user image, i.e. kernel start
pub const USER_END_OFFSET: usize = 256 * PML4_SIZE;
