use core::ptr;

use crate::{MemoryArea, PhysicalAddress, TableKind, VirtualAddress};

//TODO: Support having all page tables compile on all architectures
#[cfg(all(feature = "std", target_pointer_width = "64"))]
pub use self::emulate::EmulateArch;
#[cfg(target_pointer_width = "32")]
pub use self::x86::X86Arch;
#[cfg(target_pointer_width = "64")]
pub use self::{
    aarch64::AArch64Arch,
    riscv64::{RiscV64Sv39Arch, RiscV64Sv48Arch},
    x86_64::X8664Arch,
};

#[cfg(target_pointer_width = "64")]
mod aarch64;
#[cfg(all(feature = "std", target_pointer_width = "64"))]
mod emulate;
#[cfg(target_pointer_width = "64")]
mod riscv64;
#[cfg(target_pointer_width = "32")]
mod x86;
#[cfg(target_pointer_width = "64")]
mod x86_64;

pub trait Arch: Clone + Copy {
    const PAGE_SHIFT: usize;
    const PAGE_ENTRY_SHIFT: usize;
    const PAGE_LEVELS: usize;

    const ENTRY_ADDRESS_WIDTH: usize; // Number of bits of physical address in PTE
    const ENTRY_ADDRESS_SHIFT: usize = Self::PAGE_SHIFT; // Offset of physical address in PTE
    const ENTRY_FLAG_DEFAULT_PAGE: usize;
    const ENTRY_FLAG_DEFAULT_TABLE: usize;
    const ENTRY_FLAG_PRESENT: usize;
    const ENTRY_FLAG_READONLY: usize;
    const ENTRY_FLAG_READWRITE: usize;
    const ENTRY_FLAG_PAGE_USER: usize; // Leaf table user page flag
    const ENTRY_FLAG_TABLE_USER: usize = Self::ENTRY_FLAG_PAGE_USER; // Directory user page table flag
    const ENTRY_FLAG_NO_EXEC: usize;
    const ENTRY_FLAG_EXEC: usize;
    const ENTRY_FLAG_GLOBAL: usize;
    const ENTRY_FLAG_NO_GLOBAL: usize;
    const ENTRY_FLAG_WRITE_COMBINING: usize;

    const PHYS_OFFSET: usize;

    const PAGE_SIZE: usize = 1 << Self::PAGE_SHIFT;
    const PAGE_OFFSET_MASK: usize = Self::PAGE_SIZE - 1;
    const PAGE_ADDRESS_SHIFT: usize = Self::PAGE_LEVELS * Self::PAGE_ENTRY_SHIFT + Self::PAGE_SHIFT;
    const PAGE_ADDRESS_SIZE: u64 = 1 << (Self::PAGE_ADDRESS_SHIFT as u64);
    const PAGE_ADDRESS_MASK: usize = (Self::PAGE_ADDRESS_SIZE - (Self::PAGE_SIZE as u64)) as usize;
    const PAGE_ENTRY_SIZE: usize = 1 << (Self::PAGE_SHIFT - Self::PAGE_ENTRY_SHIFT);
    const PAGE_ENTRIES: usize = 1 << Self::PAGE_ENTRY_SHIFT;
    const PAGE_ENTRY_MASK: usize = Self::PAGE_ENTRIES - 1;
    const PAGE_NEGATIVE_MASK: usize = !(Self::PAGE_ADDRESS_SIZE - 1) as usize;

    const ENTRY_ADDRESS_SIZE: usize = 1 << Self::ENTRY_ADDRESS_WIDTH; // size of addressable physical memory, in pages
    const ENTRY_ADDRESS_MASK: usize = Self::ENTRY_ADDRESS_SIZE - 1; // Mask of physical address, starting at 0th bit
    const ENTRY_FLAGS_MASK: usize = !(Self::ENTRY_ADDRESS_MASK << Self::ENTRY_ADDRESS_SHIFT);

    unsafe fn init() -> &'static [MemoryArea];

    #[inline(always)]
    unsafe fn read<T>(address: VirtualAddress) -> T {
        unsafe { ptr::read(address.data() as *const T) }
    }

    #[inline(always)]
    unsafe fn write<T>(address: VirtualAddress, value: T) {
        unsafe { ptr::write(address.data() as *mut T, value) }
    }

    #[inline(always)]
    unsafe fn write_bytes(address: VirtualAddress, value: u8, count: usize) {
        unsafe { ptr::write_bytes(address.data() as *mut u8, value, count) }
    }

    unsafe fn invalidate(address: VirtualAddress);

    #[inline(always)]
    unsafe fn invalidate_all() {
        unsafe {
            //TODO: this stub only works on x86_64, maybe make the arch implement this?
            Self::set_table(TableKind::User, Self::table(TableKind::User));
        }
    }

    unsafe fn table(table_kind: TableKind) -> PhysicalAddress;

    unsafe fn set_table(table_kind: TableKind, address: PhysicalAddress);

    #[inline(always)]
    unsafe fn phys_to_virt(phys: PhysicalAddress) -> VirtualAddress {
        match phys.data().checked_add(Self::PHYS_OFFSET) {
            Some(some) => VirtualAddress::new(some),
            None => panic!("phys_to_virt({:#x}) overflow", phys.data()),
        }
    }

    fn virt_is_valid(address: VirtualAddress) -> bool;
}
