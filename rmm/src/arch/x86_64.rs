use core::arch::asm;

use crate::{Arch, MemoryArea, PhysicalAddress, TableKind, VirtualAddress};

#[derive(Clone, Copy, Debug)]
pub struct X8664Arch;

impl Arch for X8664Arch {
    const PAGE_SHIFT: usize = 12; // 4096 bytes
    const PAGE_ENTRY_SHIFT: usize = 9; // 512 entries, 8 bytes each
    const PAGE_LEVELS: usize = 4; // PML4, PDP, PD, PT

    const ENTRY_ADDRESS_WIDTH: usize = 40;
    const ENTRY_FLAG_DEFAULT_PAGE: usize = Self::ENTRY_FLAG_PRESENT;
    const ENTRY_FLAG_DEFAULT_TABLE: usize = Self::ENTRY_FLAG_PRESENT | Self::ENTRY_FLAG_READWRITE;
    const ENTRY_FLAG_PRESENT: usize = 1 << 0;
    const ENTRY_FLAG_READONLY: usize = 0;
    const ENTRY_FLAG_READWRITE: usize = 1 << 1;
    const ENTRY_FLAG_PAGE_USER: usize = 1 << 2;
    // Not used: const ENTRY_FLAG_HUGE: usize = 1 << 7;
    const ENTRY_FLAG_GLOBAL: usize = 1 << 8;
    const ENTRY_FLAG_NO_GLOBAL: usize = 0;
    const ENTRY_FLAG_NO_EXEC: usize = 1 << 63;
    const ENTRY_FLAG_EXEC: usize = 0;
    const ENTRY_FLAG_WRITE_COMBINING: usize = 1 << 7;

    const PHYS_OFFSET: usize = Self::PAGE_NEGATIVE_MASK + (Self::PAGE_ADDRESS_SIZE >> 1) as usize; // PML4 slot 256 and onwards

    unsafe fn init() -> &'static [MemoryArea] {
        unimplemented!("X8664Arch::init unimplemented");
    }

    #[inline(always)]
    unsafe fn invalidate(address: VirtualAddress) {
        unsafe {
            asm!("invlpg [{0}]", in(reg) address.data());
        }
    }

    #[inline(always)]
    unsafe fn table(_table_kind: TableKind) -> PhysicalAddress {
        unsafe {
            let address: usize;
            asm!("mov {0}, cr3", out(reg) address);
            PhysicalAddress::new(address)
        }
    }

    #[inline(always)]
    unsafe fn set_table(_table_kind: TableKind, address: PhysicalAddress) {
        unsafe {
            asm!("mov cr3, {0}", in(reg) address.data());
        }
    }

    fn virt_is_valid(address: VirtualAddress) -> bool {
        // On x86_64, an address is valid if and only if it is canonical. It may still point to
        // unmapped memory, but will always be valid once translated via the page table has
        // suceeded.
        let masked = address.data() & 0xFFFF_8000_0000_0000;
        // TODO: 5-level paging
        masked == 0xFFFF_8000_0000_0000 || masked == 0
    }
}

#[cfg(test)]
mod tests {
    use super::{VirtualAddress, X8664Arch};
    use crate::Arch;

    #[test]
    fn constants() {
        assert_eq!(X8664Arch::PAGE_SIZE, 4096);
        assert_eq!(X8664Arch::PAGE_OFFSET_MASK, 0xFFF);
        assert_eq!(X8664Arch::PAGE_ADDRESS_SHIFT, 48);
        assert_eq!(X8664Arch::PAGE_ADDRESS_SIZE, 0x0001_0000_0000_0000);
        assert_eq!(X8664Arch::PAGE_ADDRESS_MASK, 0x0000_FFFF_FFFF_F000);
        assert_eq!(X8664Arch::PAGE_ENTRY_SIZE, 8);
        assert_eq!(X8664Arch::PAGE_ENTRIES, 512);
        assert_eq!(X8664Arch::PAGE_ENTRY_MASK, 0x1FF);
        assert_eq!(X8664Arch::PAGE_NEGATIVE_MASK, 0xFFFF_0000_0000_0000);

        assert_eq!(X8664Arch::ENTRY_ADDRESS_SIZE, 0x0000_0100_0000_0000);
        assert_eq!(X8664Arch::ENTRY_ADDRESS_MASK, 0x0000_00FF_FFFF_FFFF);
        assert_eq!(X8664Arch::ENTRY_FLAGS_MASK, 0xFFF0_0000_0000_0FFF);

        assert_eq!(X8664Arch::PHYS_OFFSET, 0xFFFF_8000_0000_0000);
    }
    #[test]
    fn is_canonical() {
        fn yes(address: usize) {
            assert!(X8664Arch::virt_is_valid(VirtualAddress::new(address)));
        }
        fn no(address: usize) {
            assert!(!X8664Arch::virt_is_valid(VirtualAddress::new(address)));
        }

        yes(0xFFFF_8000_1337_1337);
        yes(0xFFFF_FFFF_FFFF_FFFF);
        yes(0x0000_0000_0000_0042);
        yes(0x0000_7FFF_FFFF_FFFF);
        no(0x1337_0000_0000_0000);
        no(0x1337_8000_0000_0000);
        no(0x0000_8000_0000_0000);
    }
}
