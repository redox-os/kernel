use core::arch::asm;

use crate::{Arch, MemoryArea, PhysicalAddress, TableKind, VirtualAddress};

#[derive(Clone, Copy)]
pub struct RiscV64Sv48Arch;

impl Arch for RiscV64Sv48Arch {
    const PAGE_SHIFT: usize = 12; // 4096 bytes
    const PAGE_ENTRY_SHIFT: usize = 9; // 512 entries, 8 bytes each
    const PAGE_LEVELS: usize = 4; // L0, L1, L2, L3

    const ENTRY_ADDRESS_WIDTH: usize = 44;
    const ENTRY_ADDRESS_SHIFT: usize = 10;

    const ENTRY_FLAG_DEFAULT_PAGE: usize = Self::ENTRY_FLAG_PRESENT | Self::ENTRY_FLAG_READONLY;
    const ENTRY_FLAG_DEFAULT_TABLE: usize = Self::ENTRY_FLAG_PRESENT;
    const ENTRY_FLAG_PRESENT: usize = 1 << 0;
    const ENTRY_FLAG_READONLY: usize = 1 << 1;
    const ENTRY_FLAG_READWRITE: usize = 3 << 1;
    const ENTRY_FLAG_PAGE_USER: usize = 1 << 4;
    const ENTRY_FLAG_TABLE_USER: usize = 0;
    const ENTRY_FLAG_NO_EXEC: usize = 0;
    const ENTRY_FLAG_EXEC: usize = 1 << 3;
    const ENTRY_FLAG_GLOBAL: usize = 1 << 5;
    const ENTRY_FLAG_NO_GLOBAL: usize = 0;
    const ENTRY_FLAG_WRITE_COMBINING: usize = 0;

    const PHYS_OFFSET: usize = 0xFFFF_8000_0000_0000;

    unsafe fn init() -> &'static [MemoryArea] {
        unimplemented!("RiscV64Sv48Arch::init unimplemented");
    }

    #[inline(always)]
    unsafe fn invalidate(address: VirtualAddress) {
        unsafe {
            asm!("sfence.vma {}", in(reg) address.data());
        }
    }

    #[inline(always)]
    unsafe fn invalidate_all() {
        unsafe {
            asm!("sfence.vma");
        }
    }

    #[inline(always)]
    unsafe fn table(_table_kind: TableKind) -> PhysicalAddress {
        unsafe {
            let satp: usize;
            asm!("csrr {0}, satp", out(reg) satp);
            PhysicalAddress::new(
                (satp & Self::ENTRY_ADDRESS_MASK) << Self::PAGE_SHIFT, // Convert from PPN
            )
        }
    }

    #[inline(always)]
    unsafe fn set_table(_table_kind: TableKind, address: PhysicalAddress) {
        unsafe {
            let satp = (9 << 60) | // Sv48 MODE
            (address.data() >> Self::PAGE_SHIFT); // Convert to PPN (TODO: ensure alignment)
            asm!("csrw satp, {0}", in(reg) satp);
            Self::invalidate_all();
        }
    }

    fn virt_is_valid(address: VirtualAddress) -> bool {
        // RISC-V SV48 uses 48-bit sign-extended addresses, identical to 4-level paging on x86_64.
        let mask = !((Self::PAGE_ADDRESS_SIZE as usize - 1) >> 1);
        let masked = address.data() & mask;

        masked == mask || masked == 0
    }
}

#[cfg(test)]
mod tests {
    use super::RiscV64Sv48Arch;
    use crate::Arch;

    #[test]
    fn constants() {
        assert_eq!(RiscV64Sv48Arch::PAGE_SIZE, 4096);
        assert_eq!(RiscV64Sv48Arch::PAGE_OFFSET_MASK, 0xFFF);
        assert_eq!(RiscV64Sv48Arch::PAGE_ADDRESS_SHIFT, 48);
        assert_eq!(RiscV64Sv48Arch::PAGE_ADDRESS_SIZE, 0x0001_0000_0000_0000);
        assert_eq!(RiscV64Sv48Arch::PAGE_ADDRESS_MASK, 0x0000_FFFF_FFFF_F000);
        assert_eq!(RiscV64Sv48Arch::PAGE_ENTRY_SIZE, 8);
        assert_eq!(RiscV64Sv48Arch::PAGE_ENTRIES, 512);
        assert_eq!(RiscV64Sv48Arch::PAGE_ENTRY_MASK, 0x1FF);
        assert_eq!(RiscV64Sv48Arch::PAGE_NEGATIVE_MASK, 0xFFFF_0000_0000_0000);

        assert_eq!(RiscV64Sv48Arch::ENTRY_ADDRESS_SIZE, 0x0000_1000_0000_0000);
        assert_eq!(RiscV64Sv48Arch::ENTRY_ADDRESS_MASK, 0x0000_0FFF_FFFF_FFFF);
        assert_eq!(RiscV64Sv48Arch::ENTRY_FLAGS_MASK, 0xFFC0_0000_0000_03FF);

        assert_eq!(RiscV64Sv48Arch::PHYS_OFFSET, 0xFFFF_8000_0000_0000);
    }
    #[test]
    fn is_canonical() {
        use super::VirtualAddress;

        // Close to identical when compared to x86_64 test.
        fn yes(address: usize) {
            assert!(RiscV64Sv48Arch::virt_is_valid(VirtualAddress::new(address)));
        }
        fn no(address: usize) {
            assert!(!RiscV64Sv48Arch::virt_is_valid(VirtualAddress::new(
                address
            )));
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
