use core::arch::asm;

use crate::{Arch, MemoryArea, PhysicalAddress, TableKind, VirtualAddress};

#[derive(Clone, Copy)]
pub struct RiscV64Sv39Arch;

pub const ACCESSED: usize = 1 << 6;
pub const DIRTY: usize = 1 << 7;

impl Arch for RiscV64Sv39Arch {
    const PAGE_SHIFT: usize = 12; // 4096 bytes
    const PAGE_ENTRY_SHIFT: usize = 9; // 512 entries, 8 bytes each
    const PAGE_LEVELS: usize = 3; // L0, L1, L2

    const ENTRY_ADDRESS_WIDTH: usize = 44;
    const ENTRY_ADDRESS_SHIFT: usize = 10;

    const ENTRY_FLAG_DEFAULT_PAGE: usize =
        Self::ENTRY_FLAG_PRESENT | Self::ENTRY_FLAG_READONLY | ACCESSED | DIRTY;
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

    const PHYS_OFFSET: usize = 0xFFFF_FFC0_0000_0000;

    unsafe fn init() -> &'static [MemoryArea] {
        unimplemented!("RiscV64Sv39Arch::init unimplemented");
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
            let satp = (8 << 60) | // Sv39 MODE
            (address.data() >> Self::PAGE_SHIFT); // Convert to PPN (TODO: ensure alignment)
            asm!("csrw satp, {0}", in(reg) satp);
            Self::invalidate_all();
        }
    }

    fn virt_is_valid(address: VirtualAddress) -> bool {
        let mask = !((Self::PAGE_ADDRESS_SIZE as usize - 1) >> 1);
        let masked = address.data() & mask;

        masked == mask || masked == 0
    }
}

#[cfg(test)]
mod tests {
    use super::RiscV64Sv39Arch;
    use crate::Arch;

    #[test]
    fn constants() {
        assert_eq!(RiscV64Sv39Arch::PAGE_SIZE, 4096);
        assert_eq!(RiscV64Sv39Arch::PAGE_OFFSET_MASK, 0xFFF);
        assert_eq!(RiscV64Sv39Arch::PAGE_ADDRESS_SHIFT, 39);
        assert_eq!(RiscV64Sv39Arch::PAGE_ADDRESS_SIZE, 0x0000_0080_0000_0000);
        assert_eq!(RiscV64Sv39Arch::PAGE_ADDRESS_MASK, 0x0000_007F_FFFF_F000);
        assert_eq!(RiscV64Sv39Arch::PAGE_ENTRY_SIZE, 8);
        assert_eq!(RiscV64Sv39Arch::PAGE_ENTRIES, 512);
        assert_eq!(RiscV64Sv39Arch::PAGE_ENTRY_MASK, 0x1FF);
        assert_eq!(RiscV64Sv39Arch::PAGE_NEGATIVE_MASK, 0xFFFF_FF80_0000_0000);

        assert_eq!(RiscV64Sv39Arch::ENTRY_ADDRESS_SIZE, 0x0000_1000_0000_0000);
        assert_eq!(RiscV64Sv39Arch::ENTRY_ADDRESS_MASK, 0x0000_0FFF_FFFF_FFFF);
        assert_eq!(RiscV64Sv39Arch::ENTRY_FLAGS_MASK, 0xFFC0_0000_0000_03FF);

        assert_eq!(RiscV64Sv39Arch::PHYS_OFFSET, 0xFFFF_FFC0_0000_0000);
    }
    #[test]
    fn is_canonical() {
        use super::VirtualAddress;

        #[track_caller]
        fn yes(addr: usize) {
            assert!(RiscV64Sv39Arch::virt_is_valid(VirtualAddress::new(addr)));
        }
        #[track_caller]
        fn no(addr: usize) {
            assert!(!RiscV64Sv39Arch::virt_is_valid(VirtualAddress::new(addr)));
        }

        yes(0xFFFF_FFFF_FFFF_FFFF);
        yes(0xFFFF_FFF0_1337_1337);
        no(0x0000_0F00_0000_0000);
        no(0x1337_0000_0000_0000);
        no(1 << 38);
        yes(1 << 37);

        // Check for off-by-one errors.
        yes(0xFFFF_FFC0_0000_0000 | (1 << 37));
        yes(0xFFFF_FFE0_0000_0000 | (1 << 37));
        no(0xFFFF_FF80_0000_0000 | (1 << 37));
    }
}
