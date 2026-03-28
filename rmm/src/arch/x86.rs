//TODO: USE PAE
use core::arch::asm;

use crate::{Arch, MemoryArea, PhysicalAddress, TableKind, VirtualAddress};

#[derive(Clone, Copy)]
pub struct X86Arch;

impl Arch for X86Arch {
    const PAGE_SHIFT: usize = 12; // 4096 bytes
    const PAGE_ENTRY_SHIFT: usize = 10; // 1024 entries, 4 bytes each
    const PAGE_LEVELS: usize = 2; // PD, PT

    const ENTRY_ADDRESS_WIDTH: usize = 20;
    const ENTRY_FLAG_DEFAULT_PAGE: usize = Self::ENTRY_FLAG_PRESENT;
    const ENTRY_FLAG_DEFAULT_TABLE: usize = Self::ENTRY_FLAG_PRESENT | Self::ENTRY_FLAG_READWRITE;
    const ENTRY_FLAG_PRESENT: usize = 1 << 0;
    const ENTRY_FLAG_READONLY: usize = 0;
    const ENTRY_FLAG_READWRITE: usize = 1 << 1;
    const ENTRY_FLAG_PAGE_USER: usize = 1 << 2;
    // Not used: const ENTRY_FLAG_HUGE: usize = 1 << 7;
    const ENTRY_FLAG_GLOBAL: usize = 1 << 8;
    const ENTRY_FLAG_NO_GLOBAL: usize = 0;
    const ENTRY_FLAG_NO_EXEC: usize = 0; // NOT AVAILABLE UNLESS PAE IS USED!
    const ENTRY_FLAG_EXEC: usize = 0;
    const ENTRY_FLAG_WRITE_COMBINING: usize = 1 << 7;

    const PHYS_OFFSET: usize = 0x8000_0000;

    unsafe fn init() -> &'static [MemoryArea] {
        unimplemented!("X86Arch::init unimplemented");
    }

    #[inline(always)]
    unsafe fn invalidate(address: VirtualAddress) {
        asm!("invlpg [{0}]", in(reg) address.data());
    }

    #[inline(always)]
    unsafe fn table(_table_kind: TableKind) -> PhysicalAddress {
        let address: usize;
        asm!("mov {0}, cr3", out(reg) address);
        PhysicalAddress::new(address)
    }

    #[inline(always)]
    unsafe fn set_table(_table_kind: TableKind, address: PhysicalAddress) {
        asm!("mov cr3, {0}", in(reg) address.data());
    }

    fn virt_is_valid(_address: VirtualAddress) -> bool {
        // On 32-bit x86, every virtual address is valid
        true
    }
}

#[cfg(test)]
mod tests {
    use super::{VirtualAddress, X86Arch};
    use crate::Arch;

    #[test]
    fn constants() {
        assert_eq!(X86Arch::PAGE_SIZE, 4096);
        assert_eq!(X86Arch::PAGE_OFFSET_MASK, 0xFFF);
        assert_eq!(X86Arch::PAGE_ADDRESS_SHIFT, 32);
        assert_eq!(X86Arch::PAGE_ADDRESS_SIZE, 0x0000_0001_0000_0000);
        assert_eq!(X86Arch::PAGE_ADDRESS_MASK, 0xFFFF_F000);
        assert_eq!(X86Arch::PAGE_ENTRY_SIZE, 4);
        assert_eq!(X86Arch::PAGE_ENTRIES, 1024);
        assert_eq!(X86Arch::PAGE_ENTRY_MASK, 0x3FF);
        assert_eq!(X86Arch::PAGE_NEGATIVE_MASK, 0x0000_0000_0000);

        assert_eq!(X86Arch::ENTRY_ADDRESS_SIZE, 0x0000_0000_0010_0000);
        assert_eq!(X86Arch::ENTRY_ADDRESS_MASK, 0x000F_FFFF);
        assert_eq!(X86Arch::ENTRY_FLAGS_MASK, 0x0000_0FFF);

        assert_eq!(X86Arch::PHYS_OFFSET, 0x8000_0000);
    }
}
