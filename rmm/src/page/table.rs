use core::marker::PhantomData;

use super::PageEntry;
use crate::{Arch, PhysicalAddress, TableKind, VirtualAddress};

pub struct PageTable<A> {
    base: VirtualAddress,
    phys: PhysicalAddress,
    level: usize,
    phantom: PhantomData<A>,
}

impl<A: Arch> PageTable<A> {
    pub unsafe fn new(base: VirtualAddress, phys: PhysicalAddress, level: usize) -> Self {
        Self {
            base,
            phys,
            level,
            phantom: PhantomData,
        }
    }

    pub unsafe fn top(table_kind: TableKind) -> Self {
        unsafe {
            Self::new(
                VirtualAddress::new(0),
                A::table(table_kind),
                A::PAGE_LEVELS - 1,
            )
        }
    }

    pub fn base(&self) -> VirtualAddress {
        self.base
    }

    pub fn phys(&self) -> PhysicalAddress {
        self.phys
    }

    pub fn level(&self) -> usize {
        self.level
    }

    pub unsafe fn virt(&self) -> VirtualAddress {
        unsafe {
            A::phys_to_virt(self.phys)

            // Recursive mapping
            // let mut addr = 0xFFFF_FFFF_FFFF_F000;
            // for level in (self.level + 1 .. A::PAGE_LEVELS).rev() {
            //     let index = (self.base.0 >> (level * A::PAGE_ENTRY_SHIFT + A::PAGE_SHIFT)) & A::PAGE_ENTRY_MASK;
            //     addr <<= A::PAGE_ENTRY_SHIFT;
            //     addr |= index << A::PAGE_SHIFT;
            // }
            // VirtualAddress::new(addr)
        }
    }

    pub fn entry_base(&self, i: usize) -> Option<VirtualAddress> {
        if i < A::PAGE_ENTRIES {
            let level_shift = self.level * A::PAGE_ENTRY_SHIFT + A::PAGE_SHIFT;
            Some(self.base.add(i << level_shift))
        } else {
            None
        }
    }

    pub unsafe fn entry_virt(&self, i: usize) -> Option<VirtualAddress> {
        unsafe {
            if i < A::PAGE_ENTRIES {
                Some(self.virt().add(i * A::PAGE_ENTRY_SIZE))
            } else {
                None
            }
        }
    }

    pub unsafe fn entry(&self, i: usize) -> Option<PageEntry<A>> {
        unsafe {
            let addr = self.entry_virt(i)?;
            Some(PageEntry::from_data(A::read::<usize>(addr)))
        }
    }

    pub unsafe fn set_entry(&mut self, i: usize, entry: PageEntry<A>) -> Option<()> {
        unsafe {
            let addr = self.entry_virt(i)?;
            A::write::<usize>(addr, entry.data());
            Some(())
        }
    }

    pub unsafe fn index_of(&self, address: VirtualAddress) -> Option<usize> {
        // Canonicalize address first
        let address = VirtualAddress::new(address.data() & A::PAGE_ADDRESS_MASK);
        let level_shift = self.level * A::PAGE_ENTRY_SHIFT + A::PAGE_SHIFT;
        // Intentionally wraps around at last-level table to get all-ones mask on architectures
        // where addressable physical address space covers entire usized space (e.g. x86)
        let level_mask = A::PAGE_ENTRIES
            .wrapping_shl(level_shift as u32)
            .wrapping_sub(1);
        if address >= self.base && address <= self.base.add(level_mask) {
            Some((address.data() >> level_shift) & A::PAGE_ENTRY_MASK)
        } else {
            None
        }
    }

    pub unsafe fn next(&self, i: usize) -> Option<Self> {
        unsafe {
            if self.level == 0 {
                return None;
            }

            Some(PageTable::new(
                self.entry_base(i)?,
                self.entry(i)?.address().ok()?,
                self.level - 1,
            ))
        }
    }
}
