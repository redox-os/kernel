//! # Page table entry
//! Some code borrowed from [Phil Opp's Blog](http://os.phil-opp.com/modifying-page-tables.html)

use crate::memory::Frame;

use super::{PhysicalAddress, RmmA, RmmArch};

/// A page table entry
#[repr(packed(8))]
pub struct Entry(u64);

bitflags! {
    pub struct EntryFlags: u64 {
        const PRESENT =         RmmA::ENTRY_FLAG_PRESENT as u64;
        const WRITABLE =        RmmA::ENTRY_FLAG_READWRITE as u64;
        const USER_ACCESSIBLE = RmmA::ENTRY_FLAG_USER as u64;
        const NO_CACHE =        1 << 4;
        const HUGE_PAGE =       1 << 7;
        const GLOBAL =          1 << 8;
        const NO_EXECUTE =      RmmA::ENTRY_FLAG_NO_EXEC as u64;
    }
}

pub const ADDRESS_MASK: usize = 0x000f_ffff_ffff_f000;
pub const COUNTER_MASK: u64 = 0x3ff0_0000_0000_0000;

impl Entry {
    /// Clear entry
    pub fn set_zero(&mut self) {
        self.0 = 0;
    }

    /// Is the entry unused?
    pub fn is_unused(&self) -> bool {
        self.0 == (self.0 & COUNTER_MASK)
    }

    /// Make the entry unused
    pub fn set_unused(&mut self) {
        self.0 &= COUNTER_MASK;
    }

    /// Get the address this page references
    pub fn address(&self) -> PhysicalAddress {
        PhysicalAddress::new(self.0 as usize & ADDRESS_MASK)
    }

    /// Get the current entry flags
    pub fn flags(&self) -> EntryFlags {
        EntryFlags::from_bits_truncate(self.0)
    }

    /// Get the associated frame, if available
    pub fn pointed_frame(&self) -> Option<Frame> {
        if self.flags().contains(EntryFlags::PRESENT) {
            Some(Frame::containing_address(self.address()))
        } else {
            None
        }
    }

    pub fn set(&mut self, frame: Frame, flags: EntryFlags) {
        debug_assert!(frame.start_address().data() & !ADDRESS_MASK == 0);
        self.0 = (frame.start_address().data() as u64) | flags.bits() | (self.0 & COUNTER_MASK);
    }

    /// Get bits 52-61 in entry, used as counter for page table
    pub fn counter_bits(&self) -> u64 {
        (self.0 & COUNTER_MASK) >> 52
    }

    /// Set bits 52-61 in entry, used as counter for page table
    pub fn set_counter_bits(&mut self, count: u64) {
        self.0 = (self.0 & !COUNTER_MASK) | (count << 52);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn entry_has_required_arch_alignment() {
        use super::Entry;
        assert!(core::mem::align_of::<Entry>() >= core::mem::align_of::<u64>(), "alignment of Entry is less than the required alignment of u64 ({} < {})", core::mem::align_of::<Entry>(), core::mem::align_of::<u64>());
    }
}
