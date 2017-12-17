//! # Page table entry
//! Some code borrowed from [Phil Opp's Blog](http://os.phil-opp.com/modifying-page-tables.html)

use memory::Frame;

use super::PhysicalAddress;

/// A page table entry
pub struct Entry(u64);

bitflags! {
    pub struct EntryFlags: u64 {
        const PRESENT =         1 << 0;
        const WRITABLE =        1 << 1;
        const USER_ACCESSIBLE = 1 << 2;
        const WRITE_THROUGH =   1 << 3;
        const NO_CACHE =        1 << 4;
        const ACCESSED =        1 << 5;
        const DIRTY =           1 << 6;
        const HUGE_PAGE =       1 << 7;
        const GLOBAL =          1 << 8;
        const NO_EXECUTE =      1 << 63;
    }
}

pub const ADDRESS_MASK: usize = 0x000f_ffff_ffff_f000;
pub const COUNTER_MASK: u64 = 0x3ff00000_00000000;

impl Entry {
    /// Is the entry unused?
    pub fn is_unused(&self) -> bool {
        self.0 == 0
    }

    /// Make the entry unused
    pub fn set_unused(&mut self) {
        self.0 = 0;
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
        debug_assert!(frame.start_address().get() & !ADDRESS_MASK == 0);
        self.0 = (frame.start_address().get() as u64) | flags.bits() | (self.0 & COUNTER_MASK);
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
