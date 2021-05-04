//! # Page table entry
//! Some code borrowed from [Phil Opp's Blog](http://os.phil-opp.com/modifying-page-tables.html)

use crate::memory::Frame;

use super::{PageFlags, PhysicalAddress, RmmA, RmmArch};

/// A page table entry
#[derive(Debug)]
pub struct Entry(u64);

/// A page descriptor
#[derive(Debug)]
pub struct PageDescriptor(u64);

bitflags! {
    pub struct TableDescriptorFlags: u64 {
        const PRESENT =                     1 << 0;
        const VALID =                       1 << 0;
        const TABLE =                       1 << 1;
        const AF =                          1 << 10;    /* NOTE: TableDescriptors don't actually have an AF bit! */
        const PXNTABLE =                    1 << 59;
        const UXNTABLE =                    1 << 60;
        const APTABLE_0 =                   1 << 61;
        const APTABLE_1 =                   1 << 62;
        const SUBLEVEL_NO_EL0_ACCESS =      (0 << 62) | (1 << 61);
        const SUBLEVEL_NO_WANY_ACCESS =     (1 << 62) | (0 << 61);
        const SUBLEVEL_NO_WANY_NO_REL0 =    (1 << 62) | (1 << 61);
        const NSTABLE =                     1 << 63;
    }
}

bitflags! {
    pub struct PageDescriptorFlags: u64 {
        const PRESENT =             1 << 0;
        const VALID =               1 << 0;
        const PAGE =                1 << 1;
        const ATTR_INDEX_0 =        1 << 2;
        const ATTR_INDEX_1 =        1 << 3;
        const ATTR_INDEX_2 =        1 << 4;
        const NS =                  1 << 5;
        const AP_1 =                1 << 6;
        const AP_2 =                1 << 7;
        const SH_0 =                1 << 8;
        const SH_1 =                1 << 9;
        const AF =                  1 << 10;
        const NG =                  1 << 11;
        const DBM =                 1 << 51;
        const CONTIGUOUS =          1 << 52;
        const PXN =                 1 << 53;
        const UXN =                 1 << 54;
    }
}

// These are 'virtual' flags that are used to minimise changes to the generic paging code.
// These are translated to AArch64 specific Page and Table descriptors as and when needed.
bitflags! {
    #[derive(Default)]
    pub struct EntryFlags: usize {
        const PRESENT =             1 << 0;
        const HUGE_PAGE =           1 << 1;
        const GLOBAL =              1 << 2;
        const NO_EXECUTE =          1 << 3;
        const USER_ACCESSIBLE =     1 << 4;
        const WRITABLE =            1 << 5;
        const TLS =                 1 << 6;
        const AF =                  1 << 10;
    }
}

pub const ADDRESS_MASK: usize = 0x0000_ffff_ffff_f000;
pub const COUNTER_MASK: u64 = 0x0008_0000_0000_0000;

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
    pub fn page_table_entry_flags(&self) -> TableDescriptorFlags {
        TableDescriptorFlags::from_bits_truncate(self.0)
    }

    pub fn page_descriptor_entry_flags(&self) -> PageDescriptorFlags {
        PageDescriptorFlags::from_bits_truncate(self.0)
    }

    /// Get the current entry flags
    pub fn flags(&self) -> PageFlags<RmmA> {
        unsafe { PageFlags::from_data((self.0 as usize & RmmA::ENTRY_FLAGS_MASK) & !(COUNTER_MASK as usize)) }
    }

    /// Get the associated frame, if available, for a level 4, 3, or 2 page
    pub fn pointed_frame(&self) -> Option<Frame> {
        if self.page_table_entry_flags().contains(TableDescriptorFlags::VALID) {
            Some(Frame::containing_address(self.address()))
        } else {
            None
        }
    }

    /// Get the associated frame, if available, for a level 1 page
    pub fn pointed_frame_at_l1(&self) -> Option<Frame> {
        if self.page_descriptor_entry_flags().contains(PageDescriptorFlags::VALID) {
            Some(Frame::containing_address(self.address()))
        } else {
            None
        }
    }

    pub fn page_table_entry_set(&mut self, frame: Frame, flags: TableDescriptorFlags) {
        debug_assert!(frame.start_address().data() & !ADDRESS_MASK == 0);
        // ODDNESS Alert: We need to set the AF bit - despite this being a TableDescriptor!!!
        // The Arm ARM says this bit (bit 10) is IGNORED in Table Descriptors so hopefully this is OK
        let access_flag = TableDescriptorFlags::AF;
        self.0 = (frame.start_address().data() as u64) | flags.bits() | access_flag.bits() | (self.0 & COUNTER_MASK);
    }

    pub fn page_descriptor_entry_set(&mut self, frame: Frame, flags: PageDescriptorFlags) {
        debug_assert!(frame.start_address().data() & !ADDRESS_MASK == 0);
        let access_flag = PageDescriptorFlags::AF;
        self.0 = (frame.start_address().data() as u64) | flags.bits() | access_flag.bits() | (self.0 & COUNTER_MASK);
    }

    pub fn set(&mut self, frame: Frame, flags: PageFlags<RmmA>) {
        debug_assert!(frame.start_address().data() & !ADDRESS_MASK == 0);
        self.0 = (frame.start_address().data() as u64) | (flags.data() as u64) | (self.0 & COUNTER_MASK);
    }

    /// Get bit 51 in entry, used as 1 of 9 bits (in 9 entries) used as a counter for the page table
    pub fn counter_bits(&self) -> u64 {
        (self.0 & COUNTER_MASK) >> 51
    }

    /// Set bit 51 in entry, used as 1 of 9 bits (in 9 entries) used as a counter for the page table
    pub fn set_counter_bits(&mut self, count: u64) {
        self.0 = (self.0 & !COUNTER_MASK) | ((count & 0x1) << 51);
    }
}
