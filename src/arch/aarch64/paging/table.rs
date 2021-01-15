//! # Page table
//! Code borrowed from [Phil Opp's Blog](http://os.phil-opp.com/modifying-page-tables.html)

use core::marker::PhantomData;
use core::ops::{Index, IndexMut};

use crate::memory::allocate_frames;

use super::entry::{TableDescriptorFlags, Entry};
use super::ENTRY_COUNT;

pub const P4: *mut Table<Level4> = 0xffff_ffff_ffff_f000 as *mut _;
pub const U4: *mut Table<Level4> = 0x0000_ffff_ffff_f000 as *mut _;

const KSPACE_ADDR_MASK: usize = 0xffff_0000_0000_0000;
const USPACE_ADDR_MASK: usize = 0x0000_ffff_ffff_ffff;

pub trait TableLevel {}

pub enum Level4 {}
pub enum Level3 {}
pub enum Level2 {}
pub enum Level1 {}

impl TableLevel for Level4 {}
impl TableLevel for Level3 {}
impl TableLevel for Level2 {}
impl TableLevel for Level1 {}

pub trait HierarchicalLevel: TableLevel {
    type NextLevel: TableLevel;
}

impl HierarchicalLevel for Level4 {
    type NextLevel = Level3;
}

impl HierarchicalLevel for Level3 {
    type NextLevel = Level2;
}

impl HierarchicalLevel for Level2 {
    type NextLevel = Level1;
}

pub struct Table<L: TableLevel> {
    entries: [Entry; ENTRY_COUNT],
    level: PhantomData<L>,
}

impl<L> Table<L> where L: TableLevel {
    pub fn is_unused(&self) -> bool {
        if self.entry_count() > 0 {
            return false;
        }

        true
    }

    pub fn zero(&mut self) {
        for entry in self.entries.iter_mut() {
            entry.set_zero();
        }
    }

    /// Set number of entries in first table entry
    /// FIXMES:
    /// Only 1 bit per table entry seems to work. So we need 9 entries (!).
    /// This is one reason why we need to have a non-recursive paging scheme.
    /// These updates require memory barriers and TLB invalidations.
    fn set_entry_count(&mut self, count: u64) {
        debug_assert!(count <= ENTRY_COUNT as u64, "count can't be greater than ENTRY_COUNT");
        self.entries[0].set_counter_bits((count >> 0) & 0x1);
        self.entries[1].set_counter_bits((count >> 1) & 0x1);
        self.entries[2].set_counter_bits((count >> 2) & 0x1);
        self.entries[3].set_counter_bits((count >> 3) & 0x1);
        self.entries[4].set_counter_bits((count >> 4) & 0x1);
        self.entries[5].set_counter_bits((count >> 5) & 0x1);
        self.entries[6].set_counter_bits((count >> 6) & 0x1);
        self.entries[7].set_counter_bits((count >> 7) & 0x1);
        self.entries[8].set_counter_bits((count >> 8) & 0x1);
    }

    /// Get number of entries from first table entry
    fn entry_count(&self) -> u64 {
        let mut count: u64 = (self.entries[0].counter_bits() & 0x1) << 0;
        count |= (self.entries[1].counter_bits() & 0x1) << 1;
        count |= (self.entries[2].counter_bits() & 0x1) << 2;
        count |= (self.entries[3].counter_bits() & 0x1) << 3;
        count |= (self.entries[4].counter_bits() & 0x1) << 4;
        count |= (self.entries[5].counter_bits() & 0x1) << 5;
        count |= (self.entries[6].counter_bits() & 0x1) << 6;
        count |= (self.entries[7].counter_bits() & 0x1) << 7;
        count |= (self.entries[8].counter_bits() & 0x1) << 8;
        count
    }

    pub fn increment_entry_count(&mut self) {
        let current_count = self.entry_count();
        self.set_entry_count(current_count + 1);
    }

    pub fn decrement_entry_count(&mut self) {
        let current_count = self.entry_count();
        self.set_entry_count(current_count - 1);
    }
}

impl<L> Table<L> where L: HierarchicalLevel {
    pub fn next_table(&self, index: usize) -> Option<&Table<L::NextLevel>> {
        self.next_table_address(index).map(|address| unsafe { &*(address as *const _) })
    }

    pub fn next_table_mut(&mut self, index: usize) -> Option<&mut Table<L::NextLevel>> {
        self.next_table_address(index).map(|address| unsafe { &mut *(address as *mut _) })
    }

    pub fn next_table_create(&mut self, index: usize) -> &mut Table<L::NextLevel> {
        if self.next_table(index).is_none() {
            let frame = allocate_frames(1).expect("no frames available");
            self.increment_entry_count();

            /* Allow users to go down the page table, implement permissions at the page level */
            let mut perms = TableDescriptorFlags::VALID;
            perms |= TableDescriptorFlags::TABLE;

            self[index].page_table_entry_set(frame, perms);
            self.next_table_mut(index).unwrap().zero();
        }
        self.next_table_mut(index).unwrap()
    }

    fn next_table_address(&self, index: usize) -> Option<usize> {
        let entry_flags = self[index].page_table_entry_flags();
        if entry_flags.contains(TableDescriptorFlags::VALID) {
            let table_address = self as *const _ as usize;
            if (table_address & KSPACE_ADDR_MASK) != 0 {
                Some((table_address << 9) | (index << 12))
            } else {
                Some(((table_address << 9) | (index << 12)) & USPACE_ADDR_MASK)
            }
        } else {
            None
        }
    }
}

impl<L> Index<usize> for Table<L> where L: TableLevel {
    type Output = Entry;

    fn index(&self, index: usize) -> &Entry {
        &self.entries[index]
    }
}

impl<L> IndexMut<usize> for Table<L> where L: TableLevel {
    fn index_mut(&mut self, index: usize) -> &mut Entry {
        &mut self.entries[index]
    }
}
