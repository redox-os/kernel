//! # Page table entry
//! Some code borrowed from [Phil Opp's Blog](http://os.phil-opp.com/modifying-page-tables.html)

/// A page table entry
#[repr(packed(8))]
pub struct Entry(u64);

bitflags! {
    pub struct EntryFlags: usize {
        const NO_CACHE = 1 << 2;
        const DEV_MEM = 2 << 2;
    }
}
