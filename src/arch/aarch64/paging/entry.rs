//! # Page table entry
//! Some code borrowed from [Phil Opp's Blog](http://os.phil-opp.com/modifying-page-tables.html)

bitflags! {
    pub struct EntryFlags: usize {
        const NO_CACHE = 1 << 2;
        const DEV_MEM = 2 << 2;
    }
}
