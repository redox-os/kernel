/// A page table entry
#[repr(packed(8))]
pub struct Entry(u64);

bitflags! {
    pub struct EntryFlags: usize {
        const NO_CACHE =        1 << 4;
        const DEV_MEM =         0;
        const WRITE_COMBINING = 0;
    }
}
