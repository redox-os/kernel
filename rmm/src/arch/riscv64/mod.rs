pub use sv39::RiscV64Sv39Arch;
pub use sv48::RiscV64Sv48Arch;

mod sv39;
mod sv48;

bitflags::bitflags! {
    pub struct EntryFlags: usize {
        const NO_CACHE =        1 << 4;
        const DEV_MEM =         0;
    }
}
