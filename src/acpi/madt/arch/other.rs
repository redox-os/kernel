use super::Madt;

pub(super) fn init(madt: Madt) {
    for madt_entry in madt.iter() {
        println!("      {:#x?}", madt_entry);
    }

    log::warn!("MADT not yet handled on this platform");
}
