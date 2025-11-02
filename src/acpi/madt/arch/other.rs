use super::Madt;

pub(super) fn init(madt: Madt) {
    for madt_entry in madt.iter() {
        debug!("      {:#x?}", madt_entry);
    }

    warn!("MADT not yet handled on this platform");
}
