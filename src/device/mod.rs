use paging::ActivePageTable;

pub mod cpu;
pub mod local_apic;
pub mod pic;
pub mod rtc;
pub mod serial;

pub unsafe fn init(active_table: &mut ActivePageTable) {
    pic::init();
    local_apic::init(active_table);
}

pub unsafe fn init_noncore() {
    rtc::init();
    serial::init();
}

pub unsafe fn init_ap() {
    local_apic::init_ap();
}
