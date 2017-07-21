use paging::ActivePageTable;
use acpi::ACPI_TABLE;
use syscall::io::{Pio, Io};

pub mod cpu;
pub mod local_apic;
pub mod pic;
pub mod pit;
pub mod rtc;
pub mod serial;
pub mod hpet;

pub unsafe fn init(active_table: &mut ActivePageTable){
    pic::init();
    local_apic::init(active_table);
}

pub unsafe fn init_noncore() {
    {
        if let Some(ref mut hpet) = *ACPI_TABLE.hpet.write() {
            hpet::init(hpet);
        } else {
            pit::init();
        }
    }
    
    rtc::init();
    serial::init();
}

pub unsafe fn init_ap() {
    local_apic::init_ap();
}
