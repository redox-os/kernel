use paging::ActivePageTable;
use acpi::ACPI_TABLE;
use syscall::io::{Pio, Io};

pub mod cpu;
pub mod local_apic;
pub mod pic;
pub mod rtc;
pub mod serial;
pub mod hpet;

pub unsafe fn init(active_table: &mut ActivePageTable){
    pic::init();
    local_apic::init(active_table);
}

pub unsafe fn init_noncore(active_table: &mut ActivePageTable) {
    {
        if let Some(ref hpet) = ACPI_TABLE.lock().hpet {
            // Disable the PIT
            // TODO: Move PIT driver to kernel, and just don't enable it in the first place if we have an HPET
            let mut pit_cmd = Pio::<u8>::new(0x43);
            let mut pit_c0 = Pio::<u8>::new(0x40);

            pit_cmd.write(0x30);
            pit_c0.write(0);
            pit_c0.write(0);

            hpet::init(hpet, active_table);
        }
    }
    
    rtc::init();
    serial::init();
}

pub unsafe fn init_ap() {
    local_apic::init_ap();
}
