pub mod cpu;
pub mod gic;
pub mod generic_timer;
pub mod serial;
pub mod rtc;
pub mod uart_pl011;

pub unsafe fn init() {
    println!("GIC INIT");
    gic::init();
    println!("GIT INIT");
    generic_timer::init();
}

pub unsafe fn init_noncore() {
    println!("SERIAL INIT");
    serial::init();
    println!("RTC INIT");
    rtc::init();
}

pub unsafe fn init_ap() {
}
