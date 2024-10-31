use alloc::boxed::Box;
use core::mem;

use super::{find_sdt, sdt::Sdt};
use crate::{
    device::generic_timer::GenericTimer,
    dtb::irqchip::{register_irq, IRQ_CHIP},
};

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct Gtdt {
    pub header: Sdt,
    pub cnt_control_base: u64,
    _reserved: u32,
    pub secure_el1_timer_gsiv: u32,
    pub secure_el1_timer_flags: u32,
    pub non_secure_el1_timer_gsiv: u32,
    pub non_secure_el1_timer_flags: u32,
    pub virtual_el1_timer_gsiv: u32,
    pub virtual_el1_timer_flags: u32,
    pub el2_timer_gsiv: u32,
    pub el2_timer_flags: u32,
    pub cnt_read_base: u64,
    pub platform_timer_count: u32,
    pub platform_timer_offset: u32,
    /*TODO: we don't need these yet, and they cause short tables to fail parsing
    pub virtual_el2_timer_gsiv: u32,
    pub virtual_el2_timer_flags: u32,
    */
    //TODO: platform timer structure (at platform timer offset, with platform timer count)
}

impl Gtdt {
    pub fn init() {
        let gtdt_sdt = find_sdt("GTDT");
        let gtdt = if gtdt_sdt.len() == 1 {
            match Gtdt::new(gtdt_sdt[0]) {
                Some(gtdt) => gtdt,
                None => {
                    log::warn!("Failed to parse GTDT");
                    return;
                }
            }
        } else {
            log::warn!("Unable to find GTDT");
            return;
        };

        let gsiv = gtdt.non_secure_el1_timer_gsiv;
        log::info!("generic_timer gsiv = {}", gsiv);
        let mut timer = GenericTimer {
            clk_freq: 0,
            reload_count: 0,
        };
        timer.init();
        register_irq(gsiv, Box::new(timer));
        unsafe { IRQ_CHIP.irq_enable(gsiv as u32) };
    }

    pub fn new(sdt: &'static Sdt) -> Option<&'static Gtdt> {
        if &sdt.signature == b"GTDT" && sdt.length as usize >= mem::size_of::<Gtdt>() {
            Some(unsafe { &*((sdt as *const Sdt) as *const Gtdt) })
        } else {
            None
        }
    }
}
