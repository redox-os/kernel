use alloc::boxed::Box;
use log::{debug, error, info};

use super::ic_for_chip;
use crate::{
    context,
    context::timeout,
    device::cpu::registers::control_regs,
    dtb::{
        get_interrupt,
        irqchip::{register_irq, InterruptHandler, IRQ_CHIP},
    },
    interrupt::irq::trigger,
    time,
};
use fdt::Fdt;

bitflags! {
    struct TimerCtrlFlags: u32 {
        const ENABLE = 1 << 0;
        const IMASK = 1 << 1;
        const ISTATUS = 1 << 2;
    }
}

pub unsafe fn init(fdt: &Fdt) {
    let mut timer = GenericTimer::new();
    timer.init();
    if let Some(node) = fdt.find_compatible(&["arm,armv7-timer"]) {
        let irq = get_interrupt(fdt, &node, 1).unwrap();
        debug!("irq = {:?}", irq);
        if let Some(ic_idx) = ic_for_chip(&fdt, &node) {
            //PHYS_NONSECURE_PPI only
            let virq = IRQ_CHIP.irq_chip_list.chips[ic_idx]
                .ic
                .irq_xlate(irq)
                .unwrap();
            info!("generic_timer virq = {}", virq);
            register_irq(virq as u32, Box::new(timer));
            IRQ_CHIP.irq_enable(virq as u32);
        } else {
            error!("Failed to find irq parent for generic timer");
        }
    }
}

pub struct GenericTimer {
    pub use_virtual_timer: bool,
    pub clk_freq: u32,
    pub reload_count: u32,
}

impl GenericTimer {
    pub fn new() -> Self {
        Self {
            use_virtual_timer: false,
            clk_freq: 0,
            reload_count: 0,
        }
    }
    pub fn init(&mut self) {
        self.use_virtual_timer = unsafe { !control_regs::vhe_present() };
        debug!(
            "generic_timer use_virtual_timer = {:?}",
            self.use_virtual_timer
        );
        let clk_freq = unsafe { control_regs::cntfrq_el0() };
        self.clk_freq = clk_freq;
        self.reload_count = clk_freq / 100;
        self.reload_count();
    }

    fn read_tmr_ctrl(&self) -> TimerCtrlFlags {
        TimerCtrlFlags::from_bits_truncate(if self.use_virtual_timer {
            unsafe { control_regs::vtmr_ctrl() }
        } else {
            unsafe { control_regs::ptmr_ctrl() }
        })
    }

    fn write_tmr_ctrl(&self, ctrl: TimerCtrlFlags) {
        if self.use_virtual_timer {
            unsafe { control_regs::vtmr_ctrl_write(ctrl.bits()) };
        } else {
            unsafe { control_regs::ptmr_ctrl_write(ctrl.bits()) };
        }
    }

    #[allow(unused)]
    fn disable(&self) {
        let mut ctrl = self.read_tmr_ctrl();
        ctrl.remove(TimerCtrlFlags::ENABLE);
        self.write_tmr_ctrl(ctrl);
    }

    #[allow(unused)]
    pub fn set_irq(&mut self) {
        let mut ctrl = self.read_tmr_ctrl();
        ctrl.remove(TimerCtrlFlags::IMASK);
        self.write_tmr_ctrl(ctrl);
    }

    pub fn clear_irq(&mut self) {
        let mut ctrl = self.read_tmr_ctrl();

        if ctrl.contains(TimerCtrlFlags::ISTATUS) {
            ctrl.insert(TimerCtrlFlags::IMASK);
            self.write_tmr_ctrl(ctrl);
        }
    }

    pub fn reload_count(&mut self) {
        if self.use_virtual_timer {
            unsafe { control_regs::vtmr_tval_write(self.reload_count) };
        } else {
            unsafe { control_regs::ptmr_tval_write(self.reload_count) };
        }
        let mut ctrl = self.read_tmr_ctrl();
        ctrl.insert(TimerCtrlFlags::ENABLE);
        ctrl.remove(TimerCtrlFlags::IMASK);
        self.write_tmr_ctrl(ctrl);
    }
}

impl InterruptHandler for GenericTimer {
    fn irq_handler(&mut self, irq: u32) {
        self.clear_irq();
        {
            *time::OFFSET.lock() += self.clk_freq as u128;
        }

        timeout::trigger();

        context::switch::tick();

        unsafe {
            trigger(irq);
        }
        self.reload_count();
    }
}
