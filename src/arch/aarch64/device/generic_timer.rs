use alloc::boxed::Box;
use log::{error, info};

use super::ic_for_chip;
use crate::{
    context,
    context::timeout,
    device::cpu::registers::control_regs,
    dtb::irqchip::{register_irq, InterruptHandler, IRQ_CHIP},
    interrupt::irq::trigger,
    time,
};
use byteorder::{ByteOrder, BE};
use fdt::Fdt;

bitflags! {
    struct TimerCtrlFlags: u32 {
        const ENABLE = 1 << 0;
        const IMASK = 1 << 1;
        const ISTATUS = 1 << 2;
    }
}

pub unsafe fn init(fdt: &Fdt) {
    let mut timer = GenericTimer {
        clk_freq: 0,
        reload_count: 0,
    };
    timer.init();
    if let Some(node) = fdt.find_compatible(&["arm,armv7-timer"]) {
        let interrupts = node.property("interrupts").unwrap();
        let irq = interrupts
            .value
            .array_chunks::<4>()
            .map(|f| BE::read_u32(f))
            .skip(3)
            .next_chunk::<3>()
            .unwrap();
        if let Some(ic_idx) = ic_for_chip(&fdt, &node) {
            //PHYS_NONSECURE_PPI only
            let virq = IRQ_CHIP.irq_chip_list.chips[ic_idx]
                .ic
                .irq_xlate(&irq)
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
    pub clk_freq: u32,
    pub reload_count: u32,
}

impl GenericTimer {
    pub fn init(&mut self) {
        let clk_freq = unsafe { control_regs::cntfreq_el0() };
        self.clk_freq = clk_freq;
        self.reload_count = clk_freq / 100;

        unsafe { control_regs::tmr_tval_write(self.reload_count) };

        let mut ctrl = TimerCtrlFlags::from_bits_truncate(unsafe { control_regs::tmr_ctrl() });
        ctrl.insert(TimerCtrlFlags::ENABLE);
        ctrl.remove(TimerCtrlFlags::IMASK);
        unsafe {
            control_regs::tmr_ctrl_write(ctrl.bits());
        }
    }

    #[allow(unused)]
    fn disable() {
        let mut ctrl = TimerCtrlFlags::from_bits_truncate(unsafe { control_regs::tmr_ctrl() });
        ctrl.remove(TimerCtrlFlags::ENABLE);
        unsafe { control_regs::tmr_ctrl_write(ctrl.bits()) };
    }

    #[allow(unused)]
    pub fn set_irq(&mut self) {
        let mut ctrl = TimerCtrlFlags::from_bits_truncate(unsafe { control_regs::tmr_ctrl() });
        ctrl.remove(TimerCtrlFlags::IMASK);
        unsafe { control_regs::tmr_ctrl_write(ctrl.bits()) };
    }

    pub fn clear_irq(&mut self) {
        let mut ctrl = TimerCtrlFlags::from_bits_truncate(unsafe { control_regs::tmr_ctrl() });

        if ctrl.contains(TimerCtrlFlags::ISTATUS) {
            ctrl.insert(TimerCtrlFlags::IMASK);
            unsafe { control_regs::tmr_ctrl_write(ctrl.bits()) };
        }
    }

    pub fn reload_count(&mut self) {
        let mut ctrl = TimerCtrlFlags::from_bits_truncate(unsafe { control_regs::tmr_ctrl() });
        ctrl.insert(TimerCtrlFlags::ENABLE);
        ctrl.remove(TimerCtrlFlags::IMASK);
        unsafe { control_regs::tmr_tval_write(self.reload_count) };
        unsafe { control_regs::tmr_ctrl_write(ctrl.bits()) };
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
