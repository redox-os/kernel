use alloc::boxed::Box;

use crate::arch::device::irqchip::IRQ_CHIP;
use crate::context::timeout;
use crate::device::cpu::registers::control_regs;
use crate::interrupt::irq::trigger;
use crate::time;
use crate::context;

use super::irqchip::InterruptHandler;
use super::irqchip::register_irq;

bitflags! {
    struct TimerCtrlFlags: u32 {
        const ENABLE = 1 << 0;
        const IMASK = 1 << 1;
        const ISTATUS = 1 << 2;
    }
}

pub unsafe fn init() {
    let mut timer = GenericTimer{ clk_freq: 0, reload_count: 0};
    timer.init();
    //TODO: REMOVE HARD CODE IRQ NUMBER
    register_irq(30, Box::new(timer));
    IRQ_CHIP.irq_enable(30);
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

    fn disable() {
        let mut ctrl = TimerCtrlFlags::from_bits_truncate(unsafe { control_regs::tmr_ctrl() });
        ctrl.remove(TimerCtrlFlags::ENABLE);
        unsafe { control_regs::tmr_ctrl_write(ctrl.bits()) };
    }

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

        unsafe { trigger(irq); }
        self.reload_count();
    }
}
