use crate::arch::device::gic;
use crate::device::cpu::registers::{control_regs};

bitflags! {
    struct TimerCtrlFlags: u32 {
        const ENABLE = 1 << 0;
        const IMASK = 1 << 1;
        const ISTATUS = 1 << 2;
    }
}

pub static mut GENTIMER: GenericTimer = GenericTimer {
    clk_freq: 0,
    reload_count: 0,
};

pub unsafe fn init() {
    GENTIMER.init();
}

/*
pub unsafe fn clear_irq() {
    GENTIMER.clear_irq();
}

pub unsafe fn reload() {
    GENTIMER.reload_count();
}
*/

pub struct GenericTimer {
    pub clk_freq: u32,
    pub reload_count: u32,
}

impl GenericTimer {
    pub fn init(&mut self) {
        let clk_freq = unsafe { control_regs::cntfreq_el0() };
        self.clk_freq = clk_freq;;
        self.reload_count = clk_freq / 100;

        unsafe { control_regs::tmr_tval_write(self.reload_count) };

        let mut ctrl = TimerCtrlFlags::from_bits_truncate(unsafe { control_regs::tmr_ctrl() });
        ctrl.insert(TimerCtrlFlags::ENABLE);
        ctrl.remove(TimerCtrlFlags::IMASK);
        unsafe { control_regs::tmr_ctrl_write(ctrl.bits()) };

        gic::irq_enable(30);
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
