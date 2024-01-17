use crate::log::{debug, info};
use alloc::boxed::Box;

use crate::{
    arch::device::irqchip::IRQ_CHIP, context, context::timeout,
    device::cpu::registers::control_regs, dtb::DTB_BINARY, init::device_tree::find_compatible_node,
    interrupt::irq::trigger, time,
};
use alloc::vec::Vec;
use byteorder::{ByteOrder, BE};

use super::irqchip::{register_irq, InterruptHandler};

bitflags! {
    struct TimerCtrlFlags: u32 {
        const ENABLE = 1 << 0;
        const IMASK = 1 << 1;
        const ISTATUS = 1 << 2;
    }
}

pub unsafe fn init() {
    let mut timer = GenericTimer {
        clk_freq: 0,
        reload_count: 0,
    };
    timer.init();
    let data = DTB_BINARY.get().unwrap();
    let fdt = fdt::DeviceTree::new(data).unwrap();
    if let Some(node) = find_compatible_node(&fdt, "arm,armv7-timer") {
        let interrupts = node
            .properties()
            .find(|p| p.name.contains("interrupts"))
            .unwrap();
        let mut intr_data = Vec::new();
        for chunk in interrupts.data.chunks(4) {
            let val = BE::read_u32(chunk);
            intr_data.push(val);
        }
        let mut ic_idx = IRQ_CHIP.irq_chip_list.root_idx;
        if let Some(interrupt_parent) = node
            .properties()
            .find(|p| p.name.contains("interrupt-parent"))
        {
            let phandle = BE::read_u32(interrupt_parent.data);
            let mut i = 0;
            while i < IRQ_CHIP.irq_chip_list.chips.len() {
                let item = &IRQ_CHIP.irq_chip_list.chips[i];
                if item.phandle == phandle {
                    ic_idx = i;
                    break;
                }
                i += 1;
            }
        }
        //PHYS_NONSECURE_PPI only
        let virq = IRQ_CHIP.irq_chip_list.chips[ic_idx]
            .ic
            .irq_xlate(&intr_data, 1)
            .unwrap();
        info!("generic_timer virq = {}", virq);
        register_irq(virq as u32, Box::new(timer));
        IRQ_CHIP.irq_enable(virq as u32);
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

        unsafe {
            trigger(irq);
        }
        self.reload_count();
    }
}
