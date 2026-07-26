use core::sync::atomic::Ordering;
use spin::Once;

use super::{cpu::registers::control_regs, ic_for_chip, irqchip};
use crate::{
    context::{self, timeout},
    dtb::{get_interrupt, irqchip::IRQ_CHIP},
    scheme::irq::irq_trigger,
    sync::CleanLockToken,
    time,
};
use fdt::Fdt;
use syscall::{Error, Result, EINVAL, ENODEV};

bitflags! {
    struct TimerCtrlFlags: u32 {
        const ENABLE = 1 << 0;
        const IMASK = 1 << 1;
        const ISTATUS = 1 << 2;
    }
}

#[derive(Clone, Copy)]
struct TimerConfig {
    use_virtual: bool,
    clk_freq: u32,
    reload_count: u32,
    hwirq: u32,
    virq: u32,
}

static TIMER: Once<TimerConfig> = Once::new();

pub(crate) fn ready() -> bool {
    TIMER.get().is_some()
}

pub unsafe fn init(fdt: &Fdt<'_>) {
    let use_virtual = unsafe { !control_regs::vhe_present() };
    debug!("generic_timer use_virtual_timer = {:?}", use_virtual);

    let clk_freq = unsafe { control_regs::cntfrq_el0() };
    if clk_freq == 0 {
        error!("architected timer reports zero frequency");
        return;
    }

    let Some(node) = fdt.find_compatible(&["arm,armv8-timer", "arm,armv7-timer"]) else {
        error!("architected timer not found in devicetree");
        return;
    };
    let irq_index = if use_virtual { 2 } else { 1 };
    let Some(irq) = get_interrupt(fdt, &node, irq_index) else {
        error!("architected timer is missing interrupt index {}", irq_index);
        return;
    };
    debug!("architected timer irq = {:?}", irq);

    let Some(ic_idx) = ic_for_chip(fdt, &node) else {
        error!("failed to find interrupt parent for architected timer");
        return;
    };
    let Ok(virq) = (unsafe { IRQ_CHIP.irq_chip_list.chips[ic_idx].ic.irq_xlate(irq) }) else {
        error!("failed to translate architected timer interrupt");
        return;
    };
    let Some(desc) = (unsafe { IRQ_CHIP.irq_desc.get(virq) }) else {
        error!(
            "architected timer virq {} is outside the descriptor table",
            virq
        );
        return;
    };

    let config = TimerConfig {
        use_virtual,
        clk_freq,
        reload_count: clk_freq / 100,
        hwirq: desc.basic.ic_irq,
        virq: virq as u32,
    };
    if config.reload_count == 0 {
        error!("architected timer frequency is too low");
        return;
    }

    info!(
        "architected timer virq = {} ({})",
        virq,
        if use_virtual {
            "virtual"
        } else {
            "non-secure physical"
        }
    );
    let config = TIMER.call_once(|| config);
    program_current(config);
    unsafe { IRQ_CHIP.irq_enable(config.virq) };
}

pub unsafe fn init_acpi(gsiv: u32) {
    let use_virtual = unsafe { !control_regs::vhe_present() };
    let clk_freq = unsafe { control_regs::cntfrq_el0() };
    if clk_freq == 0 {
        error!("architected timer reports zero frequency");
        return;
    }
    let config = TIMER.call_once(|| TimerConfig {
        use_virtual,
        clk_freq,
        reload_count: clk_freq / 100,
        hwirq: gsiv,
        virq: gsiv,
    });
    program_current(config);
    unsafe { IRQ_CHIP.irq_enable(config.virq) };
}

pub(crate) fn init_ap() -> Result<()> {
    let config = TIMER.get().ok_or_else(|| Error::new(ENODEV))?;
    if unsafe { control_regs::cntfrq_el0() } != config.clk_freq {
        return Err(Error::new(EINVAL));
    }
    program_current(config);
    irqchip::enable_local_irq(config.hwirq)
}

/// Consume one local timer interrupt while an AP is still booting.
///
/// This deliberately avoids the scheduler-facing timer handler: the AP does
/// not have a current context until after the boot handshake completes.
pub(crate) fn complete_ap_self_test(hwirq: u32, raw_iar: u32) -> bool {
    let Some(config) = TIMER.get().filter(|config| config.hwirq == hwirq) else {
        return false;
    };
    if !read_ctrl(config).contains(TimerCtrlFlags::ISTATUS) {
        return false;
    }

    let mut ctrl = read_ctrl(config);
    ctrl.insert(TimerCtrlFlags::IMASK);
    write_ctrl(config, ctrl);
    irqchip::end_root(raw_iar);
    program_current(config);
    true
}

fn read_ctrl(config: &TimerConfig) -> TimerCtrlFlags {
    TimerCtrlFlags::from_bits_truncate(if config.use_virtual {
        unsafe { control_regs::vtmr_ctrl() }
    } else {
        unsafe { control_regs::ptmr_ctrl() }
    })
}

fn write_ctrl(config: &TimerConfig, ctrl: TimerCtrlFlags) {
    if config.use_virtual {
        unsafe { control_regs::vtmr_ctrl_write(ctrl.bits()) };
    } else {
        unsafe { control_regs::ptmr_ctrl_write(ctrl.bits()) };
    }
}

fn program_current(config: &TimerConfig) {
    if config.use_virtual {
        unsafe { control_regs::vtmr_tval_write(config.reload_count) };
    } else {
        unsafe { control_regs::ptmr_tval_write(config.reload_count) };
    }
    let mut ctrl = read_ctrl(config);
    ctrl.insert(TimerCtrlFlags::ENABLE);
    ctrl.remove(TimerCtrlFlags::IMASK);
    write_ctrl(config, ctrl);
}

pub(crate) fn handle(hwirq: u32, raw_iar: u32, token: &mut CleanLockToken) -> bool {
    let Some(config) = TIMER.get().filter(|config| config.hwirq == hwirq) else {
        return false;
    };

    let mut ctrl = read_ctrl(config);
    if ctrl.contains(TimerCtrlFlags::ISTATUS) {
        ctrl.insert(TimerCtrlFlags::IMASK);
        write_ctrl(config, ctrl);
    }

    let cpu_id = crate::cpu_id();
    if cpu_id != crate::cpu_set::LogicalCpuId::BSP
        && !crate::percpu::PercpuBlock::current()
            .misc_arch_info
            .timer_irq_seen
            .swap(true, Ordering::AcqRel)
    {
        info!("CPU logical {}: timer IRQ path active", cpu_id);
    }

    if cpu_id == crate::cpu_set::LogicalCpuId::BSP {
        *time::OFFSET.write(token.token()) += config.clk_freq as u128;
    }

    // The GIC CPU interface is local to the CPU which acknowledged this
    // interrupt. Complete it and re-arm the local timer before tick() can
    // switch to a context which may subsequently resume on another CPU.
    irqchip::end_root(raw_iar);
    program_current(config);

    if cpu_id == crate::cpu_set::LogicalCpuId::BSP {
        timeout::trigger(token);

        if let Ok(irq) = u8::try_from(config.virq) {
            irq_trigger(irq, token);
        }
    }
    context::switch::tick(token);
    true
}
