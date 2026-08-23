use super::InterruptController;
use crate::{
    dtb::{
        irqchip::{InterruptHandler, IrqCell, IrqDesc},
        translate_mmio_address,
    },
    sync::CleanLockToken,
};
use core::{
    ptr::{read_volatile, write_volatile},
    sync::atomic::{AtomicUsize, Ordering},
};
use fdt::{node::FdtNode, Fdt};
use syscall::{
    error::{Error, EINVAL},
    Result,
};

static GICD_CTLR: u32 = 0x000;
static GICD_TYPER: u32 = 0x004;
static GICD_ISENABLER: u32 = 0x100;
static GICD_ICENABLER: u32 = 0x180;
static GICD_ICPENDR: u32 = 0x280;
static GICD_ICACTIVER: u32 = 0x380;
static GICD_IPRIORITY: u32 = 0x400;
static GICD_ITARGETSR: u32 = 0x800;
static GICD_ICFGR: u32 = 0xc00;
static GICD_SGIR: u32 = 0xf00;

static GICC_EOIR: u32 = 0x0010;
static GICC_IAR: u32 = 0x000c;
static GICC_CTLR: u32 = 0x0000;
static GICC_PMR: u32 = 0x0004;
static GICC_BPR: u32 = 0x0008;

static GICD_BASE: AtomicUsize = AtomicUsize::new(0);
static GICC_BASE: AtomicUsize = AtomicUsize::new(0);
static GIC_IRQ_BASE: AtomicUsize = AtomicUsize::new(0);
static GIC_CPU_CAPACITY: AtomicUsize = AtomicUsize::new(0);

fn read32(base: usize, offset: u32) -> u32 {
    unsafe { read_volatile((base + offset as usize) as *const u32) }
}

fn write32(base: usize, offset: u32, value: u32) {
    unsafe { write_volatile((base + offset as usize) as *mut u32, value) }
}

fn read_current_cpu_target_mask(dist: usize) -> u8 {
    // GICD_ITARGETSR0-7 are banked and read-only for SGIs/PPIs. Fold each
    // word into one byte and scan all eight registers, as some implementations
    // do not expose a useful value in ITARGETSR0 itself.
    for offset in (0..32).step_by(4) {
        let mut mask = read32(dist, GICD_ITARGETSR + offset);
        mask |= mask >> 16;
        mask |= mask >> 8;
        let mask = mask as u8;
        if mask.is_power_of_two() {
            return mask;
        }
    }
    0
}

pub(crate) fn active() -> bool {
    GICD_BASE.load(Ordering::Acquire) != 0 && GICC_BASE.load(Ordering::Acquire) != 0
}

pub(crate) fn cpu_capacity() -> Option<usize> {
    let count = GIC_CPU_CAPACITY.load(Ordering::Acquire);
    (count != 0).then_some(count)
}

pub(crate) fn current_cpu_target_mask() -> Option<u8> {
    let target_mask = crate::percpu::PercpuBlock::current()
        .misc_arch_info
        .gic_target_mask
        .load(Ordering::Acquire);
    (target_mask != 0).then_some(target_mask)
}

pub(crate) fn init_current_cpu() -> Result<()> {
    let dist = GICD_BASE.load(Ordering::Acquire);
    let cpu = GICC_BASE.load(Ordering::Acquire);
    if dist == 0 || cpu == 0 {
        return Err(Error::new(EINVAL));
    }

    write32(cpu, GICC_CTLR, 0);
    write32(cpu, GICC_BPR, 0);
    // Match Linux gic_cpu_config(): reset the banked SGI/PPI state before
    // enabling the local CPU interface. Firmware can leave a private
    // interrupt pending or active across CPU_ON, which would otherwise make
    // the first timer/SGI delivery unreliable.
    write32(dist, GICD_ICENABLER, 0xffff_ffff);
    write32(dist, GICD_ICPENDR, 0xffff_ffff);
    write32(dist, GICD_ICACTIVER, 0xffff_ffff);
    for irq in (0..32).step_by(4) {
        write32(dist, GICD_IPRIORITY + irq, 0xa0a0_a0a0);
    }
    write32(cpu, GICC_PMR, 0xff);
    unsafe { core::arch::asm!("dsb sy", options(nostack, preserves_flags)) };
    write32(cpu, GICC_CTLR, 1);

    // On a uniprocessor GIC the target registers may be RAZ/WI, so zero is
    // valid until directed SGIs are needed.
    let target_mask = read_current_cpu_target_mask(dist);
    crate::percpu::PercpuBlock::current()
        .misc_arch_info
        .gic_target_mask
        .store(target_mask, Ordering::Release);
    Ok(())
}

pub(crate) fn enable_local_irq(hwirq: u32) -> Result<()> {
    let dist = GICD_BASE.load(Ordering::Acquire);
    if dist == 0 || hwirq >= 32 {
        return Err(Error::new(EINVAL));
    }
    write32(dist, GICD_ISENABLER + 4 * (hwirq / 32), 1 << (hwirq % 32));
    Ok(())
}

pub(crate) fn acknowledge_local() -> Option<u32> {
    let cpu = GICC_BASE.load(Ordering::Acquire);
    (cpu != 0).then(|| read32(cpu, GICC_IAR))
}

pub(crate) fn end_local(raw_iar: u32) -> bool {
    let cpu = GICC_BASE.load(Ordering::Acquire);
    if cpu == 0 {
        return false;
    }
    write32(cpu, GICC_EOIR, raw_iar);
    true
}

pub(crate) fn virq_for(raw_iar: u32) -> Option<usize> {
    let hwirq = raw_iar & 0x3ff;
    (hwirq < 1020).then(|| GIC_IRQ_BASE.load(Ordering::Acquire) + hwirq as usize)
}

pub(crate) fn send_sgi(sgi: u8, target_mask: Option<u8>) -> Result<()> {
    if sgi >= 16 {
        return Err(Error::new(EINVAL));
    }
    let dist = GICD_BASE.load(Ordering::Acquire);
    if dist == 0 {
        return Err(Error::new(EINVAL));
    }

    let value = match target_mask {
        Some(0) => return Err(Error::new(EINVAL)),
        Some(mask) => u32::from(mask) << 16,
        // Target list filter 1 sends to all CPU interfaces except this one.
        None => 1 << 24,
    } | u32::from(sgi);
    unsafe { core::arch::asm!("dsb ishst", options(nostack, preserves_flags)) };
    write32(dist, GICD_SGIR, value);
    Ok(())
}

pub struct GenericInterruptController {
    pub gic_dist_if: GicDistIf,
    pub gic_cpu_if: GicCpuIf,
    pub irq_range: (usize, usize),
}

impl GenericInterruptController {
    pub fn new() -> Self {
        let gic_dist_if = GicDistIf::default();
        let gic_cpu_if = GicCpuIf::default();

        GenericInterruptController {
            gic_dist_if,
            gic_cpu_if,
            irq_range: (0, 0),
        }
    }
    pub fn parse(fdt: &Fdt) -> Result<(usize, usize, usize, usize)> {
        if let Some(node) = fdt.find_compatible(&["arm,cortex-a15-gic", "arm,gic-400"]) {
            return GenericInterruptController::parse_inner(fdt, &node);
        } else {
            return Err(Error::new(EINVAL));
        }
    }
    fn parse_inner(fdt: &Fdt, node: &FdtNode) -> Result<(usize, usize, usize, usize)> {
        //assert address_cells == 0x2, size_cells == 0x2
        let reg = node.reg().unwrap();
        let mut regs = (0, 0, 0, 0);
        let mut idx = 0;

        for chunk in reg {
            if chunk.size.is_none() {
                break;
            }
            let addr = translate_mmio_address(fdt, node, &chunk).unwrap();
            match idx {
                0 => (regs.0, regs.1) = (addr, chunk.size.unwrap()),
                2 => (regs.2, regs.3) = (addr, chunk.size.unwrap()),
                _ => break,
            }
            idx += 2;
        }

        if idx == 4 {
            Ok(regs)
        } else {
            Err(Error::new(EINVAL))
        }
    }
}

impl InterruptHandler for GenericInterruptController {
    fn irq_handler(&mut self, _irq: u32, token: &mut CleanLockToken) {}
}

impl InterruptController for GenericInterruptController {
    fn irq_init(
        &mut self,
        fdt_opt: Option<&Fdt>,
        irq_desc: &mut [IrqDesc; 1024],
        ic_idx: usize,
        irq_idx: &mut usize,
    ) -> Result<()> {
        if let Some(fdt) = fdt_opt {
            let (dist_addr, _dist_size, cpu_addr, _cpu_size) =
                match GenericInterruptController::parse(fdt) {
                    Ok(regs) => regs,
                    Err(err) => return Err(err),
                };

            unsafe {
                self.gic_dist_if.init(crate::PHYS_OFFSET + dist_addr);
                self.gic_cpu_if.init(crate::PHYS_OFFSET + cpu_addr);
            }
        }
        let idx = *irq_idx;
        let cnt = if self.gic_dist_if.nirqs > 1024 {
            1024
        } else {
            self.gic_dist_if.nirqs as usize
        };
        let mut i: usize = 0;
        //only support linear irq map now.
        while i < cnt && (idx + i < 1024) {
            irq_desc[idx + i].basic.ic_idx = ic_idx;
            irq_desc[idx + i].basic.ic_irq = i as u32;
            irq_desc[idx + i].basic.used = true;

            i += 1;
        }

        info!("gic irq_range = ({}, {})", idx, idx + cnt);
        self.irq_range = (idx, idx + cnt);
        GIC_IRQ_BASE.store(idx, Ordering::Release);
        *irq_idx = idx + cnt;
        init_current_cpu()?;
        Ok(())
    }
    fn irq_ack(&mut self) -> u32 {
        unsafe { self.gic_cpu_if.irq_ack() }
    }
    fn irq_eoi(&mut self, irq_num: u32) {
        unsafe { self.gic_cpu_if.irq_eoi(irq_num) }
    }
    fn irq_enable(&mut self, irq_num: u32) {
        unsafe { self.gic_dist_if.irq_enable(irq_num) }
    }
    fn irq_disable(&mut self, irq_num: u32) {
        unsafe { self.gic_dist_if.irq_disable(irq_num) }
    }
    fn irq_configure(&mut self, irq_data: IrqCell) -> Result<()> {
        let (irq, flags) = match irq_data {
            IrqCell::L3(0, irq, flags) => (irq, flags), // SPI
            _ => return Err(Error::new(EINVAL)),
        };
        let hwirq = irq.checked_add(32).ok_or_else(|| Error::new(EINVAL))?;
        unsafe { self.gic_dist_if.irq_configure(hwirq, flags) }
    }
    fn irq_xlate(&self, irq_data: IrqCell) -> Result<usize> {
        let off = match irq_data {
            IrqCell::L3(0, irq, _flags) => irq as usize + 32, // SPI
            IrqCell::L3(1, irq, _flags) => irq as usize + 16, // PPI
            _ => return Err(Error::new(EINVAL)),
        };
        return Ok(off + self.irq_range.0);
    }
    fn irq_to_virq(&self, hwirq: u32) -> Option<usize> {
        let hwirq = hwirq & 0x3ff;
        if hwirq >= self.gic_dist_if.nirqs {
            None
        } else {
            Some(self.irq_range.0 + hwirq as usize)
        }
    }
}

#[derive(Debug, Default)]
pub struct GicDistIf {
    pub address: usize,
    pub ncpus: u32,
    pub nirqs: u32,
}

impl GicDistIf {
    pub unsafe fn init(&mut self, addr: usize) {
        unsafe {
            self.address = addr;
            GICD_BASE.store(addr, Ordering::Release);

            // Disable IRQ Distribution
            self.write(GICD_CTLR, 0);

            let typer = self.read(GICD_TYPER);
            self.ncpus = ((typer & (0x7 << 5)) >> 5) + 1;
            GIC_CPU_CAPACITY.store(self.ncpus as usize, Ordering::Release);
            self.nirqs = ((typer & 0x1f) + 1) * 32;
            info!(
                "gic: Distributor supports {:?} CPUs and {:?} IRQs",
                self.ncpus, self.nirqs
            );
            let target_mask = read_current_cpu_target_mask(addr);
            if target_mask == 0 && self.ncpus > 1 {
                warn!("GICv2 did not expose the boot CPU target mask; SMP will remain disabled");
            }

            // Set all SPIs to level triggered
            for irq in (32..self.nirqs).step_by(16) {
                self.write(GICD_ICFGR + ((irq / 16) * 4), 0);
            }

            // Disable all SPIs
            for irq in (32..self.nirqs).step_by(32) {
                self.write(GICD_ICENABLER + ((irq / 32) * 4), 0xffff_ffff);
            }

            // When the mapping is available, keep every shared interrupt on
            // the BSP. Write the complete target field instead of preserving
            // firmware targets that could also deliver an SPI to an AP.
            let target_word = (target_mask != 0).then_some(u32::from(target_mask) * 0x0101_0101);
            for irq in (32..self.nirqs).step_by(4) {
                // If the mapping is unavailable, preserve the firmware target
                // configuration so the safe single-CPU fallback can still
                // receive device interrupts.
                if let Some(target_word) = target_word {
                    self.write(GICD_ITARGETSR + irq, target_word);
                }
                self.write(GICD_IPRIORITY + irq, 0xa0a0_a0a0);
            }

            // Enable IRQ group 0 and group 1 non-secure distribution
            self.write(GICD_CTLR, 0x3);
        }
    }

    pub unsafe fn irq_enable(&mut self, irq: u32) {
        unsafe {
            let offset = GICD_ISENABLER + (4 * (irq / 32));
            let shift = 1 << (irq % 32);
            let mut val = self.read(offset);
            val |= shift;
            self.write(offset, val);
        }
    }

    pub unsafe fn irq_disable(&mut self, irq: u32) {
        unsafe {
            let offset = GICD_ICENABLER + (4 * (irq / 32));
            let shift = 1 << (irq % 32);
            let mut val = self.read(offset);
            val |= shift;
            self.write(offset, val);
        }
    }

    pub unsafe fn irq_configure(&mut self, irq: u32, flags: u32) -> Result<()> {
        // GIC SPIs support level-sensitive or edge-triggered signaling.
        // Devicetree flags for active-low or falling-edge signaling cannot be
        // represented directly by this GIC configuration and are rejected.
        let edge = match flags & 0xf {
            1 => true,  // IRQ_TYPE_EDGE_RISING
            4 => false, // IRQ_TYPE_LEVEL_HIGH
            _ => return Err(Error::new(EINVAL)),
        };
        if irq < 32 || irq >= self.nirqs {
            return Err(Error::new(EINVAL));
        }

        unsafe {
            let offset = GICD_ICFGR + ((irq / 16) * 4);
            let shift = (irq % 16) * 2;
            let mut value = self.read(offset);
            value &= !(0b11 << shift);
            if edge {
                value |= 0b10 << shift;
            }
            self.write(offset, value);
        }
        Ok(())
    }

    unsafe fn read(&self, reg: u32) -> u32 {
        unsafe {
            let val = read_volatile((self.address + reg as usize) as *const u32);
            val
        }
    }

    unsafe fn write(&mut self, reg: u32, value: u32) {
        unsafe {
            write_volatile((self.address + reg as usize) as *mut u32, value);
        }
    }
}

#[derive(Debug, Default)]
pub struct GicCpuIf {
    pub address: usize,
}

impl GicCpuIf {
    pub unsafe fn init(&mut self, addr: usize) {
        unsafe {
            self.address = addr;
            GICC_BASE.store(addr, Ordering::Release);

            // Enable CPU0's GIC interface
            self.write(GICC_CTLR, 1);
            // Set CPU0's Interrupt Priority Mask
            self.write(GICC_PMR, 0xff);
        }
    }

    unsafe fn irq_ack(&mut self) -> u32 {
        unsafe {
            let irq = self.read(GICC_IAR);
            if irq & 0x3ff == 1023 {
                panic!("irq_ack: got ID 1023!!!");
            }
            irq
        }
    }

    unsafe fn irq_eoi(&mut self, irq: u32) {
        unsafe {
            self.write(GICC_EOIR, irq);
        }
    }

    unsafe fn read(&self, reg: u32) -> u32 {
        unsafe {
            let val = read_volatile((self.address + reg as usize) as *const u32);
            val
        }
    }

    unsafe fn write(&mut self, reg: u32, value: u32) {
        unsafe {
            write_volatile((self.address + reg as usize) as *mut u32, value);
        }
    }
}
