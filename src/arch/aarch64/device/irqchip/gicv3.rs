use alloc::vec::Vec;
use core::arch::asm;
use fdt::{node::NodeProperty, Fdt};

use super::{gic::GicDistIf, InterruptController};
use crate::dtb::irqchip::{InterruptHandler, IrqDesc};
use syscall::{
    error::{Error, EINVAL},
    Result,
};

#[derive(Debug)]
pub struct GicV3 {
    pub gic_dist_if: GicDistIf,
    pub gic_cpu_if: GicV3CpuIf,
    pub gicrs: Vec<(usize, usize)>,
    //TODO: GICC, GICH, GICV?
    pub irq_range: (usize, usize),
}

impl GicV3 {
    pub fn new() -> Self {
        GicV3 {
            gic_dist_if: GicDistIf::default(),
            gic_cpu_if: GicV3CpuIf,
            gicrs: Vec::new(),
            irq_range: (0, 0),
        }
    }

    pub fn parse(&mut self, fdt: &Fdt) -> Result<()> {
        let Some(node) = fdt.find_compatible(&["arm,gic-v3"]) else {
            return Err(Error::new(EINVAL));
        };

        // Clear current registers
        //TODO: deinit?
        self.gic_dist_if.address = 0;
        self.gicrs.clear();

        // Get number of GICRs
        let gicrs = node
            .property("#redistributor-regions")
            .and_then(NodeProperty::as_usize)
            .unwrap_or(1);

        // Read registers
        let mut chunks = node.reg().unwrap();
        if let Some(gicd) = chunks.next() {
            unsafe {
                self.gic_dist_if
                    .init(crate::PHYS_OFFSET + gicd.starting_address as usize);
            }
        }
        for _ in 0..gicrs {
            if let Some(gicr) = chunks.next() {
                self.gicrs
                    .push((gicr.starting_address as usize, gicr.size.unwrap()));
            }
        }

        if self.gic_dist_if.address == 0 || self.gicrs.is_empty() {
            Err(Error::new(EINVAL))
        } else {
            Ok(())
        }
    }
}

impl InterruptHandler for GicV3 {
    fn irq_handler(&mut self, _irq: u32) {}
}

impl InterruptController for GicV3 {
    fn irq_init(
        &mut self,
        fdt_opt: Option<&Fdt>,
        irq_desc: &mut [IrqDesc; 1024],
        ic_idx: usize,
        irq_idx: &mut usize,
    ) -> Result<()> {
        if let Some(fdt) = fdt_opt {
            self.parse(fdt)?;
        }
        log::info!("{:X?}", self);

        unsafe {
            self.gic_cpu_if.init();
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

        log::info!("gic irq_range = ({}, {})", idx, idx + cnt);
        self.irq_range = (idx, idx + cnt);
        *irq_idx = idx + cnt;
        Ok(())
    }
    fn irq_ack(&mut self) -> u32 {
        let irq_num = unsafe { self.gic_cpu_if.irq_ack() };
        irq_num
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
    fn irq_xlate(&self, irq_data: &[u32; 3]) -> Result<usize> {
        let mut off = match irq_data[0] {
            0 => irq_data[1] as usize + 32, //SPI
            1 => irq_data[1] as usize + 16, //PPI,
            _ => return Err(Error::new(EINVAL)),
        };
        off += self.irq_range.0;
        return Ok(off);
    }
    fn irq_to_virq(&self, hwirq: u32) -> Option<usize> {
        if hwirq >= self.gic_dist_if.nirqs {
            None
        } else {
            Some(self.irq_range.0 + hwirq as usize)
        }
    }
}

#[derive(Debug)]
pub struct GicV3CpuIf;

impl GicV3CpuIf {
    pub unsafe fn init(&mut self) {
        // Enable system register access
        {
            let value = 1_usize;
            asm!("msr icc_sre_el1, {}", in(reg) value);
        }
        // Set control register
        {
            let value = 0_usize;
            asm!("msr icc_ctlr_el1, {}", in(reg) value);
        }
        // Enable non-secure group 1
        {
            let value = 1_usize;
            asm!("msr icc_igrpen1_el1, {}", in(reg) value);
        }
        // Set CPU0's Interrupt Priority Mask
        {
            let value = 0xFF_usize;
            asm!("msr icc_pmr_el1, {}", in(reg) value);
        }
    }

    unsafe fn irq_ack(&mut self) -> u32 {
        let mut irq: usize;
        asm!("mrs {}, icc_iar1_el1", out(reg) irq);
        irq &= 0x1ff;
        if irq == 1023 {
            panic!("irq_ack: got ID 1023!!!");
        }
        irq as u32
    }

    unsafe fn irq_eoi(&mut self, irq: u32) {
        asm!("msr icc_eoir1_el1, {}", in(reg) irq as usize);
    }
}
