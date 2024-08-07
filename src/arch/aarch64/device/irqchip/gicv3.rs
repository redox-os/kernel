use alloc::vec::Vec;
use core::{
    arch::asm,
    ptr::{read_volatile, write_volatile},
};

use byteorder::{ByteOrder, BE};
use fdt::{DeviceTree, Node};

use super::gic::GicDistIf;
use crate::init::device_tree::find_compatible_node;
use log::{debug, info};
use syscall::{
    error::{Error, EINVAL},
    Result,
};

use super::{InterruptController, IrqDesc};

#[derive(Debug)]
pub struct GicV3 {
    gic_dist_if: GicDistIf,
    gic_cpu_if: GicV3CpuIf,
    gicrs: Vec<(usize, usize)>,
    //TODO: GICC, GICH, GICV?
    irq_range: (usize, usize),
}

impl GicV3 {
    pub fn new() -> Self {
        GicV3 {
            gic_dist_if: GicDistIf {
                address: 0,
                ncpus: 0,
                nirqs: 0,
            },
            gic_cpu_if: GicV3CpuIf,
            gicrs: Vec::new(),
            irq_range: (0, 0),
        }
    }

    pub fn parse(&mut self, fdt: &DeviceTree) -> Result<()> {
        let Some(node) = find_compatible_node(fdt, "arm,gic-v3") else {
            return Err(Error::new(EINVAL));
        };

        // Clear current registers
        //TODO: deinit?
        self.gic_dist_if.address = 0;
        self.gicrs.clear();

        // Get number of GICRs
        let gicrs = match node
            .properties()
            .find(|p| p.name.contains("#redistributor-regions"))
        {
            Some(prop) => BE::read_u32(prop.data),
            None => 1,
        };

        // Read registers
        let reg = node.properties().find(|p| p.name.contains("reg")).unwrap();
        let mut chunks = reg.data.chunks_exact(16).map(|chunk| {
            (
                BE::read_u64(&chunk[0..8]) as usize,
                BE::read_u64(&chunk[8..16]) as usize,
            )
        });
        if let Some((gicd_addr, _gicd_size)) = chunks.next() {
            unsafe {
                self.gic_dist_if.init(crate::PHYS_OFFSET + gicd_addr);
            }
        }
        for _ in 0..gicrs {
            if let Some(gicr) = chunks.next() {
                self.gicrs.push(gicr);
            }
        }

        if self.gic_dist_if.address == 0 || self.gicrs.is_empty() {
            Err(Error::new(EINVAL))
        } else {
            Ok(())
        }
    }
}

impl InterruptController for GicV3 {
    fn irq_init(
        &mut self,
        fdt: &DeviceTree,
        irq_desc: &mut [IrqDesc; 1024],
        ic_idx: usize,
        irq_idx: &mut usize,
    ) -> Result<Option<usize>> {
        self.parse(fdt)?;
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

        info!("gic irq_range = ({}, {})", idx, idx + cnt);
        self.irq_range = (idx, idx + cnt);
        *irq_idx = idx + cnt;
        Ok(None)
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
    fn irq_xlate(&mut self, irq_data: &[u32], idx: usize) -> Result<usize> {
        let mut off: usize = 0;
        let mut i = 0;
        for chunk in irq_data.chunks(3) {
            if i == idx {
                match chunk[0] {
                    0 => off = chunk[1] as usize + 32, //SPI
                    1 => off = chunk[1] as usize + 16, //PPI,
                    _ => return Err(Error::new(EINVAL)),
                }
                off += self.irq_range.0;
                return Ok(off);
            }
            i += 1;
        }
        Err(Error::new(EINVAL))
    }
    fn irq_to_virq(&mut self, hwirq: u32) -> Option<usize> {
        if hwirq >= self.gic_dist_if.nirqs {
            None
        } else {
            Some(self.irq_range.0 + hwirq as usize)
        }
    }

    fn irq_handler(&mut self, _irq: u32) {}
}

#[derive(Debug)]
pub struct GicV3CpuIf;

impl GicV3CpuIf {
    unsafe fn init(&mut self) {
        // Enable system register access
        {
            let value = 1;
            asm!("msr icc_sre_el1, {}", in(reg) value);
        }
        // Set control register
        {
            let value = 0;
            asm!("msr icc_ctlr_el1, {}", in(reg) value);
        }
        // Enable non-secure group 1
        {
            let value = 1;
            asm!("msr icc_igrpen1_el1, {}", in(reg) value);
        }
        // Set CPU0's Interrupt Priority Mask
        {
            let value = 0xFF;
            asm!("msr icc_pmr_el1, {}", in(reg) value);
        }
    }

    unsafe fn irq_ack(&mut self) -> u32 {
        let mut irq;
        asm!("mrs {}, icc_iar1_el1", out(reg) irq);
        irq &= 0x1ff;
        if irq == 1023 {
            panic!("irq_ack: got ID 1023!!!");
        }
        irq
    }

    unsafe fn irq_eoi(&mut self, irq: u32) {
        asm!("msr icc_eoir1_el1, {}", in(reg) irq);
    }
}
