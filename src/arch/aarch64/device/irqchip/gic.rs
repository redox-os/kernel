use core::ptr::{read_volatile, write_volatile};

use fdt::DeviceTree;

use crate::device::io_mmap;
use syscall::{Result, error::{Error, EINVAL}};

use super::InterruptController;

static GICD_CTLR: u32 = 0x000;
static GICD_TYPER: u32 = 0x004;
static GICD_ISENABLER: u32 = 0x100;
static GICD_ICENABLER: u32 = 0x180;
static GICD_IPRIORITY: u32 = 0x400;
static GICD_ITARGETSR: u32 = 0x800;
static GICD_ICFGR: u32 = 0xc00;

static GICC_EOIR: u32 = 0x0010;
static GICC_IAR: u32 = 0x000c;
static GICC_CTLR: u32 = 0x0000;
static GICC_PMR: u32 = 0x0004;

pub struct GenericInterruptController {
    gic_dist_if: GicDistIf,
    gic_cpu_if: GicCpuIf,
}

impl GenericInterruptController {
    pub fn new() -> Self {
        let gic_dist_if = GicDistIf {
            address: 0,
            ncpus: 0,
            nirqs: 0,
        };
        let gic_cpu_if = GicCpuIf {
            address: 0,
        };

        GenericInterruptController { gic_dist_if, gic_cpu_if }
    }
    pub fn parse(fdt: Option<&DeviceTree>) -> Result<(usize, usize, usize, usize)> {
        match fdt {
            //TODO: remove hard code for qemu-virt
            None => Ok((0x800_0000, 0x1_0000, 0x801_0000, 0x1_0000)),
            Some(dtb) => {
                //TODO: try to parse dtb using stable library
                Err(Error::new(EINVAL))
            }
        }
    }
}

impl InterruptController for GenericInterruptController {
    fn irq_init(&mut self, fdt: Option<&DeviceTree>) -> Result<()> {
        let (dist_addr, dist_size, cpu_addr, cpu_size) =
            GenericInterruptController::parse(fdt).unwrap();

        unsafe {
            //TODO: do kernel memory map using node.ranges

            // Map in the Distributor interface
            io_mmap(dist_addr, dist_size);
            // Map in CPU0's interface
            io_mmap(cpu_addr, cpu_size);

            self.gic_cpu_if.init(cpu_addr);
            self.gic_dist_if.init(dist_addr);

            // Enable CPU0's GIC interface
            self.gic_dist_if.write(GICC_CTLR, 1);
            // Set CPU0's Interrupt Priority Mask
            self.gic_dist_if.write(GICC_PMR, 0xff);

        }
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
}

pub struct GicDistIf {
    pub address: usize,
    pub ncpus: u32,
    pub nirqs: u32,
}

impl GicDistIf {
    unsafe fn init(&mut self, addr: usize) {
        self.address = addr;

        // Disable IRQ Distribution
        self.write(GICD_CTLR, 0);

        let typer = self.read(GICD_TYPER);
        self.ncpus = ((typer & (0x7 << 5)) >> 5) + 1;
        self.nirqs = ((typer & 0x1f) + 1) * 32;
        println!("gic: Distributor supports {:?} CPUs and {:?} IRQs", self.ncpus, self.nirqs);

        // Set all SPIs to level triggered
        for irq in (32..self.nirqs).step_by(16) {
            self.write(GICD_ICFGR + ((irq / 16) * 4), 0);
        }

        // Disable all SPIs
        for irq in (32..self.nirqs).step_by(32) {
            self.write(GICD_ICENABLER + ((irq / 32) * 4), 0xffff_ffff);
        }

        // Affine all SPIs to CPU0 and set priorities for all IRQs
        for irq in 0..self.nirqs {
            if irq > 31 {
                let ext_offset = GICD_ITARGETSR + (4 * (irq / 4));
                let int_offset = irq % 4;
                let mut val = self.read(ext_offset);
                val |= 0b0000_0001 << (8 * int_offset);
                self.write(ext_offset, val);
            }

            let ext_offset = GICD_IPRIORITY + (4 * (irq / 4));
            let int_offset = irq % 4;
            let mut val = self.read(ext_offset);
            val |= 0b0000_0000 << (8 * int_offset);
            self.write(ext_offset, val);
        }

        // Enable IRQ distribution
        self.write(GICD_CTLR, 0x1);
    }

    unsafe fn irq_enable(&mut self, irq: u32) {
        let offset = GICD_ISENABLER + (4 * (irq / 32));
        let shift = 1 << (irq % 32);
        let mut val = self.read(offset);
        val |= shift;
        self.write(offset, val);
    }

    unsafe fn irq_disable(&mut self, irq: u32) {
        let offset = GICD_ICENABLER + (4 * (irq / 32));
        let shift = 1 << (irq % 32);
        let mut val = self.read(offset);
        val |= shift;
        self.write(offset, val);
    }

    unsafe fn read(&self, reg: u32) -> u32 {
        let val = read_volatile((self.address + reg as usize) as *const u32);
        val
    }

    unsafe fn write(&mut self, reg: u32, value: u32) {
        write_volatile((self.address + reg as usize) as *mut u32, value);
    }
}

pub struct GicCpuIf {
    pub address: usize,
}

impl GicCpuIf {
    fn init(&mut self, addr: usize) {
        self.address = addr;
    }

    unsafe fn irq_ack(&mut self) -> u32 {
        let irq = self.read(GICC_IAR) & 0x1ff;
        if irq == 1023 {
            panic!("irq_ack: got ID 1023!!!");
        }
        irq
    }

    unsafe fn irq_eoi(&mut self, irq: u32) {
        self.write(GICC_EOIR, irq);
    }

    unsafe fn read(&self, reg: u32) -> u32 {
        let val = read_volatile((self.address + reg as usize) as *const u32);
        val
    }

    unsafe fn write(&mut self, reg: u32, value: u32) {
        write_volatile((self.address + reg as usize) as *mut u32, value);
    }
}
