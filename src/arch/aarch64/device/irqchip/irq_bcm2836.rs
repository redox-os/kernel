use super::InterruptController;
use crate::dtb::irqchip::{InterruptHandler, IrqDesc};
use core::{
    arch::asm,
    ptr::{read_volatile, write_volatile},
};
use fdt::{node::FdtNode, Fdt};
use log::{debug, info};
use syscall::{
    error::{Error, EINVAL},
    Result,
};

const LOCAL_CONTROL: u32 = 0x000;
const LOCAL_PRESCALER: u32 = 0x008;
const LOCAL_GPU_ROUTING: u32 = 0x00C;
const LOCAL_TIMER_INT_CONTROL0: u32 = 0x040;
const LOCAL_IRQ_PENDING: u32 = 0x060;

const LOCAL_IRQ_CNTPNSIRQ: u32 = 0x1;
const LOCAL_IRQ_GPU_FAST: u32 = 0x8;
const LOCAL_IRQ_PMU_FAST: u32 = 0x9;
const LOCAL_IRQ_LAST: u32 = LOCAL_IRQ_PMU_FAST;

#[inline(always)]
fn ffs(num: u32) -> u32 {
    let mut x = num;
    if x == 0 {
        return 0;
    }
    let mut r = 1;
    if (x & 0xffff) == 0 {
        x >>= 16;
        r += 16;
    }
    if (x & 0xff) == 0 {
        x >>= 8;
        r += 8;
    }
    if (x & 0xf) == 0 {
        x >>= 4;
        r += 4;
    }
    if (x & 0x3) == 0 {
        x >>= 2;
        r += 2;
    }
    if (x & 0x1) == 0 {
        r += 1;
    }

    r
}

pub struct Bcm2836ArmInterruptController {
    pub address: usize,
    pub irq_range: (usize, usize),
    pub active_cpu: u32,
}

impl Bcm2836ArmInterruptController {
    pub fn new() -> Self {
        Bcm2836ArmInterruptController {
            address: 0,
            irq_range: (0, 0),
            active_cpu: 0,
        }
    }
    pub fn parse(fdt: &Fdt) -> Result<(usize, usize)> {
        if let Some(node) = fdt.find_compatible(&["brcm,bcm2836-l1-intc"]) {
            return Bcm2836ArmInterruptController::parse_inner(&node);
        } else {
            return Err(Error::new(EINVAL));
        }
    }
    fn parse_inner(node: &FdtNode) -> Result<(usize, usize)> {
        //assert address_cells == 0x1, size_cells == 0x1
        let reg = node.reg().unwrap().nth(0).unwrap();

        Ok((reg.starting_address as usize, reg.size.unwrap()))
    }

    unsafe fn init(&mut self) {
        debug!("IRQ BCM2836 INIT");
        //init local timer freq
        self.write(LOCAL_CONTROL, 0x0);
        self.write(LOCAL_PRESCALER, 0x8000_0000);

        //routing all irq to core
        self.write(LOCAL_GPU_ROUTING, self.active_cpu);
        debug!("routing all irq to core {}", self.active_cpu);
        debug!("IRQ BCM2836 END");
    }

    unsafe fn read(&self, reg: u32) -> u32 {
        let val = read_volatile((self.address + reg as usize) as *const u32);
        val
    }

    unsafe fn write(&mut self, reg: u32, value: u32) {
        write_volatile((self.address + reg as usize) as *mut u32, value);
    }
}

impl InterruptHandler for Bcm2836ArmInterruptController {
    fn irq_handler(&mut self, _irq: u32) {}
}

impl InterruptController for Bcm2836ArmInterruptController {
    fn irq_init(
        &mut self,
        fdt_opt: Option<&Fdt>,
        irq_desc: &mut [IrqDesc; 1024],
        ic_idx: usize,
        irq_idx: &mut usize,
    ) -> Result<()> {
        let (base, _size) = match Bcm2836ArmInterruptController::parse(fdt_opt.unwrap()) {
            Ok((a, b)) => (a, b),
            Err(_) => return Err(Error::new(EINVAL)),
        };
        unsafe {
            self.address = base + crate::PHYS_OFFSET;
            let cpuid: usize;
            asm!("mrs {}, mpidr_el1", out(reg) cpuid);
            self.active_cpu = cpuid as u32 & 0x3;

            self.init();
            let idx = *irq_idx;
            let cnt = LOCAL_IRQ_LAST as usize;
            let mut i: usize = 0;
            //only support linear irq map now.
            while i < cnt && (idx + i < 1024) {
                irq_desc[idx + i].basic.ic_idx = ic_idx;
                irq_desc[idx + i].basic.ic_irq = i as u32;
                irq_desc[idx + i].basic.used = true;

                i += 1;
            }

            info!("bcm2836 irq_range = ({}, {})", idx, idx + cnt);
            self.irq_range = (idx, idx + cnt);
            *irq_idx = idx + cnt;
        }

        Ok(())
    }

    fn irq_ack(&mut self) -> u32 {
        let cpuid: usize;
        unsafe {
            asm!("mrs {}, mpidr_el1", out(reg) cpuid);
        }
        let cpu = cpuid as u32 & 0x3;
        let sources: u32 = unsafe { self.read(LOCAL_IRQ_PENDING + 4 * cpu) };
        ffs(sources) - 1
    }

    fn irq_eoi(&mut self, _irq_num: u32) {}

    fn irq_enable(&mut self, irq_num: u32) {
        match irq_num {
            LOCAL_IRQ_CNTPNSIRQ => unsafe {
                let cpuid: usize;
                asm!("mrs {}, mpidr_el1", out(reg) cpuid);
                let cpu = cpuid as u32 & 0x3;
                let mut reg_val = self.read(LOCAL_TIMER_INT_CONTROL0 + 4 * cpu);
                reg_val |= 0x2;
                self.write(LOCAL_TIMER_INT_CONTROL0 + 4 * cpu, reg_val);
            },
            LOCAL_IRQ_GPU_FAST => {
                //GPU IRQ always enable
            }
            _ => {
                //ignore
            }
        }
    }

    fn irq_disable(&mut self, irq_num: u32) {
        match irq_num {
            LOCAL_IRQ_CNTPNSIRQ => unsafe {
                let cpuid: usize;
                asm!("mrs {}, mpidr_el1", out(reg) cpuid);
                let cpu = cpuid as u32 & 0x3;
                let mut reg_val = self.read(LOCAL_TIMER_INT_CONTROL0 + 4 * cpu);
                reg_val &= !0x2;
                self.write(LOCAL_TIMER_INT_CONTROL0 + 4 * cpu, reg_val);
            },
            LOCAL_IRQ_GPU_FAST => {
                //GPU IRQ always enable
            }
            _ => {
                //ignore
            }
        }
    }
    fn irq_xlate(&self, irq_data: &[u32; 3]) -> Result<usize> {
        //assert interrupt-cells == 0x2
        let off = irq_data[0] as usize + self.irq_range.0;
        return Ok(off);
    }
    fn irq_to_virq(&self, hwirq: u32) -> Option<usize> {
        if hwirq > LOCAL_IRQ_LAST {
            None
        } else {
            Some(self.irq_range.0 + hwirq as usize)
        }
    }
}
