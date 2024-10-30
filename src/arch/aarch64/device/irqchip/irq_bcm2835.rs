use byteorder::{ByteOrder, BE};
use core::ptr::{read_volatile, write_volatile};
use fdt::{node::FdtNode, Fdt};
use log::{debug, error, info};

use super::InterruptController;
use crate::dtb::irqchip::{InterruptHandler, IrqDesc, IRQ_CHIP};
use syscall::{
    error::{Error, EINVAL},
    Result,
};

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

const PENDING_0: u32 = 0x0;
const PENDING_1: u32 = 0x4;
const PENDING_2: u32 = 0x8;
const ENABLE_0: u32 = 0x18;
const ENABLE_1: u32 = 0x10;
const ENABLE_2: u32 = 0x14;
const DISABLE_0: u32 = 0x24;
const DISABLE_1: u32 = 0x1c;
const DISABLE_2: u32 = 0x20;

pub struct Bcm2835ArmInterruptController {
    pub address: usize,
    pub irq_range: (usize, usize),
}

impl Bcm2835ArmInterruptController {
    pub fn new() -> Self {
        Bcm2835ArmInterruptController {
            address: 0,
            irq_range: (0, 0),
        }
    }
    pub fn parse(fdt: &Fdt) -> Result<(usize, usize, Option<usize>)> {
        if let Some(node) = fdt.find_compatible(&["brcm,bcm2836-armctrl-ic"]) {
            return unsafe { Bcm2835ArmInterruptController::parse_inner(&node) };
        } else {
            return Err(Error::new(EINVAL));
        }
    }
    unsafe fn parse_inner(node: &FdtNode) -> Result<(usize, usize, Option<usize>)> {
        //assert address_cells == 0x1, size_cells == 0x1
        let mem = node.reg().unwrap().nth(0).unwrap();
        let base = mem.starting_address as u32;
        let size = mem.size.unwrap() as u32;
        let mut ret_virq = None;

        if let Some(interrupt_parent) = node.property("interrupt-parent") {
            let phandle = interrupt_parent.as_usize().unwrap() as u32;
            let interrupts = node.property("interrupts").unwrap();
            let irq = interrupts
                .value
                .array_chunks::<4>()
                .map(|f| BE::read_u32(f))
                .next_chunk::<3>()
                .unwrap();
            let ic_idx = IRQ_CHIP.phandle_to_ic_idx(phandle).unwrap();
            //PHYS_NONSECURE_PPI only
            let virq = IRQ_CHIP.irq_chip_list.chips[ic_idx]
                .ic
                .irq_xlate(&irq)
                .unwrap();
            info!("bcm2835arm_ctrl virq = {}", virq);
            ret_virq = Some(virq);
        }
        Ok((base as usize, size as usize, ret_virq))
    }

    unsafe fn init(&mut self) {
        debug!("IRQ BCM2835 INIT");
        //disable all interrupt
        self.write(DISABLE_0, 0xffff_ffff);
        self.write(DISABLE_1, 0xffff_ffff);
        self.write(DISABLE_2, 0xffff_ffff);

        debug!("IRQ BCM2835 END");
    }

    unsafe fn read(&self, reg: u32) -> u32 {
        let val = read_volatile((self.address + reg as usize) as *const u32);
        val
    }

    unsafe fn write(&mut self, reg: u32, value: u32) {
        write_volatile((self.address + reg as usize) as *mut u32, value);
    }
}

impl InterruptController for Bcm2835ArmInterruptController {
    fn irq_init(
        &mut self,
        fdt_opt: Option<&Fdt>,
        irq_desc: &mut [IrqDesc; 1024],
        ic_idx: usize,
        irq_idx: &mut usize,
    ) -> Result<()> {
        let (base, _size, _virq) = match Bcm2835ArmInterruptController::parse(fdt_opt.unwrap()) {
            Ok((a, b, c)) => (a, b, c),
            Err(_) => return Err(Error::new(EINVAL)),
        };
        unsafe {
            self.address = base + crate::PHYS_OFFSET;

            self.init();
            let idx = *irq_idx;
            let cnt = 3 << 5; //3 * 32 irqs, basic == 8, reg1 = 32, reg2 = 32
            let mut i: usize = 0;
            //only support linear irq map now.
            while i < cnt && (idx + i < 1024) {
                irq_desc[idx + i].basic.ic_idx = ic_idx;
                irq_desc[idx + i].basic.ic_irq = i as u32;
                irq_desc[idx + i].basic.used = true;

                i += 1;
            }

            info!("bcm2835 irq_range = ({}, {})", idx, idx + cnt);
            self.irq_range = (idx, idx + cnt);
            *irq_idx = idx + cnt;
        }

        Ok(())
    }

    fn irq_ack(&mut self) -> u32 {
        //TODO: support smp self.read(LOCAL_IRQ_PENDING + 4 * cpu)
        let sources = unsafe { self.read(PENDING_0) };
        let pending_num = ffs(sources) - 1;
        let fast_irq = [
            7 + 32,
            9 + 32,
            10 + 32,
            18 + 32,
            19 + 32,
            21 + 64,
            22 + 64,
            23 + 64,
            24 + 64,
            25 + 64,
            30 + 64,
        ];

        //fast irq
        if pending_num >= 10 && pending_num <= 20 {
            return fast_irq[(pending_num - 10) as usize];
        }

        let pending_num = ffs(sources & 0x3ff) - 1;
        match pending_num {
            num @ 0..=7 => return num,
            8 => {
                let sources1 = unsafe { self.read(PENDING_1) };
                let irq_0_31 = ffs(sources1) - 1;
                return irq_0_31 + 32;
            }
            9 => {
                let sources2 = unsafe { self.read(PENDING_2) };
                let irq_32_63 = ffs(sources2) - 1;
                return irq_32_63 + 64;
            }
            num => {
                error!(
                    "unexpected irq pending in BASIC PENDING: 0x{}, sources = 0x{:08x}",
                    num, sources
                );
                return num;
            }
        }
    }

    fn irq_eoi(&mut self, _irq_num: u32) {}

    fn irq_enable(&mut self, irq_num: u32) {
        debug!("bcm2835 enable {} {}", irq_num, irq_num & 0x1f);
        match irq_num {
            num @ 0..=31 => {
                let val = 1 << num;
                unsafe {
                    self.write(ENABLE_0, val);
                }
            }
            num @ 32..=63 => {
                let val = 1 << (num & 0x1f);
                unsafe {
                    self.write(ENABLE_1, val);
                }
            }
            num @ 64..=95 => {
                let val = 1 << (num & 0x1f);
                unsafe {
                    self.write(ENABLE_2, val);
                }
            }
            _ => return,
        }
    }

    fn irq_disable(&mut self, irq_num: u32) {
        match irq_num {
            num @ 0..=31 => {
                let val = 1 << num;
                unsafe {
                    self.write(DISABLE_0, val);
                }
            }
            num @ 32..=63 => {
                let val = 1 << (num & 0x1f);
                unsafe {
                    self.write(DISABLE_1, val);
                }
            }
            num @ 64..=95 => {
                let val = 1 << (num & 0x1f);
                unsafe {
                    self.write(DISABLE_2, val);
                }
            }
            _ => return,
        }
    }
    fn irq_xlate(&self, irq_data: &[u32; 3]) -> Result<usize> {
        //assert interrupt-cells == 0x2
        let bank = irq_data[0] as usize;
        let irq = irq_data[1] as usize;
        //TODO: check bank && irq
        let hwirq = bank << 5 | irq;
        let off = hwirq + self.irq_range.0;
        return Ok(off);
    }

    fn irq_to_virq(&self, hwirq: u32) -> Option<usize> {
        if hwirq > 95 {
            None
        } else {
            Some(self.irq_range.0 + hwirq as usize)
        }
    }
}

impl InterruptHandler for Bcm2835ArmInterruptController {
    fn irq_handler(&mut self, _irq: u32) {
        unsafe {
            let irq = self.irq_ack();
            if let Some(virq) = self.irq_to_virq(irq)
                && virq < 1024
            {
                if let Some(handler) = &mut IRQ_CHIP.irq_desc[virq].handler {
                    handler.irq_handler(virq as u32);
                }
            } else {
                error!("unexpected irq num {}", irq);
            }
            self.irq_eoi(irq);
        }
    }
}
