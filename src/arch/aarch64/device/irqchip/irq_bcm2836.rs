use core::ptr::{read_volatile, write_volatile};

use byteorder::{ByteOrder, BE};
use fdt::{DeviceTree, Node};

use crate::{device::io_mmap, init::device_tree::find_compatible_node};
use syscall::{Result, error::{Error, EINVAL}};

use super::InterruptController;

static LOCAL_CONTROL: u32 = 0x000;
static LOCAL_PRESCALER: u32 = 0x008;
static LOCAL_GPU_ROUTING: u32 = 0x00C;
static LOCAL_TIMER_INT_CONTROL0: u32 = 0x040;
static LOCAL_IRQ_PENDING: u32 = 0x060;
static LOCAL_FIQ_PENDING: u32 = 0x070;

static LOCAL_IRQ_CNTPSIRQ: u32 = 0x0;
static LOCAL_IRQ_CNTPNSIRQ: u32 = 0x1;
static LOCAL_IRQ_CNTHPIRQ: u32 = 0x2;
static LOCAL_IRQ_CNTVIRQ: u32 = 0x3;
static LOCAL_IRQ_MAILBOX0: u32 = 0x4;
static LOCAL_IRQ_MAILBOX1: u32 = 0x5;
static LOCAL_IRQ_MAILBOX2: u32 = 0x6;
static LOCAL_IRQ_MAILBOX3: u32 = 0x7;
static LOCAL_IRQ_GPU_FAST: u32 = 0x8;
static LOCAL_IRQ_PMU_FAST: u32 = 0x9;
static LOCAL_IRQ_LAST: u32 = 0x9;

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
        x >>= 1;
        r += 1;
    }
    
    r
}

pub struct Bcm2836ArmInterruptController {
    pub address: usize,
}


impl Bcm2836ArmInterruptController {
    pub fn new() -> Self {
        Bcm2836ArmInterruptController { address: 0 }
    }
    pub fn parse(fdt: Option<&DeviceTree>) -> Result<(usize, usize)> {
        match fdt {
            //TODO: remove hard code for qemu-virt
            None => Err(Error::new(EINVAL)),
            Some(dtb) => {
                //TODO: try to parse dtb using stable library
                if let Some(node) = find_compatible_node(dtb, "brcm,bcm2836-l1-intc") {
                    return Bcm2836ArmInterruptController::parse_inner(&node);
                } else {
                    return Err(Error::new(EINVAL));
                }
            }
        }
    }
    fn parse_inner(node: &Node) -> Result<(usize, usize)> {
        //assert address_cells == 0x1, size_cells == 0x1
        let reg = node.properties().find(|p| p.name.contains("reg")).unwrap();
        let (base, size) = reg.data.split_at(4);
        let base = BE::read_u32(base);
        let size = BE::read_u32(size);
        
        Ok((base as usize, size as usize))
    }

    unsafe fn init(&mut self) {
        println!("IRQ BCM2836 INIT");
        //init local timer freq
        self.write(LOCAL_CONTROL, 0x0);
        self.write(LOCAL_PRESCALER, 0x8000_0000);

        //routing all irq to core0
        self.write(LOCAL_GPU_ROUTING, 0x0);
        println!("IRQ BCM2836 END");
    }

    unsafe fn read(&self, reg: u32) -> u32 {
        let val = read_volatile((self.address + reg as usize) as *const u32);
        val
    }

    unsafe fn write(&mut self, reg: u32, value: u32) {
        write_volatile((self.address + reg as usize) as *mut u32, value);
    }
}

impl InterruptController for Bcm2836ArmInterruptController {
    fn irq_init(&mut self, fdt: Option<&DeviceTree>) -> Result<()> {
        let (base, size) = match Bcm2836ArmInterruptController::parse(fdt) {
            Ok((a, b)) => (a, b),
            Err(_) => return Err(Error::new(EINVAL)),
        };
        unsafe {
            io_mmap(base, size);

            self.address = base;

            self.init();
        }

        Ok(())
    }

    fn irq_ack(&mut self) -> u32 {
        //TODO: support smp self.read(LOCAL_IRQ_PENDING + 4 * cpu)
        //assert cpu == 0
        let sources = unsafe { self.read(LOCAL_IRQ_PENDING) };
        ffs(sources) - 1
    }

    fn irq_eoi(&mut self, irq_num: u32) {

    }

    fn irq_enable(&mut self, irq_num: u32) {

    }

    fn irq_disable(&mut self, irq_num: u32) {

    }
}
