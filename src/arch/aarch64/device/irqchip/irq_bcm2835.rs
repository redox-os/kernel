use core::ptr::{read_volatile, write_volatile};

use byteorder::{ByteOrder, BE};
use fdt::{DeviceTree, Node};

use crate::{device::io_mmap, init::device_tree::find_compatible_node};
use syscall::{Result, error::{Error, EINVAL}};

use super::InterruptController;

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

const PENDING_0: u32 = 0x200;
const PENDING_1: u32 = 0x204;
const PENDING_2: u32 = 0x208;
const FIQ_CTRL: u32 = 0x20c;
const ENABLE_0: u32 = 0x218;
const ENABLE_1: u32 = 0x210;
const ENABLE_2: u32 = 0x214;
const DISABLE_0: u32 = 0x224;
const DISABLE_1: u32 = 0x21c;
const DISABLE_2: u32 = 0x220;


pub struct Bcm2835ArmInterruptController {
    pub address: usize,
}


impl Bcm2835ArmInterruptController {
    pub fn new() -> Self {
        Bcm2835ArmInterruptController { address: 0 }
    }
    pub fn parse(fdt: Option<&DeviceTree>) -> Result<(usize, usize)> {
        match fdt {
            //TODO: remove hard code for qemu-virt
            None => Err(Error::new(EINVAL)),
            Some(dtb) => {
                //TODO: try to parse dtb using stable library
                if let Some(node) = find_compatible_node(dtb, "brcm,bcm2835-armctrl-ic") {
                    return Bcm2835ArmInterruptController::parse_inner(&node);
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
        println!("IRQ BCM2835 INIT");
        //disable all interrupt
        self.write(DISABLE_0, 0xffff_ffff);
        self.write(DISABLE_1, 0xffff_ffff);
        self.write(DISABLE_2, 0xffff_ffff);

        println!("IRQ BCM2835 END");
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
    fn irq_init(&mut self, fdt: Option<&DeviceTree>) -> Result<()> {
        let (base, size) = match Bcm2835ArmInterruptController::parse(fdt) {
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
        let sources = unsafe { self.read(PENDING_0) };
        let pending_num = ffs(sources) - 1;
        match pending_num {
            num@0..=7 => return num,
            8 => {
                let sources1 = unsafe { self.read(PENDING_1) };
                let irq_0_31 = ffs(sources1) - 1;
                return irq_0_31;
            },
            9 => {
                let sources2 = unsafe { self.read(PENDING_2) };
                let irq_32_63 = ffs(sources2) - 1;
                return irq_32_63 + 32;
            },
            num => {
                println!("unexpected irq pending in BASIC PENDING: {}", num);
                return num;
            }
        }
    }

    fn irq_eoi(&mut self, irq_num: u32) {

    }

    fn irq_enable(&mut self, irq_num: u32) {

    }

    fn irq_disable(&mut self, irq_num: u32) {

    }
}
