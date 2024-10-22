use crate::{
    arch::riscv64::sbi::SBI,
    context,
    context::timeout,
    dtb::irqchip::{register_irq, InterruptHandler, IRQ_CHIP},
};
use alloc::{boxed::Box, vec::Vec};
use byteorder::{ByteOrder, BE};
use core::{arch::asm, cmp::max};
use fdt::node::FdtNode;
use spin::Mutex;
// This is a Core-Local Interruptor (CLINT). A single device directly routed into each HLIC
// It is responsible for local timer and IPI interrupts
// An example DTS:
// /soc/
//   clint@2000000/
//     interrupts-extended = <&hlic0 3>, <&hlic0 7>, <&hlic1 3>, <&hlic1 7>,
//                           <&hlic2 3>, <&hlic2 7>, <&hlic3 3>, <&hlic3 7>;
//     reg = <0x200000000 0x10000>;
//     compatible = "sifive,clint0", "riscv,clint0";

pub struct Clint {
    freq: u64,
    next_event: Vec<u64>,
}

pub static CLINT: Mutex<Option<Clint>> = Mutex::new(None);
const TICKS_PER_SECOND: u64 = 100;
const IRQ_IPI: usize = 0;
const IRQ_TIMER: usize = 1;

struct ClintConnector {
    hart_id: usize,
    irq: usize,
}

impl InterruptHandler for ClintConnector {
    fn irq_handler(&mut self, _irq: u32) {
        CLINT
            .lock()
            .as_mut()
            .unwrap()
            .irq_handler(self.hart_id, self.irq);
        if self.irq == IRQ_TIMER {
            // a bit of hack, but it is a really bad idea to call scheduler
            // from inside clint irq handler
            timeout::trigger();
            context::switch::tick();
        }
    }
}

fn map_interrupt(irq: u32) -> u32 {
    match irq {
        3 => 1, // map M-mode IPI to S-mode IPI
        7 => 5, // map M-mode timer to S-mode timer
        x => x,
    }
}

impl Clint {
    pub fn new(freq: usize, node: &FdtNode) -> Self {
        // TODO IPI
        // let reg = clint_node.reg().unwrap().next().unwrap();
        // reg.starting_address.add(crate::PHYS_OFFSET) as *mut u8;
        // reg.size.unwrap();

        let mut me = Self {
            freq: freq as u64,
            next_event: Vec::new(),
        };
        let mut interrupts = node
            .property("interrupts-extended")
            .unwrap()
            .value
            .chunks(4)
            .map(|x| BE::read_u32(x));
        let mut hart_id = 0;
        while let Ok([phandle1, irq0, phandle2, irq1]) = interrupts.next_chunk::<4>() {
            assert_eq!(
                phandle1, phandle2,
                "Invalid interrupts-extended property for CLINT"
            );
            let hlic = unsafe {
                IRQ_CHIP
                    .irq_chip_list
                    .chips
                    .iter()
                    .find(|x| x.phandle == phandle1)
                    .expect("Couldn't find HLIC in irqchip list for CLINT")
            };

            // FIXME dirty hack map M-mode interrupts (handled by SBI) to S-mode interrupts we get from SBI
            // Why aren't S-mode interrupts in the DTB already?
            let irq0 = map_interrupt(irq0);
            let irq1 = map_interrupt(irq1);

            let virq0 = hlic
                .ic
                .irq_xlate(&[irq0, 0, 0])
                .expect("Couldn't get virq 0 from HLIC");
            let virq1 = hlic
                .ic
                .irq_xlate(&[irq1, 0, 0])
                .expect("Couldn't get virq 1 from HLIC");
            register_irq(virq0 as u32, Box::new(ClintConnector { hart_id, irq: 0 }));
            register_irq(virq1 as u32, Box::new(ClintConnector { hart_id, irq: 1 }));
            hart_id += 1;
        }
        me.next_event.resize_with(hart_id, || 0);
        me
    }

    pub(crate) fn irq_handler(self: &mut Self, hart_id: usize, irq: usize) {
        match irq {
            IRQ_IPI => {
                println!("IPI interrupt at {}", hart_id);
            }
            IRQ_TIMER => {
                let mtime: usize;
                unsafe {
                    asm!(
                    "rdtime t0",
                    lateout("t0") mtime
                    )
                };

                self.next_event[hart_id] =
                    max(self.next_event[hart_id], mtime as u64) + self.freq / TICKS_PER_SECOND;
                SBI.set_timer(self.next_event[hart_id])
                    .expect("SBI timer cannot be set!");
            }
            _ => {
                panic!("Unexpected CLINT irq")
            }
        }
    }

    pub fn init(self: &mut Self, hart: usize) {
        let mtime: usize;
        unsafe {
            asm!(
            "rdtime t0",
            lateout("t0") mtime
            )
        };
        self.next_event[hart] = mtime as u64 + (self.freq / TICKS_PER_SECOND);
        SBI.set_timer(self.next_event[hart])
            .expect("SBI timer cannot be set!");
    }
}
