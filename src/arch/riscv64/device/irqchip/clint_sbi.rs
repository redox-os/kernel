use crate::{
    context,
    context::timeout,
    dtb::irqchip::{register_irq, InterruptHandler, IrqCell, IrqChip},
    sync::CleanLockToken,
};
use alloc::boxed::Box;
use core::{
    arch::asm,
    cmp::max,
    sync::atomic::{AtomicU64, Ordering},
};
use fdt::node::FdtNode;
use spin::Once;
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
    // Could be changed to SyncUnsafeCell<u64> since it's only accessed from the corresponding hart
    next_event: Box<[AtomicU64]>,
}

pub static CLINT: Once<Clint> = Once::new();
const TICKS_PER_SECOND: u64 = 100;
const IRQ_IPI: usize = 0;
const IRQ_TIMER: usize = 1;

struct ClintConnector {
    hart_id: usize,
    irq: usize,
}

impl InterruptHandler for ClintConnector {
    fn irq_handler(&self, _irq: u32, token: &mut CleanLockToken) {
        CLINT
            .get()
            .expect("CLINT has not been initialized!")
            .irq_handler(self.hart_id, self.irq);
        if self.irq == IRQ_TIMER {
            // a bit of hack, but it is a really bad idea to call scheduler
            // from inside clint irq handler
            timeout::trigger(token);
            context::switch::tick(token);
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
    pub fn new(freq: u64, node: &FdtNode) -> Self {
        // TODO IPI
        // let reg = clint_node.reg().unwrap().next().unwrap();
        // reg.starting_address.add(crate::PHYS_OFFSET) as *mut u8;
        // reg.size.unwrap();

        let mut interrupts = node
            .property("interrupts-extended")
            .expect("CLINT failed to parse interrupts!")
            .value
            .as_chunks::<4>()
            .0
            .iter()
            .map(|&x| u32::from_be_bytes(x));
        let mut hart_id = 0;
        while let Ok([phandle1, irq0, phandle2, irq1]) = interrupts.next_chunk::<4>() {
            assert_eq!(
                phandle1, phandle2,
                "Invalid interrupts-extended property for CLINT"
            );
            let hlic = IrqChip::chips()
                .iter()
                .find(|x| x.phandle == phandle1)
                .expect("Couldn't find HLIC in irqchip list for CLINT");

            // FIXME dirty hack map M-mode interrupts (handled by SBI) to S-mode interrupts we get from SBI
            // Why aren't S-mode interrupts in the DTB already?
            let irq0 = IrqCell::L1(map_interrupt(irq0));
            let irq1 = IrqCell::L1(map_interrupt(irq1));

            let virq0 = hlic
                .ic
                .irq_xlate(irq0)
                .expect("Couldn't get virq 0 from HLIC");
            let virq1 = hlic
                .ic
                .irq_xlate(irq1)
                .expect("Couldn't get virq 1 from HLIC");
            register_irq(virq0 as u32, Box::new(ClintConnector { hart_id, irq: 0 }));
            register_irq(virq1 as u32, Box::new(ClintConnector { hart_id, irq: 1 }));
            hart_id += 1;
        }
        Self {
            freq,
            next_event: (0..hart_id).map(|_| AtomicU64::new(0)).collect(),
        }
    }

    pub(crate) fn irq_handler(&self, hart_id: usize, irq: usize) {
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
                let next_event = max(
                    self.next_event[hart_id].load(Ordering::Relaxed),
                    mtime as u64,
                ) + self.freq / TICKS_PER_SECOND;
                self.next_event[hart_id].store(next_event, Ordering::Relaxed);
                sbi_rt::set_timer(next_event).expect("SBI timer cannot be set!");
            }
            _ => {
                panic!("Unexpected CLINT irq")
            }
        }
    }

    pub fn init(&self, hart: usize) {
        let mtime: u64;
        unsafe {
            asm!(
            "rdtime t0",
            lateout("t0") mtime
            )
        };
        let next_event = mtime + (self.freq / TICKS_PER_SECOND);
        self.next_event[hart].store(next_event, Ordering::Relaxed);
        sbi_rt::set_timer(next_event).expect("SBI timer cannot be set!");
    }
}
