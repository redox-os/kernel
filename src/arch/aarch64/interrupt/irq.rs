use core::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT};

use crate::context;
use crate::context::timeout;
use crate::device::generic_timer::{GENTIMER};
use crate::device::{gic};
use crate::device::serial::{COM1};
use crate::time;

//resets to 0 in context::switch()
pub static PIT_TICKS: AtomicUsize = ATOMIC_USIZE_INIT;

#[naked]
#[no_mangle]
pub unsafe extern fn do_irq() {
    #[inline(never)]
    unsafe fn inner() {
        irq_demux();
    }

    llvm_asm!("str	    x0, [sp, #-8]!
          str	    x1, [sp, #-8]!
          str	    x2, [sp, #-8]!
          str	    x3, [sp, #-8]!
          str	    x4, [sp, #-8]!
          str	    x5, [sp, #-8]!
          str	    x6, [sp, #-8]!
          str	    x7, [sp, #-8]!
          str	    x8, [sp, #-8]!
          str	    x9, [sp, #-8]!
          str	    x10, [sp, #-8]!
          str	    x11, [sp, #-8]!
          str	    x12, [sp, #-8]!
          str	    x13, [sp, #-8]!
          str	    x14, [sp, #-8]!
          str	    x15, [sp, #-8]!
          str	    x16, [sp, #-8]!
          str	    x17, [sp, #-8]!
          str	    x18, [sp, #-8]!
          str	    x19, [sp, #-8]!
          str	    x20, [sp, #-8]!
          str	    x21, [sp, #-8]!
          str	    x22, [sp, #-8]!
          str	    x23, [sp, #-8]!
          str	    x24, [sp, #-8]!
          str	    x25, [sp, #-8]!
          str	    x26, [sp, #-8]!
          str	    x27, [sp, #-8]!
          str	    x28, [sp, #-8]!
          str	    x29, [sp, #-8]!
          str	    x30, [sp, #-8]!

          mrs       x18, sp_el0
          str       x18, [sp, #-8]!

          mrs       x18, esr_el1
          str       x18, [sp, #-8]!

          mrs       x18, spsr_el1
          str       x18, [sp, #-8]!

          mrs       x18, tpidrro_el0
          str       x18, [sp, #-8]!

          mrs       x18, tpidr_el0
          str       x18, [sp, #-8]!

          str       x18, [sp, #-8]!

          mrs       x18, elr_el1
          str       x18, [sp, #-8]!"
    : : : : "volatile");

    inner();

    llvm_asm!("ldr	    x18, [sp], #8
          msr	    elr_el1, x18

          ldr	    x18, [sp], #8

          ldr	    x18, [sp], #8
          msr	    tpidr_el0, x18

          ldr	    x18, [sp], #8
          msr	    tpidrro_el0, x18

          ldr	    x18, [sp], #8
          msr	    spsr_el1, x18

          ldr	    x18, [sp], #8
          msr	    esr_el1, x18

          ldr	    x18, [sp], #8
          msr       sp_el0, x18

          ldr	    x30, [sp], #8
          ldr	    x29, [sp], #8
          ldr	    x28, [sp], #8
          ldr	    x27, [sp], #8
          ldr	    x26, [sp], #8
          ldr	    x25, [sp], #8
          ldr	    x24, [sp], #8
          ldr	    x23, [sp], #8
          ldr	    x22, [sp], #8
          ldr	    x21, [sp], #8
          ldr	    x20, [sp], #8
          ldr	    x19, [sp], #8
          ldr	    x18, [sp], #8
          ldr	    x17, [sp], #8
          ldr	    x16, [sp], #8
          ldr	    x15, [sp], #8
          ldr	    x14, [sp], #8
          ldr	    x13, [sp], #8
          ldr	    x12, [sp], #8
          ldr	    x11, [sp], #8
          ldr	    x10, [sp], #8
          ldr	    x9, [sp], #8
          ldr	    x8, [sp], #8
          ldr	    x7, [sp], #8
          ldr	    x6, [sp], #8
          ldr	    x5, [sp], #8
          ldr	    x4, [sp], #8
          ldr	    x3, [sp], #8
          ldr	    x2, [sp], #8
          ldr	    x1, [sp], #8
          ldr	    x0, [sp], #8"
    : : : : "volatile");

    llvm_asm!("eret" :::: "volatile");
}

unsafe fn trigger(irq: u32) {
    extern {
        fn irq_trigger(irq: u32);
    }

    irq_trigger(irq);
    gic::irq_eoi(irq);
}

pub unsafe fn acknowledge(_irq: usize) {
}

pub unsafe fn irq_handler_com1(irq: u32) {
    if let Some(ref mut serial_port) = *COM1.lock() {
        serial_port.receive();
    };
    trigger(irq);
}

pub unsafe fn irq_handler_gentimer(irq: u32) {
    GENTIMER.clear_irq();
    {
        let mut offset = time::OFFSET.lock();
        let sum = offset.1 + GENTIMER.clk_freq as u64;
        offset.1 = sum % 1_000_000_000;
        offset.0 += sum / 1_000_000_000;
    }

    timeout::trigger();

    if PIT_TICKS.fetch_add(1, Ordering::SeqCst) >= 10 {
        let _ = context::switch();
    }
    trigger(irq);
    GENTIMER.reload_count();
}

unsafe fn irq_demux() {
    match gic::irq_ack() {
        30 => irq_handler_gentimer(30),
        33 => irq_handler_com1(33),
        _ => panic!("irq_demux: unregistered IRQ"),
    }
}
