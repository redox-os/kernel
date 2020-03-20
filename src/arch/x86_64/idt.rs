use core::mem;
use core::num::NonZeroU8;

use x86::segmentation::Descriptor as X86IdtEntry;
use x86::dtables::{self, DescriptorTablePointer};

use crate::interrupt::*;
use crate::ipi::IpiKind;

use spin::Mutex;

pub static mut INIT_IDTR: DescriptorTablePointer<X86IdtEntry> = DescriptorTablePointer {
    limit: 0,
    base: 0 as *const X86IdtEntry
};

pub static mut IDTR: DescriptorTablePointer<X86IdtEntry> = DescriptorTablePointer {
    limit: 0,
    base: 0 as *const X86IdtEntry
};

// TODO: It's probably a good idea to use a separate IDT (and IDT_RESERVATIONS) for each CPU.
// Currently 202 interrupts are freely allocatable, for the IDT, but if different CPUs received
// different IDTs, the number would go up to e.g. 1616 IRQs on a processor with 8 logical CPUs.

pub static mut IDT: [IdtEntry; 256] = [IdtEntry::new(); 256];
pub static IDT_RESERVATIONS: Mutex<[u64; 256 / 64]> = Mutex::new([0u64; 256 / 64]);

#[inline]
pub fn is_reserved(index: u8) -> bool {
    let byte_index = index / 64;
    let bit = index % 64;

    IDT_RESERVATIONS.lock()[usize::from(byte_index)] & (1 << bit) != 0
}

#[inline]
pub fn set_reserved(index: u8, reserved: bool) {
    let byte_index = index / 64;
    let bit = index % 64;

    IDT_RESERVATIONS.lock()[usize::from(byte_index)] |= u64::from(reserved) << bit;
}

pub fn allocate_interrupt() -> Option<NonZeroU8> {
    for number in 50..=255 {
        if ! is_reserved(number) {
            set_reserved(number, true);
            return Some(unsafe { NonZeroU8::new_unchecked(number) });
        }
    }
    None
}

pub fn available_irqs_iter() -> impl Iterator<Item = u8> + 'static {
    AvailableIrqsIter { index: Some(50) }.filter(|&index| !is_reserved(index))
}

struct AvailableIrqsIter {
    index: Option<u8>,
}
impl Iterator for AvailableIrqsIter {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        let index = self.index?;
        self.index = index.checked_add(1);
        Some(index)
    }
}

macro_rules! use_irq(
    ( $number:literal, $func:ident ) => {
        IDT[$number].set_func($func);
    }
);

macro_rules! use_default_irqs(
    () => {{
        use crate::interrupt::irq::*;
        default_irqs!(use_irq);
    }}
);

pub unsafe fn init() {
    dtables::lidt(&INIT_IDTR);
}

pub unsafe fn init_paging() {
    IDTR.limit = (IDT.len() * mem::size_of::<IdtEntry>() - 1) as u16;
    IDTR.base = IDT.as_ptr() as *const X86IdtEntry;

    // Set up exceptions
    IDT[0].set_func(exception::divide_by_zero);
    IDT[1].set_func(exception::debug);
    IDT[2].set_func(exception::non_maskable);
    IDT[3].set_func(exception::breakpoint);
    IDT[3].set_flags(IdtFlags::PRESENT | IdtFlags::RING_3 | IdtFlags::INTERRUPT);
    IDT[4].set_func(exception::overflow);
    IDT[5].set_func(exception::bound_range);
    IDT[6].set_func(exception::invalid_opcode);
    IDT[7].set_func(exception::device_not_available);
    IDT[8].set_func(exception::double_fault);
    // 9 no longer available
    IDT[10].set_func(exception::invalid_tss);
    IDT[11].set_func(exception::segment_not_present);
    IDT[12].set_func(exception::stack_segment);
    IDT[13].set_func(exception::protection);
    IDT[14].set_func(exception::page);
    // 15 reserved
    IDT[16].set_func(exception::fpu);
    IDT[17].set_func(exception::alignment_check);
    IDT[18].set_func(exception::machine_check);
    IDT[19].set_func(exception::simd);
    IDT[20].set_func(exception::virtualization);
    // 21 through 29 reserved
    IDT[30].set_func(exception::security);
    // 31 reserved

    // reserve bits 31:0, i.e. the first 32 interrupts, which are reserved for exceptions
    IDT_RESERVATIONS.lock()[0] |= 0x0000_0000_FFFF_FFFF;

    // Set up IRQs
    IDT[32].set_func(irq::pit);
    IDT[33].set_func(irq::keyboard);
    IDT[34].set_func(irq::cascade);
    IDT[35].set_func(irq::com2);
    IDT[36].set_func(irq::com1);
    IDT[37].set_func(irq::lpt2);
    IDT[38].set_func(irq::floppy);
    IDT[39].set_func(irq::lpt1);
    IDT[40].set_func(irq::rtc);
    IDT[41].set_func(irq::pci1);
    IDT[42].set_func(irq::pci2);
    IDT[43].set_func(irq::pci3);
    IDT[44].set_func(irq::mouse);
    IDT[45].set_func(irq::fpu);
    IDT[46].set_func(irq::ata1);
    IDT[47].set_func(irq::ata2);
    IDT[48].set_func(irq::lapic_timer);
    IDT[49].set_func(irq::lapic_error);

    use_default_irqs!();

    // reserve bits 49:32, which are for the standard IRQs, and for the local apic timer and error.
    IDT_RESERVATIONS.lock()[0] |= 0x0003_FFFF_0000_0000;

    // Set IPI handlers
    IDT[IpiKind::Wakeup as usize].set_func(ipi::wakeup);
    IDT[IpiKind::Switch as usize].set_func(ipi::switch);
    IDT[IpiKind::Tlb as usize].set_func(ipi::tlb);
    IDT[IpiKind::Pit as usize].set_func(ipi::pit);
    set_reserved(IpiKind::Wakeup as u8, true);
    set_reserved(IpiKind::Switch as u8, true);
    set_reserved(IpiKind::Tlb as u8, true);
    set_reserved(IpiKind::Pit as u8, true);

    // Set syscall function
    IDT[0x80].set_func(syscall::syscall);
    IDT[0x80].set_flags(IdtFlags::PRESENT | IdtFlags::RING_3 | IdtFlags::INTERRUPT);
    set_reserved(0x80, true);

    dtables::lidt(&IDTR);
}

bitflags! {
    pub struct IdtFlags: u8 {
        const PRESENT = 1 << 7;
        const RING_0 = 0 << 5;
        const RING_1 = 1 << 5;
        const RING_2 = 2 << 5;
        const RING_3 = 3 << 5;
        const SS = 1 << 4;
        const INTERRUPT = 0xE;
        const TRAP = 0xF;
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(packed)]
pub struct IdtEntry {
    offsetl: u16,
    selector: u16,
    zero: u8,
    attribute: u8,
    offsetm: u16,
    offseth: u32,
    zero2: u32
}

impl IdtEntry {
    pub const fn new() -> IdtEntry {
        IdtEntry {
            offsetl: 0,
            selector: 0,
            zero: 0,
            attribute: 0,
            offsetm: 0,
            offseth: 0,
            zero2: 0
        }
    }

    pub fn set_flags(&mut self, flags: IdtFlags) {
        self.attribute = flags.bits;
    }

    pub fn set_offset(&mut self, selector: u16, base: usize) {
        self.selector = selector;
        self.offsetl = base as u16;
        self.offsetm = (base >> 16) as u16;
        self.offseth = (base >> 32) as u32;
    }

    // A function to set the offset more easily
    pub fn set_func(&mut self, func: unsafe extern fn()) {
        self.set_flags(IdtFlags::PRESENT | IdtFlags::RING_0 | IdtFlags::INTERRUPT);
        self.set_offset(8, func as usize);
    }
}
