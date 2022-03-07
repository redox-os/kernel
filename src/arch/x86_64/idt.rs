use core::num::NonZeroU8;
use core::sync::atomic::{AtomicU64, Ordering};
use core::mem;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;

use x86::segmentation::Descriptor as X86IdtEntry;
use x86::dtables::{self, DescriptorTablePointer};

use crate::interrupt::*;
use crate::ipi::IpiKind;
use crate::paging::PageFlags;

use spin::RwLock;

pub static mut INIT_IDTR: DescriptorTablePointer<X86IdtEntry> = DescriptorTablePointer {
    limit: 0,
    base: 0 as *const X86IdtEntry
};

#[thread_local]
pub static mut IDTR: DescriptorTablePointer<X86IdtEntry> = DescriptorTablePointer {
    limit: 0,
    base: 0 as *const X86IdtEntry
};

pub type IdtEntries = [IdtEntry; 256];
pub type IdtReservations = [AtomicU64; 4];

#[repr(packed)]
pub struct Idt {
    entries: IdtEntries,
    reservations: IdtReservations,
}
impl Idt {
    pub const fn new() -> Self {
        Self {
            entries: [IdtEntry::new(); 256],
            reservations: new_idt_reservations(),
        }
    }
    #[inline]
    pub fn is_reserved(&self, index: u8) -> bool {
        let byte_index = index / 64;
        let bit = index % 64;

        { &self.reservations[usize::from(byte_index)] }.load(Ordering::Acquire) & (1 << bit) != 0
    }

    #[inline]
    pub fn set_reserved(&self, index: u8, reserved: bool) {
        let byte_index = index / 64;
        let bit = index % 64;

        { &self.reservations[usize::from(byte_index)] }.fetch_or(u64::from(reserved) << bit, Ordering::AcqRel);
    }
    #[inline]
    pub fn is_reserved_mut(&mut self, index: u8) -> bool {
        let byte_index = index / 64;
        let bit = index % 64;

        *{ &mut self.reservations[usize::from(byte_index)] }.get_mut() & (1 << bit) != 0
    }

    #[inline]
    pub fn set_reserved_mut(&mut self, index: u8, reserved: bool) {
        let byte_index = index / 64;
        let bit = index % 64;

        *{ &mut self.reservations[usize::from(byte_index)] }.get_mut() |= u64::from(reserved) << bit;
    }
}

static mut INIT_BSP_IDT: Idt = Idt::new();

// TODO: VecMap?
pub static IDTS: RwLock<Option<BTreeMap<usize, &'static mut Idt>>> = RwLock::new(None);

#[inline]
pub fn is_reserved(cpu_id: usize, index: u8) -> bool {
    let byte_index = index / 64;
    let bit = index % 64;

    { &IDTS.read().as_ref().unwrap().get(&cpu_id).unwrap().reservations[usize::from(byte_index)] }.load(Ordering::Acquire) & (1 << bit) != 0
}

#[inline]
pub fn set_reserved(cpu_id: usize, index: u8, reserved: bool) {
    let byte_index = index / 64;
    let bit = index % 64;

    { &IDTS.read().as_ref().unwrap().get(&cpu_id).unwrap().reservations[usize::from(byte_index)] }.fetch_or(u64::from(reserved) << bit, Ordering::AcqRel);
}

pub fn allocate_interrupt() -> Option<NonZeroU8> {
    let cpu_id = crate::cpu_id();
    for number in 50..=254 {
        if ! is_reserved(cpu_id, number) {
            set_reserved(cpu_id, number, true);
            return Some(unsafe { NonZeroU8::new_unchecked(number) });
        }
    }
    None
}

pub fn available_irqs_iter(cpu_id: usize) -> impl Iterator<Item = u8> + 'static {
    (32..=254).filter(move |&index| !is_reserved(cpu_id, index))
}

macro_rules! use_irq(
    ( $idt: expr, $number:literal, $func:ident ) => {{
        $idt[$number].set_func($func);
    }}
);

macro_rules! use_default_irqs(
    ($idt:expr) => {{
        use crate::interrupt::irq::*;
        default_irqs!($idt, use_irq);
    }}
);

pub unsafe fn init() {
    dtables::lidt(&INIT_IDTR);
}

const fn new_idt_reservations() -> [AtomicU64; 4] {
    [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)]
}

/// Initialize the IDT for a
pub unsafe fn init_paging_post_heap(is_bsp: bool, cpu_id: usize) {
    let mut idts_guard = IDTS.write();
    let idts_btree = idts_guard.get_or_insert_with(|| BTreeMap::new());

    if is_bsp {
        idts_btree.insert(cpu_id, &mut INIT_BSP_IDT);
    } else {
        let idt = idts_btree.entry(cpu_id).or_insert_with(|| Box::leak(Box::new(Idt::new())));
        init_generic(is_bsp, idt);
    }
}

/// Initializes a fully functional IDT for use before it be moved into the map. This is ONLY called
/// on the BSP, since the kernel heap is ready for the APs.
pub unsafe fn init_paging_bsp() {
    init_generic(true, &mut INIT_BSP_IDT);
}

/// Initializes an IDT for any type of processor.
pub unsafe fn init_generic(is_bsp: bool, idt: &mut Idt) {
    let (current_idt, current_reservations) = (&mut idt.entries, &mut idt.reservations);

    IDTR.limit = (current_idt.len() * mem::size_of::<IdtEntry>() - 1) as u16;
    IDTR.base = current_idt.as_ptr() as *const X86IdtEntry;

    let backup_ist = {
        // We give Non-Maskable Interrupts, Double Fault, and Machine Check exceptions separate
        // stacks, since these (unless we are going to set up NMI watchdogs like Linux does) are
        // considered the most fatal, especially Double Faults which are caused by errors __when
        // accessing the system IDT__. If that goes wrong, then kernel memory may be partially
        // corrupt, and we want a separate stack.
        //
        // Note that each CPU has its own "backup interrupt stack".
        let index = 1_u8;

        // Allocate 64 KiB of stack space for the backup stack.
        const BACKUP_STACK_SIZE: usize = 65536;
        assert_eq!(BACKUP_STACK_SIZE % crate::memory::PAGE_SIZE, 0);
        let page_count = BACKUP_STACK_SIZE / crate::memory::PAGE_SIZE;
        let frames = crate::memory::allocate_frames(page_count)
            .expect("failed to allocate pages for backup interrupt stack");

        // Map them linearly, i.e. PHYS_OFFSET + physaddr.
        let base_address = {
            use crate::memory::{Frame, PhysicalAddress};
            use crate::paging::{ActivePageTable, Page, VirtualAddress};

            let base_virtual_address = VirtualAddress::new(frames.start_address().data() + crate::PHYS_OFFSET);
            let mut active_table = ActivePageTable::new(base_virtual_address.kind());

            for i in 0..page_count {
                let virtual_address = VirtualAddress::new(base_virtual_address.data() + i * crate::memory::PAGE_SIZE);
                let physical_address = PhysicalAddress::new(frames.start_address().data() + i * crate::memory::PAGE_SIZE);
                let page = Page::containing_address(virtual_address);

                let flags = PageFlags::new().write(true);

                let flusher = if let Some(already_mapped) = active_table.translate_page(page) {
                    assert_eq!(already_mapped.start_address(), physical_address, "address already mapped, but non-linearly");
                    active_table.remap(page, flags)
                } else {
                    active_table.map_to(page, Frame::containing_address(physical_address), flags)
                };
                flusher.flush();
            }

            base_virtual_address
        };
        // Stack always grows downwards.
        let address = base_address.data() + BACKUP_STACK_SIZE;

        // Put them in the 1st entry of the IST.
        crate::gdt::KPCR.tss.0.ist[usize::from(index - 1)] = address as u64;

        index
    };

    // Set up exceptions
    current_idt[0].set_func(exception::divide_by_zero);
    current_idt[1].set_func(exception::debug);
    current_idt[2].set_func(exception::non_maskable);
    current_idt[2].set_ist(backup_ist);
    current_idt[3].set_func(exception::breakpoint);
    current_idt[3].set_flags(IdtFlags::PRESENT | IdtFlags::RING_3 | IdtFlags::INTERRUPT);
    current_idt[4].set_func(exception::overflow);
    current_idt[5].set_func(exception::bound_range);
    current_idt[6].set_func(exception::invalid_opcode);
    current_idt[7].set_func(exception::device_not_available);
    current_idt[8].set_func(exception::double_fault);
    current_idt[8].set_ist(backup_ist);
    // 9 no longer available
    current_idt[10].set_func(exception::invalid_tss);
    current_idt[11].set_func(exception::segment_not_present);
    current_idt[12].set_func(exception::stack_segment);
    current_idt[13].set_func(exception::protection);
    current_idt[14].set_func(exception::page);
    // 15 reserved
    current_idt[16].set_func(exception::fpu_fault);
    current_idt[17].set_func(exception::alignment_check);
    current_idt[18].set_func(exception::machine_check);
    current_idt[18].set_ist(backup_ist);
    current_idt[19].set_func(exception::simd);
    current_idt[20].set_func(exception::virtualization);
    // 21 through 29 reserved
    current_idt[30].set_func(exception::security);
    // 31 reserved

    // reserve bits 31:0, i.e. the first 32 interrupts, which are reserved for exceptions
    *current_reservations[0].get_mut() |= 0x0000_0000_FFFF_FFFF;

    if is_bsp {
        // Set up IRQs
        current_idt[32].set_func(irq::pit_stack);
        current_idt[33].set_func(irq::keyboard);
        current_idt[34].set_func(irq::cascade);
        current_idt[35].set_func(irq::com2);
        current_idt[36].set_func(irq::com1);
        current_idt[37].set_func(irq::lpt2);
        current_idt[38].set_func(irq::floppy);
        current_idt[39].set_func(irq::lpt1);
        current_idt[40].set_func(irq::rtc);
        current_idt[41].set_func(irq::pci1);
        current_idt[42].set_func(irq::pci2);
        current_idt[43].set_func(irq::pci3);
        current_idt[44].set_func(irq::mouse);
        current_idt[45].set_func(irq::fpu);
        current_idt[46].set_func(irq::ata1);
        current_idt[47].set_func(irq::ata2);
        current_idt[48].set_func(irq::lapic_timer);
        current_idt[49].set_func(irq::lapic_error);


        // reserve bits 49:32, which are for the standard IRQs, and for the local apic timer and error.
        *current_reservations[0].get_mut() |= 0x0003_FFFF_0000_0000;
    } else {
        // TODO: use_default_irqs! but also the legacy IRQs that are only needed on one CPU
        current_idt[49].set_func(irq::lapic_error);

        // reserve bit 49
        *current_reservations[0].get_mut() |= (1 << 49);
    }

    use_default_irqs!(current_idt);

    // Set IPI handlers
    current_idt[IpiKind::Wakeup as usize].set_func(ipi::wakeup);
    current_idt[IpiKind::Switch as usize].set_func(ipi::switch);
    current_idt[IpiKind::Tlb as usize].set_func(ipi::tlb);
    current_idt[IpiKind::Pit as usize].set_func(ipi::pit);
    idt.set_reserved_mut(IpiKind::Wakeup as u8, true);
    idt.set_reserved_mut(IpiKind::Switch as u8, true);
    idt.set_reserved_mut(IpiKind::Tlb as u8, true);
    idt.set_reserved_mut(IpiKind::Pit as u8, true);
    let current_idt = &mut idt.entries;

    // Set syscall function
    current_idt[0x80].set_func(syscall::syscall);
    current_idt[0x80].set_flags(IdtFlags::PRESENT | IdtFlags::RING_3 | IdtFlags::INTERRUPT);
    idt.set_reserved_mut(0x80, true);

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

#[derive(Copy, Clone, Debug, Default)]
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

    pub fn set_ist(&mut self, ist: u8) {
        assert_eq!(ist & 0x07, ist, "interrupt stack table must be within 0..=7");
        self.zero &= 0xF8;
        self.zero |= ist;
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
        self.set_offset((crate::gdt::GDT_KERNEL_CODE as u16) << 3, func as usize);
    }
}
