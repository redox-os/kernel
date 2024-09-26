use core::{
    cell::SyncUnsafeCell,
    mem,
    sync::atomic::{AtomicU32, Ordering},
};

use alloc::boxed::Box;
use hashbrown::HashMap;

use x86::{
    dtables::{self, DescriptorTablePointer},
    segmentation::Descriptor as X86IdtEntry,
};

#[cfg(target_arch = "x86_64")]
use crate::interrupt::irq::{__generic_interrupts_end, __generic_interrupts_start};
use crate::{cpu_set::LogicalCpuId, interrupt::*, ipi::IpiKind};

use spin::RwLock;

pub static INIT_IDT: SyncUnsafeCell<[IdtEntry; 32]> = SyncUnsafeCell::new([IdtEntry::new(); 32]);

pub type IdtEntries = [IdtEntry; 256];
pub type IdtReservations = [AtomicU32; 8];

#[repr(C)]
pub struct Idt {
    pub(crate) entries: IdtEntries,
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
    pub fn set_reserved_mut(&mut self, index: u8, reserved: bool) {
        let byte_index = index / 32;
        let bit = index % 32;

        *{ &mut self.reservations[usize::from(byte_index)] }.get_mut() |=
            u32::from(reserved) << bit;
    }
}

static INIT_BSP_IDT: SyncUnsafeCell<Idt> = SyncUnsafeCell::new(Idt::new());

// TODO: VecMap?
pub static IDTS: RwLock<Option<HashMap<LogicalCpuId, &'static mut Idt>>> = RwLock::new(None);

#[inline]
pub fn is_reserved(cpu_id: LogicalCpuId, index: u8) -> bool {
    let byte_index = index / 32;
    let bit = index % 32;

    {
        &IDTS
            .read()
            .as_ref()
            .unwrap()
            .get(&cpu_id)
            .unwrap()
            .reservations[usize::from(byte_index)]
    }
    .load(Ordering::Acquire)
        & (1 << bit)
        != 0
}

#[inline]
pub fn set_reserved(cpu_id: LogicalCpuId, index: u8, reserved: bool) {
    let byte_index = index / 32;
    let bit = index % 32;

    {
        &IDTS
            .read()
            .as_ref()
            .unwrap()
            .get(&cpu_id)
            .unwrap()
            .reservations[usize::from(byte_index)]
    }
    .fetch_or(u32::from(reserved) << bit, Ordering::AcqRel);
}

pub fn available_irqs_iter(cpu_id: LogicalCpuId) -> impl Iterator<Item = u8> + 'static {
    (32..=254).filter(move |&index| !is_reserved(cpu_id, index))
}

#[cfg(target_arch = "x86")]
macro_rules! use_irq(
    ( $idt: expr, $number:literal, $func:ident ) => {{
        $idt[$number].set_func($func);
    }}
);

#[cfg(target_arch = "x86")]
macro_rules! use_default_irqs(
    ($idt:expr) => {{
        use crate::interrupt::irq::*;
        default_irqs!($idt, use_irq);
    }}
);

pub unsafe fn init() {
    let idt = &mut *INIT_IDT.get();
    set_exceptions(idt);
    dtables::lidt(&DescriptorTablePointer::new(&idt));
}

fn set_exceptions(idt: &mut [IdtEntry]) {
    // Set up exceptions
    idt[0].set_func(exception::divide_by_zero);
    idt[1].set_func(exception::debug);
    idt[2].set_func(exception::non_maskable);
    idt[3].set_func(exception::breakpoint);
    idt[3].set_flags(IdtFlags::PRESENT | IdtFlags::RING_3 | IdtFlags::INTERRUPT);
    idt[4].set_func(exception::overflow);
    idt[5].set_func(exception::bound_range);
    idt[6].set_func(exception::invalid_opcode);
    idt[7].set_func(exception::device_not_available);
    idt[8].set_func(exception::double_fault);
    // 9 no longer available
    idt[10].set_func(exception::invalid_tss);
    idt[11].set_func(exception::segment_not_present);
    idt[12].set_func(exception::stack_segment);
    idt[13].set_func(exception::protection);
    idt[14].set_func(exception::page);
    // 15 reserved
    idt[16].set_func(exception::fpu_fault);
    idt[17].set_func(exception::alignment_check);
    idt[18].set_func(exception::machine_check);
    idt[19].set_func(exception::simd);
    idt[20].set_func(exception::virtualization);
    // 21 through 29 reserved
    idt[30].set_func(exception::security);
    // 31 reserved
}

const fn new_idt_reservations() -> [AtomicU32; 8] {
    [
        AtomicU32::new(0),
        AtomicU32::new(0),
        AtomicU32::new(0),
        AtomicU32::new(0),
        AtomicU32::new(0),
        AtomicU32::new(0),
        AtomicU32::new(0),
        AtomicU32::new(0),
    ]
}

/// Initialize the IDT for a
pub unsafe fn init_paging_post_heap(cpu_id: LogicalCpuId) {
    let mut idts_guard = IDTS.write();
    let idts_btree = idts_guard.get_or_insert_with(HashMap::new);

    if cpu_id == LogicalCpuId::BSP {
        idts_btree.insert(cpu_id, &mut *INIT_BSP_IDT.get());
    } else {
        let idt = idts_btree
            .entry(cpu_id)
            .or_insert_with(|| Box::leak(Box::new(Idt::new())));
        init_generic(cpu_id, idt);
    }
}

/// Initializes a fully functional IDT for use before it be moved into the map. This is ONLY called
/// on the BSP, since the kernel heap is ready for the APs.
pub unsafe fn init_paging_bsp() {
    init_generic(LogicalCpuId::BSP, &mut *INIT_BSP_IDT.get());
}

/// Initializes an IDT for any type of processor.
pub unsafe fn init_generic(cpu_id: LogicalCpuId, idt: &mut Idt) {
    let (current_idt, current_reservations) = (&mut idt.entries, &mut idt.reservations);

    let idtr: DescriptorTablePointer<X86IdtEntry> = DescriptorTablePointer {
        limit: (current_idt.len() * mem::size_of::<IdtEntry>() - 1) as u16,
        base: current_idt.as_ptr() as *const X86IdtEntry,
    };

    let backup_ist = {
        // We give Non-Maskable Interrupts, Double Fault, and Machine Check exceptions separate
        // stacks, since these (unless we are going to set up NMI watchdogs like Linux does) are
        // considered the most fatal, especially Double Faults which are caused by errors __when
        // accessing the system IDT__. If that goes wrong, then kernel memory may be partially
        // corrupt, and we want a separate stack.
        //
        // Note that each CPU has its own "backup interrupt stack".
        let index = 1_u8;

        // Put them in the 1st entry of the IST.
        #[cfg(target_arch = "x86_64")] // TODO: x86
        {
            use crate::paging::PAGE_SIZE;
            // Allocate 64 KiB of stack space for the backup stack.
            const BACKUP_STACK_SIZE: usize = PAGE_SIZE << 4;
            let frames = crate::memory::allocate_p2frame(4)
                .expect("failed to allocate pages for backup interrupt stack");

            use crate::paging::{RmmA, RmmArch};

            // Physical pages are mapped linearly. So is the linearly mapped virtual memory.
            let base_address = RmmA::phys_to_virt(frames.base());

            // Stack always grows downwards.
            let address = base_address.data() + BACKUP_STACK_SIZE;

            (*crate::gdt::pcr()).tss.ist[usize::from(index - 1)] = address as u64;
        }

        index
    };

    set_exceptions(current_idt);
    current_idt[2].set_ist(backup_ist);
    current_idt[8].set_ist(backup_ist);
    current_idt[18].set_ist(backup_ist);

    #[cfg(target_arch = "x86_64")]
    assert_eq!(
        __generic_interrupts_end as usize - __generic_interrupts_start as usize,
        224 * 8
    );

    #[cfg(target_arch = "x86_64")]
    for i in 0..224 {
        current_idt[i + 32].set_func(mem::transmute(__generic_interrupts_start as usize + i * 8));
    }

    // reserve bits 31:0, i.e. the first 32 interrupts, which are reserved for exceptions
    *current_reservations[0].get_mut() |= 0x0000_0000_FFFF_FFFF;

    if cpu_id == LogicalCpuId::BSP {
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
        *current_reservations[1].get_mut() |= 0x0003_FFFF;
    } else {
        // TODO: use_default_irqs! but also the legacy IRQs that are only needed on one CPU
        current_idt[49].set_func(irq::lapic_error);

        // reserve bit 49
        *current_reservations[1].get_mut() |= 1 << 17;
    }

    #[cfg(target_arch = "x86")]
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

    #[cfg(target_arch = "x86")]
    {
        let current_idt = &mut idt.entries;
        // Set syscall function
        current_idt[0x80].set_func(syscall::syscall);
        current_idt[0x80].set_flags(IdtFlags::PRESENT | IdtFlags::RING_3 | IdtFlags::INTERRUPT);
        idt.set_reserved_mut(0x80, true);
    }

    #[cfg(feature = "profiling")]
    crate::profiling::maybe_setup_timer(idt, cpu_id);

    dtables::lidt(&idtr);
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
#[repr(C, packed)]
pub struct IdtEntry {
    offsetl: u16,
    selector: u16,
    zero: u8,
    attribute: u8,
    offsetm: u16,
    #[cfg(target_arch = "x86_64")]
    offseth: u32,
    #[cfg(target_arch = "x86_64")]
    _zero2: u32,
}

impl IdtEntry {
    pub const fn new() -> IdtEntry {
        IdtEntry {
            offsetl: 0,
            selector: 0,
            zero: 0,
            attribute: 0,
            offsetm: 0,
            #[cfg(target_arch = "x86_64")]
            offseth: 0,
            #[cfg(target_arch = "x86_64")]
            _zero2: 0,
        }
    }

    pub fn set_flags(&mut self, flags: IdtFlags) {
        self.attribute = flags.bits();
    }

    pub fn set_ist(&mut self, ist: u8) {
        assert_eq!(
            ist & 0x07,
            ist,
            "interrupt stack table must be within 0..=7"
        );
        self.zero &= 0xF8;
        self.zero |= ist;
    }

    pub fn set_offset(&mut self, selector: u16, base: usize) {
        self.selector = selector;
        self.offsetl = base as u16;
        self.offsetm = (base >> 16) as u16;
        #[cfg(target_arch = "x86_64")]
        {
            self.offseth = ((base as u64) >> 32) as u32;
        }
    }

    // A function to set the offset more easily
    pub fn set_func(&mut self, func: unsafe extern "C" fn()) {
        self.set_flags(IdtFlags::PRESENT | IdtFlags::RING_0 | IdtFlags::INTERRUPT);
        self.set_offset((crate::gdt::GDT_KERNEL_CODE as u16) << 3, func as usize);
    }
}
