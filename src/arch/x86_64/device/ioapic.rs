use core::{fmt, ptr};

use alloc::vec::Vec;
use spin::Mutex;

#[cfg(feature = "acpi")]
use crate::acpi::madt::{self, Madt, MadtEntry, MadtIoApic, MadtIntSrcOverride};

use crate::arch::interrupt::irq;
use crate::memory::Frame;
use crate::paging::{ActivePageTable, Page, PageFlags, PhysicalAddress, VirtualAddress};
use crate::paging::entry::EntryFlags;

use super::pic;

pub struct IoApicRegs {
    pointer: *const u32,
}
impl IoApicRegs {
    fn ioregsel(&self) -> *const u32 {
        self.pointer
    }
    fn iowin(&self) -> *const u32 {
        // offset 0x10
        unsafe { self.pointer.offset(4) }
    }
    fn write_ioregsel(&mut self, value: u32) {
        unsafe { ptr::write_volatile::<u32>(self.ioregsel() as *mut u32, value) }
    }
    fn read_iowin(&self) -> u32 {
        unsafe { ptr::read_volatile::<u32>(self.iowin()) }
    }
    fn write_iowin(&mut self, value: u32) {
        unsafe { ptr::write_volatile::<u32>(self.iowin() as *mut u32, value) }
    }
    fn read_reg(&mut self, reg: u8) -> u32 {
        self.write_ioregsel(reg.into());
        self.read_iowin()
    }
    fn write_reg(&mut self, reg: u8, value: u32) {
        self.write_ioregsel(reg.into());
        self.write_iowin(value);
    }
    pub fn read_ioapicid(&mut self) -> u32 {
        self.read_reg(0x00)
    }
    pub fn write_ioapicid(&mut self, value: u32) {
        self.write_reg(0x00, value);
    }
    pub fn read_ioapicver(&mut self) -> u32 {
        self.read_reg(0x01)
    }
    pub fn read_ioapicarb(&mut self) -> u32 {
        self.read_reg(0x02)
    }
    pub fn read_ioredtbl(&mut self, idx: u8) -> u64 {
        assert!(idx < 24);
        let lo = self.read_reg(0x10 + idx * 2);
        let hi = self.read_reg(0x10 + idx * 2 + 1);

        u64::from(lo) | (u64::from(hi) << 32)
    }
    pub fn write_ioredtbl(&mut self, idx: u8, value: u64) {
        assert!(idx < 24);

        let lo = value as u32;
        let hi = (value >> 32) as u32;

        self.write_reg(0x10 + idx * 2, lo);
        self.write_reg(0x10 + idx * 2 + 1, hi);
    }

    pub fn max_redirection_table_entries(&mut self) -> u8 {
        let ver = self.read_ioapicver();
        ((ver & 0x00FF_0000) >> 16) as u8
    }
    pub fn id(&mut self) -> u8 {
        let id_reg = self.read_ioapicid();
        ((id_reg & 0x0F00_0000) >> 24) as u8
    }
}
pub struct IoApic {
    regs: Mutex<IoApicRegs>,
    gsi_start: u32,
    count: u8,
}
impl IoApic {
    pub fn new(regs_base: *const u32, gsi_start: u32) -> Self {
        let mut regs = IoApicRegs { pointer: regs_base };
        let count = regs.max_redirection_table_entries();

        Self {
            regs: Mutex::new(regs),
            gsi_start,
            count,
        }
    }
    /// Map an interrupt vector to a physical local APIC ID of a processor (thus physical mode).
    pub fn map(&self, idx: u8, info: MapInfo) {
        self.regs.lock().write_ioredtbl(idx, info.as_raw())
    }
    pub fn set_mask(&self, gsi: u32, mask: bool) {
        let idx = (gsi - self.gsi_start) as u8;
        let mut guard = self.regs.lock();

        let mut reg = guard.read_ioredtbl(idx);
        reg &= !(1 << 16);
        reg |= u64::from(mask) << 16;
        guard.write_ioredtbl(idx, reg);
    }
}
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum ApicTriggerMode {
    Edge = 0,
    Level = 1,
}
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum ApicPolarity {
    ActiveHigh = 0,
    ActiveLow = 1,
}
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum DestinationMode {
    Physical = 0,
    Logical = 1,
}
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum DeliveryMode {
    Fixed =             0b000,
    LowestPriority =    0b001,
    Smi =               0b010,
    Nmi =               0b100,
    Init =              0b101,
    ExtInt =            0b111,
}

#[derive(Clone, Copy, Debug)]
pub struct MapInfo {
    pub dest: u8,
    pub mask: bool,
    pub trigger_mode: ApicTriggerMode,
    pub polarity: ApicPolarity,
    pub dest_mode: DestinationMode,
    pub delivery_mode: DeliveryMode,
    pub vector: u8,
}

impl MapInfo {
    pub fn as_raw(&self) -> u64 {
        assert!(self.vector >= 0x20);
        assert!(self.vector <= 0xFE);

        // TODO: Check for reserved fields.

        (u64::from(self.dest) << 56)
            | (u64::from(self.mask) << 16)
            | ((self.trigger_mode as u64) << 15)
            | ((self.polarity as u64) << 13)
            | ((self.dest_mode as u64) << 11)
            | ((self.delivery_mode as u64) << 8)
            | u64::from(self.vector)
    }
}

impl fmt::Debug for IoApic {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        struct RedirTable<'a>(&'a Mutex<IoApicRegs>);

        impl<'a> fmt::Debug for RedirTable<'a> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                let mut guard = self.0.lock();

                let count = guard.max_redirection_table_entries();
                f.debug_list().entries((0..count).map(|i| guard.read_ioredtbl(i))).finish()
            }
        }

        f.debug_struct("IoApic")
            .field("redir_table", &RedirTable(&self.regs))
            .field("gsi_start", &self.gsi_start)
            .field("count", &self.count)
            .finish()
    }
}

#[derive(Clone, Copy, Debug)]
pub enum TriggerMode {
    ConformsToSpecs,
    Edge,
    Level,
}

#[derive(Clone, Copy, Debug)]
pub enum Polarity {
    ConformsToSpecs,
    ActiveHigh,
    ActiveLow,
}

#[derive(Clone, Copy, Debug)]
pub struct Override {
    bus_irq: u8,
    gsi: u32,

    trigger_mode: TriggerMode,
    polarity: Polarity,
}

// static mut because only the AP initializes the I/O Apic, and when that is done, it's solely
// accessed immutably.
static mut IOAPICS: Option<Vec<IoApic>> = None;

// static mut for the same reason as above
static mut SRC_OVERRIDES: Option<Vec<Override>> = None;

pub fn ioapics() -> &'static [IoApic] {
    unsafe {
        IOAPICS.as_ref().map_or(&[], |vector| &vector[..])
    }
}
pub fn src_overrides() -> &'static [Override] {
    unsafe {
        SRC_OVERRIDES.as_ref().map_or(&[], |vector| &vector[..])
    }
}

#[cfg(feature = "acpi")]
pub unsafe fn handle_ioapic(active_table: &mut ActivePageTable, madt_ioapic: &'static MadtIoApic) {
    // map the I/O APIC registers

    let frame = Frame::containing_address(PhysicalAddress::new(madt_ioapic.address as usize));
    let page = Page::containing_address(VirtualAddress::new(madt_ioapic.address as usize + crate::PHYS_OFFSET));

    assert_eq!(active_table.translate_page(page), None);

    let result = active_table.map_to(page, frame, PageFlags::new().write(true).custom_flag(EntryFlags::NO_CACHE.bits(), true));
    result.flush();

    let ioapic_registers = page.start_address().data() as *const u32;
    let ioapic = IoApic::new(ioapic_registers, madt_ioapic.gsi_base);

    assert_eq!(ioapic.regs.lock().id(), madt_ioapic.id, "mismatched ACPI MADT I/O APIC ID, and the ID reported by the I/O APIC");

    IOAPICS.get_or_insert_with(Vec::new).push(ioapic);
}
#[cfg(feature = "acpi")]
pub unsafe fn handle_src_override(src_override: &'static MadtIntSrcOverride) {
    let flags = src_override.flags;

    let polarity_raw = (flags & 0x0003) as u8;
    let trigger_mode_raw = ((flags & 0x000C) >> 2) as u8;

    let polarity = match polarity_raw {
        0b00 => Polarity::ConformsToSpecs,
        0b01 => Polarity::ActiveHigh,
        0b10 => return, // reserved
        0b11 => Polarity::ActiveLow,

        _ => unreachable!(),
    };

    let trigger_mode = match trigger_mode_raw {
        0b00 => TriggerMode::ConformsToSpecs,
        0b01 => TriggerMode::Edge,
        0b10 => return, // reserved
        0b11 => TriggerMode::Level,
        _ => unreachable!(),
    };

    let over = Override {
        bus_irq: src_override.irq_source,
        gsi: src_override.gsi_base,
        polarity,
        trigger_mode,
    };
    SRC_OVERRIDES.get_or_insert_with(Vec::new).push(over);
}

pub unsafe fn init(active_table: &mut ActivePageTable) {
    let bsp_apic_id = x86::cpuid::CpuId::new().get_feature_info().unwrap().initial_local_apic_id(); // TODO

    // search the madt for all IOAPICs.
    #[cfg(feature = "acpi")]
    {
        let madt: &'static Madt = match madt::MADT.as_ref() {
            Some(m) => m,
            // TODO: Parse MP tables too.
            None => return,
        };
        if madt.flags & madt::FLAG_PCAT != 0 {
            pic::disable();
        }

        // find all I/O APICs (usually one).

        for entry in madt.iter() {
            match entry {
                MadtEntry::IoApic(ioapic) => handle_ioapic(active_table, ioapic),
                MadtEntry::IntSrcOverride(src_override) => handle_src_override(src_override),
                _ => (),
            }
        }
    }
    println!("I/O APICs: {:?}, overrides: {:?}", ioapics(), src_overrides());

    // map the legacy PC-compatible IRQs (0-15) to 32-47, just like we did with 8259 PIC (if it
    // wouldn't have been disabled due to this I/O APIC)
    for legacy_irq in 0..=15 {
        let (gsi, trigger_mode, polarity) = match get_override(legacy_irq) {
            Some(over) => (over.gsi, over.trigger_mode, over.polarity),
            None => {
                if src_overrides().iter().any(|over| over.gsi == u32::from(legacy_irq) && over.bus_irq != legacy_irq) && !src_overrides().iter().any(|over| over.bus_irq == legacy_irq) {
                    // there's an IRQ conflict, making this legacy IRQ inaccessible.
                    continue;
                }
                (legacy_irq.into(), TriggerMode::ConformsToSpecs, Polarity::ConformsToSpecs)
            }
        };
        let apic = match find_ioapic(gsi) {
            Some(ioapic) => ioapic,
            None => {
                println!("Unable to find a suitable APIC for legacy IRQ {} (GSI {}). It will not be mapped.", legacy_irq, gsi);
                continue;
            }
        };
        let redir_tbl_index = (gsi - apic.gsi_start) as u8;

        let map_info = MapInfo {
            // only send to the BSP
            dest: bsp_apic_id,
            dest_mode: DestinationMode::Physical,
            delivery_mode: DeliveryMode::Fixed,
            mask: false,
            polarity: match polarity {
                Polarity::ActiveHigh => ApicPolarity::ActiveHigh,
                Polarity::ActiveLow => ApicPolarity::ActiveLow,
                Polarity::ConformsToSpecs => ApicPolarity::ActiveHigh,
            },
            trigger_mode: match trigger_mode {
                TriggerMode::Edge => ApicTriggerMode::Edge,
                TriggerMode::Level => ApicTriggerMode::Level,
                TriggerMode::ConformsToSpecs => ApicTriggerMode::Edge,
            },
            vector: 32 + legacy_irq,
        };
        apic.map(redir_tbl_index, map_info);
    }
    println!("I/O APICs: {:?}, overrides: {:?}", ioapics(), src_overrides());
    irq::set_irq_method(irq::IrqMethod::Apic);

    // tell the firmware that we're using APIC rather than the default 8259 PIC.

    // FIXME: With ACPI moved to userspace, we should instead allow userspace to check whether the
    // IOAPIC has been initialized, and then subsequently let some ACPI driver call the AML from
    // userspace.

    /*#[cfg(feature = "acpi")]
    {
        let method = {
            let namespace_guard = crate::acpi::ACPI_TABLE.namespace.read();
            if let Some(value) = namespace_guard.as_ref().unwrap().get("\\_PIC") {
                value.get_as_method().ok()
            } else {
                None
            }
        };
        if let Some(m) = method {
            m.execute("\\_PIC".into(), vec!(crate::acpi::aml::AmlValue::Integer(1)));
        }
    }*/
}
fn get_override(irq: u8) -> Option<&'static Override> {
    src_overrides().iter().find(|over| over.bus_irq == irq)
}
fn resolve(irq: u8) -> u32 {
    get_override(irq).map_or(u32::from(irq), |over| over.gsi)
}
fn find_ioapic(gsi: u32) -> Option<&'static IoApic> {
    ioapics().iter().find(|apic| gsi >= apic.gsi_start && gsi < apic.gsi_start + u32::from(apic.count))
}

pub unsafe fn mask(irq: u8) {
    let gsi = resolve(irq);
    let apic = match find_ioapic(gsi) {
        Some(a) => a,
        None => return,
    };
    apic.set_mask(gsi, true);
}
pub unsafe fn unmask(irq: u8) {
    let gsi = resolve(irq);
    let apic = match find_ioapic(gsi) {
        Some(a) => a,
        None => return,
    };
    apic.set_mask(gsi, false);
}
