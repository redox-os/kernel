use core::mem;

use super::{find_sdt, sdt::Sdt};

/// The Multiple APIC Descriptor Table
#[derive(Clone, Copy, Debug)]
pub struct Madt {
    sdt: &'static Sdt,
    pub local_address: u32,
    pub flags: u32,
}

#[cfg(target_arch = "aarch64")]
#[path = "arch/aarch64.rs"]
mod arch;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[path = "arch/x86.rs"]
mod arch;

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86", target_arch = "x86_64")))]
#[path = "arch/other.rs"]
mod arch;

pub static mut MADT: Option<Madt> = None;
pub const FLAG_PCAT: u32 = 1;

impl Madt {
    pub fn init() {
        let madt_sdt = find_sdt("APIC");
        let madt = if madt_sdt.len() == 1 {
            Madt::new(madt_sdt[0])
        } else {
            println!("Unable to find MADT");
            return;
        };

        if let Some(madt) = madt {
            // safe because no APs have been started yet.
            unsafe { MADT = Some(madt) };

            println!("  APIC: {:>08X}: {}", madt.local_address, madt.flags);

            arch::init(madt);
        }
    }

    pub fn new(sdt: &'static Sdt) -> Option<Madt> {
        if &sdt.signature == b"APIC" && sdt.data_len() >= 8 {
            //Not valid if no local address and flags
            let local_address = unsafe { (sdt.data_address() as *const u32).read_unaligned() };
            let flags = unsafe {
                (sdt.data_address() as *const u32)
                    .offset(1)
                    .read_unaligned()
            };

            Some(Madt {
                sdt,
                local_address,
                flags,
            })
        } else {
            None
        }
    }

    pub fn iter(&self) -> MadtIter {
        MadtIter {
            sdt: self.sdt,
            i: 8, // Skip local controller address and flags
        }
    }
}

/// MADT Local APIC
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct MadtLocalApic {
    /// Processor ID
    pub processor: u8,
    /// Local APIC ID
    pub id: u8,
    /// Flags. 1 means that the processor is enabled
    pub flags: u32,
}

/// MADT I/O APIC
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct MadtIoApic {
    /// I/O APIC ID
    pub id: u8,
    /// reserved
    _reserved: u8,
    /// I/O APIC address
    pub address: u32,
    /// Global system interrupt base
    pub gsi_base: u32,
}

/// MADT Interrupt Source Override
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct MadtIntSrcOverride {
    /// Bus Source
    pub bus_source: u8,
    /// IRQ Source
    pub irq_source: u8,
    /// Global system interrupt base
    pub gsi_base: u32,
    /// Flags
    pub flags: u16,
}

/// MADT GICC
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct MadtGicc {
    _reserved: u16,
    pub cpu_interface_number: u32,
    pub acpi_processor_uid: u32,
    pub flags: u32,
    pub parking_protocol_version: u32,
    pub performance_interrupt_gsiv: u32,
    pub parked_address: u64,
    pub physical_base_address: u64,
    pub gicv: u64,
    pub gich: u64,
    pub vgic_maintenance_interrupt: u32,
    pub gicr_base_address: u64,
    pub mpidr: u64,
    pub processor_power_efficiency_class: u8,
    _reserved2: u8,
    pub spe_overflow_interrupt: u16,
    //TODO: optional field introduced in ACPI 6.5: pub trbe_interrupt: u16,
}

/// MADT GICD
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct MadtGicd {
    _reserved: u16,
    pub gic_id: u32,
    pub physical_base_address: u64,
    pub system_vector_base: u32,
    pub gic_version: u8,
    _reserved2: [u8; 3],
}

/// MADT Entries
#[derive(Debug)]
pub enum MadtEntry {
    LocalApic(&'static MadtLocalApic),
    InvalidLocalApic(usize),
    IoApic(&'static MadtIoApic),
    InvalidIoApic(usize),
    IntSrcOverride(&'static MadtIntSrcOverride),
    InvalidIntSrcOverride(usize),
    Gicc(&'static MadtGicc),
    InvalidGicc(usize),
    Gicd(&'static MadtGicd),
    InvalidGicd(usize),
    Unknown(u8),
}

pub struct MadtIter {
    sdt: &'static Sdt,
    i: usize,
}

impl Iterator for MadtIter {
    type Item = MadtEntry;
    fn next(&mut self) -> Option<Self::Item> {
        if self.i + 1 < self.sdt.data_len() {
            let entry_type = unsafe { *(self.sdt.data_address() as *const u8).add(self.i) };
            let entry_len =
                unsafe { *(self.sdt.data_address() as *const u8).add(self.i + 1) } as usize;

            if self.i + entry_len <= self.sdt.data_len() {
                let item = match entry_type {
                    0x0 => {
                        if entry_len == mem::size_of::<MadtLocalApic>() + 2 {
                            MadtEntry::LocalApic(unsafe {
                                &*((self.sdt.data_address() + self.i + 2) as *const MadtLocalApic)
                            })
                        } else {
                            MadtEntry::InvalidLocalApic(entry_len)
                        }
                    }
                    0x1 => {
                        if entry_len == mem::size_of::<MadtIoApic>() + 2 {
                            MadtEntry::IoApic(unsafe {
                                &*((self.sdt.data_address() + self.i + 2) as *const MadtIoApic)
                            })
                        } else {
                            MadtEntry::InvalidIoApic(entry_len)
                        }
                    }
                    0x2 => {
                        if entry_len == mem::size_of::<MadtIntSrcOverride>() + 2 {
                            MadtEntry::IntSrcOverride(unsafe {
                                &*((self.sdt.data_address() + self.i + 2)
                                    as *const MadtIntSrcOverride)
                            })
                        } else {
                            MadtEntry::InvalidIntSrcOverride(entry_len)
                        }
                    }
                    0xB => {
                        if entry_len >= mem::size_of::<MadtGicc>() + 2 {
                            MadtEntry::Gicc(unsafe {
                                &*((self.sdt.data_address() + self.i + 2) as *const MadtGicc)
                            })
                        } else {
                            MadtEntry::InvalidGicc(entry_len)
                        }
                    }
                    0xC => {
                        if entry_len >= mem::size_of::<MadtGicd>() + 2 {
                            MadtEntry::Gicd(unsafe {
                                &*((self.sdt.data_address() + self.i + 2) as *const MadtGicd)
                            })
                        } else {
                            MadtEntry::InvalidGicd(entry_len)
                        }
                    }
                    _ => MadtEntry::Unknown(entry_type),
                };

                self.i += entry_len;

                Some(item)
            } else {
                None
            }
        } else {
            None
        }
    }
}
