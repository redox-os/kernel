use rmm::PhysicalAddress;

/// RSDP
#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
pub struct Rsdp {
    signature: [u8; 8],
    _checksum: u8,
    _oemid: [u8; 6],
    revision: u8,
    rsdt_address: u32,
    _length: u32,
    xsdt_address: u64,
    _extended_checksum: u8,
    _reserved: [u8; 3],
}

impl Rsdp {
    pub unsafe fn get_rsdp(already_supplied_rsdp: Option<*const u8>) -> Option<Rsdp> {
        already_supplied_rsdp.map(|rsdp_ptr| {
            // TODO: Validate
            unsafe { *(rsdp_ptr as *const Rsdp) }
        })
    }

    /// Get the RSDT or XSDT address
    pub fn sdt_address(&self) -> PhysicalAddress {
        PhysicalAddress::new(if self.revision >= 2 {
            self.xsdt_address as usize
        } else {
            self.rsdt_address as usize
        })
    }
}
