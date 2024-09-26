use crate::{
    memory::{Frame, KernelMapper},
    paging::{Page, PageFlags, PhysicalAddress, VirtualAddress},
};

/// RSDP
#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
pub struct RSDP {
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

impl RSDP {
    fn get_already_supplied_rsdp(rsdp_ptr: *const u8) -> RSDP {
        // TODO: Validate
        unsafe { *(rsdp_ptr as *const RSDP) }
    }
    pub fn get_rsdp(
        mapper: &mut KernelMapper,
        already_supplied_rsdp: Option<*const u8>,
    ) -> Option<RSDP> {
        if let Some(rsdp_ptr) = already_supplied_rsdp {
            Some(Self::get_already_supplied_rsdp(rsdp_ptr))
        } else {
            Self::get_rsdp_by_searching(mapper)
        }
    }
    /// Search for the RSDP
    pub fn get_rsdp_by_searching(mapper: &mut KernelMapper) -> Option<RSDP> {
        let start_addr = 0xE_0000;
        let end_addr = 0xF_FFFF;

        // Map all of the ACPI RSDP space
        {
            let start_frame = Frame::containing(PhysicalAddress::new(start_addr));
            let end_frame = Frame::containing(PhysicalAddress::new(end_addr));
            for frame in Frame::range_inclusive(start_frame, end_frame) {
                let page = Page::containing_address(VirtualAddress::new(frame.base().data()));
                let result = unsafe {
                    mapper
                        .get_mut()
                        .expect("KernelMapper locked re-entrant while locating RSDPs")
                        .map_phys(page.start_address(), frame.base(), PageFlags::new())
                        .expect("failed to map page while searching for RSDP")
                };
                result.flush();
            }
        }

        RSDP::search(start_addr, end_addr)
    }

    fn search(start_addr: usize, end_addr: usize) -> Option<RSDP> {
        for i in 0..(end_addr + 1 - start_addr) / 16 {
            let rsdp = unsafe { &*((start_addr + i * 16) as *const RSDP) };
            if &rsdp.signature == b"RSD PTR " {
                return Some(*rsdp);
            }
        }
        None
    }

    /// Get the RSDT or XSDT address
    pub fn sdt_address(&self) -> usize {
        if self.revision >= 2 {
            self.xsdt_address as usize
        } else {
            self.rsdt_address as usize
        }
    }
}
