use core::slice;

pub mod memory;

#[repr(C, packed(8))]
pub(crate) struct KernelArgs {
    kernel_base: u64,
    kernel_size: u64,

    pub(crate) stack_base: u64,
    pub(crate) stack_size: u64,

    env_base: u64,
    env_size: u64,

    /// The base pointer to the saved RSDP or device tree blob.
    ///
    /// On x86 this field can be NULL, and if so, the system has not booted
    /// with UEFI or in some other way retrieved the RSDPs. The kernel or a
    /// userspace driver will thus try searching the BIOS memory instead. On
    /// UEFI systems, searching is not guaranteed to actually work though.
    /// On other architectures this field must always contain a pointer to
    /// either an RSDP or device tree blob.
    pub(crate) hwdesc_base: u64,
    pub(crate) hwdesc_size: u64,

    areas_base: u64,
    areas_size: u64,

    /// The physical base 64-bit pointer to the contiguous bootstrap/initfs.
    bootstrap_base: u64,
    /// Size of contiguous bootstrap/initfs physical region, not necessarily page aligned.
    bootstrap_size: u64,
}

impl KernelArgs {
    pub(crate) fn print(&self) {
        debug!(
            "Kernel: {:X}:{:X}",
            { self.kernel_base },
            self.kernel_base + self.kernel_size
        );
        debug!(
            "Env: {:X}:{:X}",
            { self.env_base },
            self.env_base + self.env_size
        );
        debug!(
            "HWDESC: {:X}:{:X}",
            { self.hwdesc_base },
            self.hwdesc_base + self.hwdesc_size
        );
        debug!(
            "Areas: {:X}:{:X}",
            { self.areas_base },
            self.areas_base + self.areas_size
        );
        debug!(
            "Bootstrap: {:X}:{:X}",
            { self.bootstrap_base },
            self.bootstrap_base + self.bootstrap_size
        );
    }

    pub(crate) fn bootstrap(&self) -> crate::Bootstrap {
        crate::Bootstrap {
            base: crate::memory::Frame::containing(crate::paging::PhysicalAddress::new(
                self.bootstrap_base as usize,
            )),
            page_count: (self.bootstrap_size as usize) / crate::memory::PAGE_SIZE,
            env: self.env(),
        }
    }

    pub(crate) fn env(&self) -> &'static [u8] {
        unsafe {
            slice::from_raw_parts(
                (crate::PHYS_OFFSET + self.env_base as usize) as *const u8,
                self.env_size as usize,
            )
        }
    }

    #[cfg(feature = "acpi")]
    pub(crate) fn acpi_rsdp(&self) -> Option<*const u8> {
        if self.hwdesc_base != 0 {
            let data = unsafe {
                slice::from_raw_parts(
                    (crate::PHYS_OFFSET + self.hwdesc_base as usize) as *const u8,
                    self.hwdesc_size as usize,
                )
            };
            if data.starts_with(b"RSD PTR ") {
                Some(data.as_ptr())
            } else {
                None
            }
        } else {
            None
        }
    }

    #[cfg(dtb)]
    pub(crate) fn dtb(&self) -> Option<fdt::Fdt<'static>> {
        if self.hwdesc_base != 0 {
            let data = unsafe {
                slice::from_raw_parts(
                    (crate::PHYS_OFFSET + self.hwdesc_base as usize) as *const u8,
                    self.hwdesc_size as usize,
                )
            };
            fdt::Fdt::new(data).ok()
        } else {
            None
        }
    }
}
