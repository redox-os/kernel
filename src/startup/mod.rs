pub mod memory;

#[repr(C, packed(8))]
pub(crate) struct KernelArgs {
    pub(crate) kernel_base: u64,
    pub(crate) kernel_size: u64,

    pub(crate) stack_base: u64,
    pub(crate) stack_size: u64,

    pub(crate) env_base: u64,
    pub(crate) env_size: u64,

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

    pub(crate) areas_base: u64,
    pub(crate) areas_size: u64,

    /// The physical base 64-bit pointer to the contiguous bootstrap/initfs.
    pub(crate) bootstrap_base: u64,
    /// Size of contiguous bootstrap/initfs physical region, not necessarily page aligned.
    pub(crate) bootstrap_size: u64,
}

impl KernelArgs {
    pub(crate) fn print(&self) {
        info!(
            "Kernel: {:X}:{:X}",
            { self.kernel_base },
            self.kernel_base + self.kernel_size
        );
        info!(
            "Stack: {:X}:{:X}",
            { self.stack_base },
            self.stack_base + self.stack_size
        );
        info!(
            "Env: {:X}:{:X}",
            { self.env_base },
            self.env_base + self.env_size
        );
        info!(
            "HWDESC: {:X}:{:X}",
            { self.hwdesc_base },
            self.hwdesc_base + self.hwdesc_size
        );
        info!(
            "Areas: {:X}:{:X}",
            { self.areas_base },
            self.areas_base + self.areas_size
        );
        info!(
            "Bootstrap: {:X}:{:X}",
            { self.bootstrap_base },
            self.bootstrap_base + self.bootstrap_size
        );
    }
}
