use rmm::{Arch, PageFlags, VirtualAddress};

pub struct KernelMapper {
    mapper: crate::paging::PageMapper,
    ro: bool,
}
impl KernelMapper {
    pub fn lock() -> Self {
        unimplemented!()
    }
    pub fn get_mut(&mut self) -> Option<&mut crate::paging::PageMapper> {
        unimplemented!()
    }
}

pub unsafe fn page_flags<A: Arch>(virt: VirtualAddress) -> PageFlags<A> {
    use crate::kernel_executable_offsets::*;
    let virt_addr = virt.data();

    if virt_addr >= __text_start() && virt_addr < __text_end() {
        // Remap text read-only, execute
        PageFlags::new().execute(true)
    } else if virt_addr >= __rodata_start() && virt_addr < __rodata_end() {
        // Remap rodata read-only, no execute
        PageFlags::new()
    } else {
        // Remap everything else read-write, no execute
        PageFlags::new().write(true)
    }
}
