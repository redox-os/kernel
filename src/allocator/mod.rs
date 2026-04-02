use crate::{
    memory::KernelMapper,
    paging::{mapper::PageFlushAll, Page, PageFlags, VirtualAddress},
};
use rmm::{Flusher, FrameAllocator};

pub use self::linked_list::Allocator;
mod linked_list;

/// Size of kernel heap
const KERNEL_HEAP_SIZE: usize = ::rmm::MEGABYTE;

unsafe fn map_heap(mapper: &mut KernelMapper<true>, offset: usize, size: usize) {
    let mut flush_all = PageFlushAll::new();

    let heap_start_page = Page::containing_address(VirtualAddress::new(offset));
    let heap_end_page = Page::containing_address(VirtualAddress::new(offset + size - 1));
    for page in Page::range_inclusive(heap_start_page, heap_end_page) {
        let phys = mapper
            .allocator_mut()
            .allocate_one()
            .expect("failed to allocate kernel heap");
        let flush = unsafe {
            mapper
                .map_phys(
                    page.start_address(),
                    phys,
                    PageFlags::new()
                        .write(true)
                        .global(cfg!(not(feature = "pti"))),
                )
                .expect("failed to map kernel heap")
        };
        flush_all.consume(flush);
    }

    flush_all.flush();
}

pub unsafe fn init() {
    unsafe {
        let offset = crate::kernel_heap_offset();
        let size = KERNEL_HEAP_SIZE;

        // Map heap pages
        map_heap(&mut KernelMapper::lock_rw(), offset, size);

        // Initialize global heap
        Allocator::init(offset, size);
    }
}
