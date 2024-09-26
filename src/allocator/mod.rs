use crate::{
    memory::KernelMapper,
    paging::{mapper::PageFlushAll, Page, PageFlags, VirtualAddress},
};
use rmm::Flusher;

#[cfg(not(feature = "slab"))]
pub use self::linked_list::Allocator;

#[cfg(feature = "slab")]
pub use self::slab::Allocator;

#[cfg(not(feature = "slab"))]
mod linked_list;

#[cfg(feature = "slab")]
mod slab;

unsafe fn map_heap(mapper: &mut KernelMapper, offset: usize, size: usize) {
    let mapper = mapper
        .get_mut()
        .expect("failed to obtain exclusive access to KernelMapper while extending heap");
    let mut flush_all = PageFlushAll::new();

    let heap_start_page = Page::containing_address(VirtualAddress::new(offset));
    let heap_end_page = Page::containing_address(VirtualAddress::new(offset + size - 1));
    for page in Page::range_inclusive(heap_start_page, heap_end_page) {
        let result = mapper
            .map(
                page.start_address(),
                PageFlags::new()
                    .write(true)
                    .global(cfg!(not(feature = "pti"))),
            )
            .expect("failed to map kernel heap");
        flush_all.consume(result);
    }

    flush_all.flush();
}

pub unsafe fn init() {
    let offset = crate::KERNEL_HEAP_OFFSET;
    let size = crate::KERNEL_HEAP_SIZE;

    // Map heap pages
    map_heap(&mut KernelMapper::lock(), offset, size);

    // Initialize global heap
    Allocator::init(offset, size);
}
