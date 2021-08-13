use crate::paging::{ActivePageTable, Page, PageFlags, VirtualAddress, mapper::PageFlushAll, entry::EntryFlags};

#[cfg(not(feature="slab"))]
pub use self::linked_list::Allocator;

#[cfg(feature="slab")]
pub use self::slab::Allocator;

#[cfg(not(feature="slab"))]
mod linked_list;

#[cfg(feature="slab")]
mod slab;

unsafe fn map_heap(active_table: &mut ActivePageTable, offset: usize, size: usize) {
    let flush_all = PageFlushAll::new();

    let heap_start_page = Page::containing_address(VirtualAddress::new(offset));
    let heap_end_page = Page::containing_address(VirtualAddress::new(offset + size-1));
    for page in Page::range_inclusive(heap_start_page, heap_end_page) {
        let result = active_table.map(page, PageFlags::new().write(true).custom_flag(EntryFlags::GLOBAL.bits(), cfg!(not(feature = "pti"))))
            .expect("failed to map kernel heap");
        flush_all.consume(result);
    }

    flush_all.flush();
}

pub unsafe fn init(active_table: &mut ActivePageTable) {
    let offset = crate::KERNEL_HEAP_OFFSET;
    let size = crate::KERNEL_HEAP_SIZE;

    // Map heap pages
    map_heap(active_table, offset, size);

    // Initialize global heap
    Allocator::init(offset, size);
}
