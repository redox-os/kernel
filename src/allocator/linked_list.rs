use core::alloc::{GlobalAlloc, Layout};
use core::ptr::{self, NonNull};
use linked_list_allocator::Heap;
use spin::Mutex;

use crate::paging::{ActivePageTable, TableKind};

static HEAP: Mutex<Option<Heap>> = Mutex::new(None);

pub struct Allocator;

impl Allocator {
    pub unsafe fn init(offset: usize, size: usize) {
        *HEAP.lock() = Some(Heap::new(offset, size));
    }
}

unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        while let Some(ref mut heap) = *HEAP.lock() {
            match heap.allocate_first_fit(layout) {
                Err(()) => {
                    let size = heap.size();
                    super::map_heap(&mut ActivePageTable::new(TableKind::Kernel), crate::KERNEL_HEAP_OFFSET + size, crate::KERNEL_HEAP_SIZE);
                    heap.extend(crate::KERNEL_HEAP_SIZE);
                },
                other => return other.ok().map_or(ptr::null_mut(), |allocation| allocation.as_ptr()),
            }
        }
        panic!("__rust_allocate: heap not initialized");
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if let Some(ref mut heap) = *HEAP.lock() {
            heap.deallocate(NonNull::new_unchecked(ptr), layout)
        } else {
            panic!("__rust_deallocate: heap not initialized");
        }
    }
}
