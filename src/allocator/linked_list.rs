use core::alloc::{AllocErr, GlobalAlloc, Layout};
use core::ptr::NonNull;
use linked_list_allocator::Heap;
use spin::Mutex;

use crate::paging::ActivePageTable;

static HEAP: Mutex<Option<Heap>> = Mutex::new(None);

pub struct Allocator;

impl Allocator {
    pub unsafe fn init(offset: usize, size: usize) {
        *HEAP.lock() = Some(Heap::new(offset, size));
    }
}

unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        loop {
            let res = if let Some(ref mut heap) = *HEAP.lock() {
                heap.allocate_first_fit(layout)
            } else {
                panic!("__rust_allocate: heap not initialized");
            };

            match res {
                Err(AllocErr) => {
                    let size = if let Some(ref heap) = *HEAP.lock() {
                        heap.size()
                    } else {
                        panic!("__rust_allocate: heap not initialized");
                    };

                    super::map_heap(&mut ActivePageTable::new(), crate::KERNEL_HEAP_OFFSET + size, crate::KERNEL_HEAP_SIZE);

                    if let Some(ref mut heap) = *HEAP.lock() {
                        heap.extend(crate::KERNEL_HEAP_SIZE);
                    } else {
                        panic!("__rust_allocate: heap not initialized");
                    }
                },
                other => return other.ok().map_or(0 as *mut u8, |allocation| allocation.as_ptr()),
            }
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if let Some(ref mut heap) = *HEAP.lock() {
            heap.deallocate(NonNull::new_unchecked(ptr), layout)
        } else {
            panic!("__rust_deallocate: heap not initialized");
        }
    }
}
