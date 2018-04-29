use alloc::heap::{AllocErr, GlobalAlloc, Layout, Opaque};
use core::ptr::NonNull;
use linked_list_allocator::Heap;
use spin::Mutex;

use paging::ActivePageTable;

static HEAP: Mutex<Option<Heap>> = Mutex::new(None);

pub struct Allocator;

impl Allocator {
    pub unsafe fn init(offset: usize, size: usize) {
        *HEAP.lock() = Some(Heap::new(offset, size));
    }
}

unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut Opaque {
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

                    super::map_heap(&mut ActivePageTable::new(), ::KERNEL_HEAP_OFFSET + size, ::KERNEL_HEAP_SIZE);

                    if let Some(ref mut heap) = *HEAP.lock() {
                        heap.extend(::KERNEL_HEAP_SIZE);
                    } else {
                        panic!("__rust_allocate: heap not initialized");
                    }
                },
                other => return other.ok().map_or(0 as *mut Opaque, |allocation| allocation.as_ptr()),
            }
        }
    }

    unsafe fn dealloc(&self, ptr: *mut Opaque, layout: Layout) {
        if let Some(ref mut heap) = *HEAP.lock() {
            heap.deallocate(NonNull::new_unchecked(ptr), layout)
        } else {
            panic!("__rust_deallocate: heap not initialized");
        }
    }
}
