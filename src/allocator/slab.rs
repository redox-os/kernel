use core::alloc::{Alloc, AllocErr, Layout};
use spin::Mutex;
use slab_allocator::Heap;

static HEAP: Mutex<Option<Heap>> = Mutex::new(None);

pub struct Allocator;

impl Allocator {
    pub unsafe fn init(offset: usize, size: usize) {
        *HEAP.lock() = Some(Heap::new(offset, size));
    }
}

unsafe impl<'a> Alloc for &'a Allocator {
    unsafe fn alloc(&mut self, layout: Layout) -> Result<*mut u8, AllocErr> {
        if let Some(ref mut heap) = *HEAP.lock() {
            heap.allocate(layout)
        } else {
            panic!("__rust_allocate: heap not initialized");
        }
    }

    unsafe fn dealloc(&mut self, ptr: *mut u8, layout: Layout) {
        if let Some(ref mut heap) = *HEAP.lock() {
            heap.deallocate(ptr, layout)
        } else {
            panic!("__rust_deallocate: heap not initialized");
        }
    }

    fn oom(&mut self, error: AllocErr) -> ! {
        panic!("Out of memory: {:?}", error);
    }

    fn usable_size(&self, layout: &Layout) -> (usize, usize) {
        if let Some(ref mut heap) = *HEAP.lock() {
            heap.usable_size(layout)
        } else {
            panic!("__rust_usable_size: heap not initialized");
        }
    }
}
