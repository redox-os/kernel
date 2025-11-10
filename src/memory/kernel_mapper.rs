use core::sync::{
    atomic,
    atomic::{AtomicU32, AtomicUsize, Ordering},
};
use rmm::{PageMapper, TableKind};

const NO_PROCESSOR: u32 = !0;
static LOCK_OWNER: AtomicU32 = AtomicU32::new(NO_PROCESSOR);
static LOCK_COUNT: AtomicUsize = AtomicUsize::new(0);

// TODO: Support, perhaps via const generics, embedding address checking in PageMapper, thereby
// statically enforcing that the kernel mapper can only map things in the kernel half, and vice
// versa.
/// A guard to the global lock protecting the upper 128 TiB of kernel address space.
///
/// NOTE: Use this with great care! Since heap allocations may also require this lock when the heap
/// needs to be expended, it must not be held while memory allocations are done!
// TODO: Make the lock finer-grained so that e.g. the heap part can be independent from e.g.
// PHYS_PML4?
pub struct KernelMapper {
    mapper: crate::paging::PageMapper,
    ro: bool,
}
impl KernelMapper {
    pub fn lock() -> Self {
        let mapper =
            unsafe { PageMapper::current(TableKind::Kernel, crate::memory::TheFrameAllocator) };

        let current_processor = crate::cpu_id();
        loop {
            match LOCK_OWNER.compare_exchange_weak(
                NO_PROCESSOR,
                current_processor.get(),
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                // already owned by this hardware thread
                Err(id) if id == current_processor.get() => break,
                // either CAS failed, or some other hardware thread holds the lock
                Err(_) => core::hint::spin_loop(),
            }
        }

        let prev_count = LOCK_COUNT.fetch_add(1, Ordering::Relaxed);
        atomic::compiler_fence(Ordering::Acquire);

        let ro = prev_count > 0;
        Self { mapper, ro }
    }

    pub fn get_mut(&mut self) -> Option<&mut crate::paging::PageMapper> {
        if self.ro {
            None
        } else {
            Some(&mut self.mapper)
        }
    }
}
impl core::ops::Deref for KernelMapper {
    type Target = crate::paging::PageMapper;

    fn deref(&self) -> &Self::Target {
        &self.mapper
    }
}
impl Drop for KernelMapper {
    fn drop(&mut self) {
        if LOCK_COUNT.fetch_sub(1, Ordering::Relaxed) == 1 {
            LOCK_OWNER.store(NO_PROCESSOR, Ordering::Release);
        }
        atomic::compiler_fence(Ordering::Release);
    }
}
