use core::{
    alloc::{AllocError, Allocator, Layout},
    marker::PhantomData,
    num::NonZeroUsize,
    ptr::NonNull,
    sync::atomic::{AtomicUsize, Ordering},
};

use rmm::{Arch, PhysicalAddress};
use spin::Mutex;

use crate::{
    context::ContextLock,
    memory::{allocate_p2frame, Frame, RmmA, PAGE_SIZE},
};

pub unsafe trait PoolType: 'static + Sized {
    const ITEM_SIZE: usize;
    const ITEM_ALIGN: usize;

    fn state() -> &'static Mutex<State<Self>>;
    fn name() -> &'static str;
}
impl_pool_type_arc!(ContextLock);
pub const CONTEXT_POOL: ContextPool = Pool::new();
pub type ContextPool = Pool<alloc::sync::Arc<crate::context::ContextLock>>;

/// Simple allocator based on allocating p2frames of order 2, with a SLOB on top.
#[derive(Clone, Copy, Debug)]
pub struct Pool<T> {
    _marker: PhantomData<fn() -> T>,
}
impl<T: PoolType> core::fmt::Display for Pool<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let state = T::state().lock();
        // TODO: print T::name()?
        write!(
            f,
            "{} allocations of size {} align {}, using {} p2frames of size {}",
            state.num_allocs,
            T::ITEM_SIZE,
            T::ITEM_ALIGN,
            state.num_p2frames,
            4 * PAGE_SIZE
        )
    }
}

impl<T> Pool<T> {
    pub const fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}
impl<T> Default for Pool<T> {
    fn default() -> Self {
        Self::new()
    }
}

pub struct State<T> {
    head: Option<NonNull<FreeListEntry>>,
    num_allocs: usize,
    num_p2frames: usize,
    _marker: PhantomData<fn() -> T>,
}
impl<T> State<T> {
    pub const fn new() -> Self {
        Self {
            head: None,
            num_allocs: 0,
            num_p2frames: 0,
            _marker: PhantomData,
        }
    }
}
unsafe impl<T> Send for State<T> {}
unsafe impl<T> Sync for State<T> {}

struct FreeListEntry {
    prev: Option<NonNull<FreeListEntry>>,
    next: Option<NonNull<FreeListEntry>>,
}

struct SlabMetadata {
    num_used: &'static AtomicUsize,
}

#[cfg(test)]
static FAKE_METADATA_MAP: spin::Mutex<alloc::collections::BTreeMap<usize, &'static AtomicUsize>> =
    spin::Mutex::new(alloc::collections::BTreeMap::new());

fn round_down_ptr_to_page(ptr: NonNull<()>) -> NonNull<()> {
    ptr.map_addr(|addr| NonZeroUsize::new(addr.get() & !(4 * PAGE_SIZE - 1)).unwrap())
}

#[cfg(test)]
fn slab_metadata(ptr: NonNull<()>) -> SlabMetadata {
    SlabMetadata {
        num_used: FAKE_METADATA_MAP.lock().get(&ptr.addr().get()).unwrap(),
    }
}

#[cfg(not(test))]
fn slab_metadata(ptr: NonNull<()>) -> SlabMetadata {
    let phys = PhysicalAddress::new(ptr.addr().get() - RmmA::PHYS_OFFSET);
    SlabMetadata {
        num_used: &crate::memory::get_page_info(Frame::containing(phys))
            .expect("slab page not in memory map")
            .next,
    }
}

unsafe impl<T: PoolType> Allocator for Pool<T> {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let chunk_size = 4 * PAGE_SIZE;
        assert_eq!(layout.size(), T::ITEM_SIZE);
        assert_eq!(T::ITEM_SIZE % layout.align(), 0);
        assert!(layout.align() <= T::ITEM_ALIGN);

        let mut state = T::state().lock();

        //info!("T {} ALLOC {:?} STATE {:p} {:?}", core::any::type_name::<T>(), layout, &*state, &*state);

        let ret = match state.head.take() {
            Some(head) => {
                let FreeListEntry { prev, next } = unsafe { head.cast().read() };
                debug_assert_eq!(prev, None);

                if let Some(next) = next.map(|mut nn| unsafe { nn.as_mut() }) {
                    next.prev = None;
                }
                state.head = next;
                state.num_allocs += 1;

                let ptr = head.cast::<()>();

                let meta = slab_metadata(round_down_ptr_to_page(ptr));
                meta.num_used
                    .store(meta.num_used.load(Ordering::Relaxed) + 1, Ordering::Relaxed);

                ptr
            }
            None => {
                #[cfg(test)]
                let base = {
                    // TODO: don't hardcode?
                    #[repr(align(16384))]
                    struct Align([u8; 16384]);
                    let p2 = Box::leak(unsafe { Box::<Align>::new_zeroed().assume_init() });
                    FAKE_METADATA_MAP.lock().insert(
                        p2 as *mut Align as usize,
                        Box::leak(Box::new(AtomicUsize::new(1))),
                    );

                    NonNull::from(p2).cast::<()>()
                };
                #[cfg(not(test))]
                let base = {
                    let must_be_zero = false;

                    let p2 = allocate_p2frame(2, must_be_zero).ok_or(AllocError)?;

                    let ptr = NonNull::new(RmmA::phys_to_virt(p2.base()).data() as *mut ())
                        .expect("can never be NULL");

                    slab_metadata(ptr).num_used.store(1, Ordering::Relaxed);

                    ptr
                };
                state.num_p2frames += 1;

                let mut second = None;

                let mut offset = T::ITEM_SIZE;
                while offset + T::ITEM_SIZE <= chunk_size {
                    if second.is_none() {
                        second = Some(unsafe { base.byte_add(offset) });
                    }
                    let next = if offset + 2 * T::ITEM_SIZE <= chunk_size {
                        Some(
                            unsafe { base.byte_add(offset + T::ITEM_SIZE) }.cast::<FreeListEntry>(),
                        )
                    } else {
                        None
                    };
                    let prev = if offset >= 2 * T::ITEM_SIZE {
                        Some(
                            unsafe { base.byte_add(offset - T::ITEM_SIZE) }.cast::<FreeListEntry>(),
                        )
                    } else {
                        None
                    };
                    unsafe {
                        base.byte_add(offset)
                            .cast::<FreeListEntry>()
                            .write(FreeListEntry { next, prev });
                    }

                    offset += T::ITEM_SIZE;
                }

                state.head = second.map(|s| s.cast::<FreeListEntry>());

                state.num_allocs += 1;
                base
            }
        };
        Ok(NonNull::slice_from_raw_parts(
            ret.cast::<u8>(),
            T::ITEM_SIZE,
        ))
    }
    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        assert_eq!(layout.size(), T::ITEM_SIZE);
        assert_eq!(T::ITEM_SIZE % layout.align(), 0);
        assert!(layout.align() <= T::ITEM_ALIGN);

        let mut state = T::state().lock();
        //info!("T {} FREE {:?} STATE {:p} {:?}", core::any::type_name::<T>(), layout, &*state, &*state);

        let meta = slab_metadata(round_down_ptr_to_page(ptr.cast()));
        if meta.num_used.load(Ordering::Relaxed) == 1 {
            // Return p2frame to frame allocator.
            let base: NonNull<FreeListEntry> = round_down_ptr_to_page(ptr.cast()).cast();
            let end = unsafe { base.byte_add(4 * PAGE_SIZE) };

            let mut offset = 0;
            while offset + T::ITEM_SIZE <= PAGE_SIZE * 4 {
                let entry_ptr: NonNull<FreeListEntry> = unsafe { base.byte_add(offset) };
                offset += T::ITEM_SIZE;

                if entry_ptr.cast::<u8>() == ptr {
                    continue;
                }

                let FreeListEntry { prev, next } = unsafe { entry_ptr.read() };
                if let Some(prev) = prev.map(|mut nn| unsafe { nn.as_mut() }) {
                    prev.next = next;
                }
                if let Some(next) = next.map(|mut nn| unsafe { nn.as_mut() }) {
                    next.prev = prev;
                }
            }
            if let Some(head) = state.head
                && head >= base
                && head < end
            {
                state.head = None;
            }
            meta.num_used.store(0, Ordering::Relaxed);

            #[cfg(test)]
            {
                // TODO: don't hardcode?
                #[repr(align(16384))]
                struct Align([u8; 16384]);

                drop(unsafe { Box::from_raw(base.as_ptr().cast::<Align>()) });
            }
            #[cfg(not(test))]
            {
                let frame =
                    Frame::containing(PhysicalAddress::new(base.addr().get() - RmmA::PHYS_OFFSET));
                unsafe {
                    crate::memory::deallocate_p2frame(frame, 2);
                }
            }
            state.num_p2frames -= 1;
        } else {
            meta.num_used
                .store(meta.num_used.load(Ordering::Relaxed) - 1, Ordering::Relaxed);
            let old_head = state.head.replace(ptr.cast::<FreeListEntry>());
            unsafe {
                ptr.cast::<FreeListEntry>().write(FreeListEntry {
                    next: old_head,
                    prev: None,
                });
            }
        }

        state.num_allocs -= 1;
    }
}
