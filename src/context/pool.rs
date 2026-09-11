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
// TODO: Also add support for variable-length allocations (for example, always rounding up to the
// nearest power of two, between say 32 bytes and the page size), and use this to replace
// linked_list_allocator at more places. Some huge allocations like the profiling queue may need to
// be rewritten to use e.g. unrolled linked lists, since contiguity beyond say 16 pages can be
// difficult after some p2buddy fragmentation. Once that is done, then linked_list_allocator can
// possibly be removed.
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
impl<T: PoolType> Pool<T> {
    pub fn num_allocs(&self) -> usize {
        T::state().lock().num_allocs
    }
    pub fn num_p2frames(&self) -> usize {
        T::state().lock().num_p2frames
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

fn round_down_ptr_to_slab(ptr: NonNull<()>) -> NonNull<()> {
    ptr.map_addr(|addr| NonZeroUsize::new(addr.get() & !(4 * PAGE_SIZE - 1)).unwrap())
}

#[cfg(test)]
fn slab_metadata(ptr: NonNull<()>) -> SlabMetadata {
    SlabMetadata {
        num_used: FAKE_METADATA_MAP.lock().get(&ptr.addr().get()).unwrap(),
    }
}

//#[cfg(not(test))]
fn slab_metadata(ptr: NonNull<()>) -> SlabMetadata {
    let phys = PhysicalAddress::new(ptr.addr().get().checked_sub(RmmA::PHYS_OFFSET).unwrap());
    assert_eq!(phys.data() % (4 * PAGE_SIZE), 0);
    let info =
        crate::memory::get_page_info(Frame::containing(phys)).expect("slab page not in memory map");
    assert_ne!(
        info.refcount.load(Ordering::Relaxed) & crate::memory::RC_USED_NOT_FREE,
        0
    );
    SlabMetadata {
        num_used: &info.next,
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

                let meta = slab_metadata(round_down_ptr_to_slab(ptr));
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

        let meta = slab_metadata(round_down_ptr_to_slab(ptr.cast()));
        if meta.num_used.load(Ordering::Relaxed) == 1 {
            // Return p2frame to frame allocator.
            let base: NonNull<FreeListEntry> = round_down_ptr_to_slab(ptr.cast()).cast();
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
                let frame = Frame::containing(PhysicalAddress::new(
                    base.addr().get().checked_sub(RmmA::PHYS_OFFSET).unwrap(),
                ));
                unsafe {
                    crate::memory::deallocate_p2frame(frame, 2);
                }
            }
            state.num_p2frames -= 1;
        } else {
            let new_head = ptr.cast::<FreeListEntry>();

            meta.num_used
                .store(meta.num_used.load(Ordering::Relaxed) - 1, Ordering::Relaxed);
            let old_head = state.head.replace(new_head);

            if let Some(old_head) = old_head.map(|mut nn| unsafe { nn.as_mut() }) {
                assert_eq!(old_head.prev, None);
                old_head.prev = Some(new_head);
            }

            unsafe {
                new_head.write(FreeListEntry {
                    next: old_head,
                    prev: None,
                });
            }
        }

        state.num_allocs -= 1;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        context::file::{
            ArcLockedFileDescription, FileDescription, InternalFlags, KernelSchemeRef,
            FILE_DESCRIPTION_POOL,
        },
        sync::RwLock,
    };

    #[cfg_attr(not(miri), test)]
    fn filedesc_allocations() {
        let len = 1024 * 128;
        let mut descs: Vec<Option<ArcLockedFileDescription>> = vec![const { None }; len];

        assert_eq!(FILE_DESCRIPTION_POOL.num_allocs(), 0);
        assert_eq!(FILE_DESCRIPTION_POOL.num_p2frames(), 0);

        for slot in &mut descs {
            *slot = Some(Arc::new_in(
                RwLock::new(FileDescription {
                    offset: 42,
                    scheme_ref: KernelSchemeRef::SchemeMgr,
                    number: 1337,
                    flags: 0,
                    internal_flags: InternalFlags::empty(),
                }),
                FILE_DESCRIPTION_POOL,
            ));
        }

        // TODO: mix allocation and deallocation?

        let mut validate = |descs: &mut [Option<ArcLockedFileDescription>]| {
            for mut slot in descs.iter_mut().filter_map(|x| x.as_mut()) {
                assert_eq!(Arc::get_mut(slot).unwrap().get_mut().offset, 42);
                assert_eq!(Arc::get_mut(slot).unwrap().get_mut().number, 1337);
            }
        };

        // Deallocate "randomly"
        for slot in descs.iter_mut().step_by(3) {
            *slot = None;
        }
        validate(&mut descs);
        for slot in descs.iter_mut().step_by(5) {
            *slot = None;
        }
        validate(&mut descs);
        for slot in descs.iter_mut().step_by(7) {
            *slot = None;
        }
        validate(&mut descs);
        for slot in descs.iter_mut().step_by(2) {
            *slot = None;
        }
        validate(&mut descs);
        for slot in descs.iter_mut() {
            *slot = None;
        }
        assert_eq!(FILE_DESCRIPTION_POOL.num_allocs(), 0);
        assert_eq!(FILE_DESCRIPTION_POOL.num_p2frames(), 0);
    }
}
