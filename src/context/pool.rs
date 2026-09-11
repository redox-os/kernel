use core::{
    alloc::{AllocError, Allocator, Layout},
    marker::PhantomData,
    ptr::NonNull,
};

use rmm::{Arch, PhysicalAddress};
use spin::Mutex;

use crate::{
    context::ContextLock,
    memory::{allocate_p2frame, RmmA, PAGE_SIZE},
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
    head: Option<NonNull<()>>,
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
                let next_head = unsafe { head.cast::<Option<NonNull<()>>>().read() };
                state.head = next_head;
                state.num_allocs += 1;

                head
            }
            None => {
                #[cfg(test)]
                let base = {
                    // TODO: don't hardcode?
                    #[repr(align(16384))]
                    struct Align([u8; 16384]);
                    let p2 = Box::leak(unsafe { Box::<Align>::new_zeroed().assume_init() });

                    NonNull::from(p2).cast::<()>()
                };
                #[cfg(not(test))]
                let base = {
                    let must_be_zero = false;

                    let p2 = allocate_p2frame(2, must_be_zero).ok_or(AllocError)?;

                    NonNull::new(RmmA::phys_to_virt(p2.base()).data() as *mut ())
                        .expect("can never be NULL")
                };
                state.num_p2frames += 1;

                let mut second = None;

                let mut offset = T::ITEM_SIZE;
                while offset + T::ITEM_SIZE <= chunk_size {
                    if second.is_none() {
                        second = Some(unsafe { base.byte_add(offset) });
                    }
                    let next = if offset + 2 * T::ITEM_SIZE <= chunk_size {
                        Some(unsafe { base.byte_add(offset + T::ITEM_SIZE) })
                    } else {
                        None
                    };
                    unsafe {
                        base.byte_add(offset)
                            .cast::<Option<NonNull<()>>>()
                            .write(next);
                    }

                    offset += T::ITEM_SIZE;
                }

                state.head = second;

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
        let old_head = state.head.replace(ptr.cast::<()>());
        unsafe {
            ptr.cast::<Option<NonNull<()>>>().write(old_head);
        }
        state.num_allocs -= 1;
        // TODO: free pages when possible
    }
}
