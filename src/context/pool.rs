use core::{
    alloc::{AllocError, Allocator, Layout},
    marker::PhantomData,
    ptr::NonNull,
};

use rmm::{Arch, PhysicalAddress};
use spin::Mutex;

use crate::memory::{allocate_p2frame, RmmA, PAGE_SIZE};

pub trait PoolType {
    const ITEM_SIZE: usize;
    const ITEM_ALIGN: usize;

    fn state() -> &'static Mutex<State>;
}
impl<T, A: Allocator> PoolType for alloc::sync::Arc<T, A> {
    const ITEM_SIZE: usize =
        size_of::<T>().next_multiple_of(size_of::<usize>()) + 2 * size_of::<usize>();
    const ITEM_ALIGN: usize = align_of::<T>();

    fn state() -> &'static Mutex<State> {
        const {
            assert!(Self::ITEM_SIZE <= 4 * PAGE_SIZE);
            assert!(Self::ITEM_SIZE >= size_of::<usize>());
            assert!(Self::ITEM_SIZE % size_of::<usize>() == 0);

            assert!(Self::ITEM_ALIGN <= 4 * PAGE_SIZE);
        };

        // TODO: Will this static be created uniquely for each T?
        static STATE: Mutex<State> = Mutex::new(State::new());
        &STATE
    }
}

pub const CONTEXT_POOL: ContextPool = Pool::new();
pub type ContextPool = Pool<alloc::sync::Arc<crate::context::ContextLock>>;

/// Simple allocator based on allocating p2frames of order 2, with a SLOB on top.
#[derive(Clone, Copy, Debug)]
pub struct Pool<T> {
    _marker: PhantomData<fn() -> T>,
}

impl<T> Pool<T> {
    pub const fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

pub struct State {
    head: Option<NonNull<()>>,
}
impl State {
    pub const fn new() -> Self {
        Self { head: None }
    }
}
unsafe impl Send for State {}
unsafe impl Sync for State {}

unsafe impl<T: PoolType> Allocator for Pool<T> {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let chunk_size = PAGE_SIZE << 2;
        assert_eq!(layout.size(), T::ITEM_SIZE);
        assert_eq!(T::ITEM_SIZE % layout.align(), 0);
        assert!(layout.align() <= T::ITEM_ALIGN);

        let mut state = T::state().lock();

        let ret = match state.head.take() {
            Some(head) => {
                let next_head = unsafe { head.cast::<Option<NonNull<()>>>().read() };
                state.head = next_head;

                head
            }
            None => {
                let must_be_zero = false;

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
                    let p2 = allocate_p2frame(2, must_be_zero).ok_or(AllocError)?;

                    NonNull::new(RmmA::phys_to_virt(p2.base()).data() as *mut ())
                        .expect("can never be NULL")
                };

                let mut offset = T::ITEM_SIZE;
                while offset + T::ITEM_SIZE <= chunk_size {
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
        let old_head = state.head.replace(ptr.cast::<()>());
        unsafe {
            ptr.cast::<Option<NonNull<()>>>().write(old_head);
        }
        // TODO: free pages when possible
    }
}
