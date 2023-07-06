use core::{alloc::GlobalAlloc, mem};

use crate::common::unique::Unique;
use crate::memory::Enomem;

// Necessary because GlobalAlloc::dealloc requires the layout to be the same, and therefore Box
// cannot be used for increased alignment directly.
// TODO: move to common?
pub struct AlignedBox<T, const ALIGN: usize> {
    inner: Unique<T>,
}
pub unsafe trait ValidForZero {}
unsafe impl<const N: usize> ValidForZero for [u8; N] {}

unsafe impl ValidForZero for crate::syscall::data::Stat {}
unsafe impl ValidForZero for crate::syscall::data::StatVfs {}

impl<T, const ALIGN: usize> AlignedBox<T, ALIGN> {
    const LAYOUT: core::alloc::Layout = {
        const fn max(a: usize, b: usize) -> usize {
            if a > b { a } else { b }
        }

        match core::alloc::Layout::from_size_align(mem::size_of::<T>(), max(mem::align_of::<T>(), ALIGN)) {
            Ok(l) => l,
            Err(_) => panic!("layout validation failed at compile time"),
        }
    };
    #[inline(always)]
    pub fn try_zeroed() -> Result<Self, Enomem>
    where
        T: ValidForZero,
    {
        Ok(unsafe {
            let ptr = crate::ALLOCATOR.alloc_zeroed(Self::LAYOUT);
            if ptr.is_null() {
                return Err(Enomem);
            }
            Self {
                inner: Unique::new_unchecked(ptr.cast()),
            }
        })
    }
}

impl<T, const ALIGN: usize> core::fmt::Debug for AlignedBox<T, ALIGN> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "[aligned box at {:p}, size {} alignment {}]", self.inner.as_ptr(), mem::size_of::<T>(), mem::align_of::<T>())
    }
}
impl<T, const ALIGN: usize> Drop for AlignedBox<T, ALIGN> {
    fn drop(&mut self) {
        unsafe {
            core::ptr::drop_in_place(self.inner.as_ptr());
            crate::ALLOCATOR.dealloc(self.inner.as_ptr().cast(), Self::LAYOUT);
        }
    }
}
impl<T, const ALIGN: usize> core::ops::Deref for AlignedBox<T, ALIGN> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.inner.as_ptr() }
    }
}
impl<T, const ALIGN: usize> core::ops::DerefMut for AlignedBox<T, ALIGN> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.inner.as_ptr() }
    }
}
impl<T: Clone + ValidForZero, const ALIGN: usize> Clone for AlignedBox<T, ALIGN> {
    fn clone(&self) -> Self {
        let mut new = Self::try_zeroed().unwrap_or_else(|_| alloc::alloc::handle_alloc_error(Self::LAYOUT));
        T::clone_from(&mut new, self);
        new
    }
}
