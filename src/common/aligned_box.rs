use core::alloc::{GlobalAlloc, Layout};

use crate::{common::unique::Unique, memory::Enomem};

// Necessary because GlobalAlloc::dealloc requires the layout to be the same, and therefore Box
// cannot be used for increased alignment directly.
// TODO: move to common?
pub struct AlignedBox<T: ?Sized, const ALIGN: usize> {
    inner: Unique<T>,
}
pub unsafe trait ValidForZero {}
unsafe impl<const N: usize> ValidForZero for [u8; N] {}
unsafe impl ValidForZero for u8 {}

impl<T: ?Sized, const ALIGN: usize> AlignedBox<T, ALIGN> {
    fn layout(&self) -> Layout {
        layout_upgrade_align(Layout::for_value::<T>(&*self), ALIGN)
    }
}
const fn layout_upgrade_align(layout: Layout, align: usize) -> Layout {
    const fn max(a: usize, b: usize) -> usize {
        if a > b {
            a
        } else {
            b
        }
    }
    let Ok(x) = Layout::from_size_align(layout.size(), max(align, layout.align())) else {
        panic!("failed to calculate layout");
    };
    x
}

impl<T, const ALIGN: usize> AlignedBox<T, ALIGN> {
    #[inline(always)]
    pub fn try_zeroed() -> Result<Self, Enomem>
    where
        T: ValidForZero,
    {
        Ok(unsafe {
            let ptr =
                crate::ALLOCATOR.alloc_zeroed(layout_upgrade_align(Layout::new::<T>(), ALIGN));
            if ptr.is_null() {
                return Err(Enomem);
            }
            Self {
                inner: Unique::new_unchecked(ptr.cast()),
            }
        })
    }
}
impl<T, const ALIGN: usize> AlignedBox<[T], ALIGN> {
    #[inline]
    pub fn try_zeroed_slice(len: usize) -> Result<Self, Enomem>
    where
        T: ValidForZero,
    {
        Ok(unsafe {
            let ptr = crate::ALLOCATOR.alloc_zeroed(layout_upgrade_align(
                Layout::array::<T>(len).unwrap(),
                ALIGN,
            ));
            if ptr.is_null() {
                return Err(Enomem);
            }
            Self {
                inner: Unique::new_unchecked(core::ptr::slice_from_raw_parts_mut(ptr.cast(), len)),
            }
        })
    }
}

impl<T: ?Sized, const ALIGN: usize> core::fmt::Debug for AlignedBox<T, ALIGN> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "[aligned box at {:p}, size {} alignment {}]",
            self.inner.as_ptr(),
            self.layout().size(),
            self.layout().align()
        )
    }
}
impl<T: ?Sized, const ALIGN: usize> Drop for AlignedBox<T, ALIGN> {
    fn drop(&mut self) {
        unsafe {
            let layout = self.layout();
            core::ptr::drop_in_place(self.inner.as_ptr());
            crate::ALLOCATOR.dealloc(self.inner.as_ptr().cast(), layout);
        }
    }
}
impl<T: ?Sized, const ALIGN: usize> core::ops::Deref for AlignedBox<T, ALIGN> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.inner.as_ptr() }
    }
}
impl<T: ?Sized, const ALIGN: usize> core::ops::DerefMut for AlignedBox<T, ALIGN> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.inner.as_ptr() }
    }
}
impl<T: Clone + ValidForZero, const ALIGN: usize> Clone for AlignedBox<T, ALIGN> {
    fn clone(&self) -> Self {
        let mut new =
            Self::try_zeroed().unwrap_or_else(|_| alloc::alloc::handle_alloc_error(self.layout()));
        T::clone_from(&mut new, self);
        new
    }
}
impl<T: Clone + ValidForZero, const ALIGN: usize> Clone for AlignedBox<[T], ALIGN> {
    fn clone(&self) -> Self {
        let mut new = Self::try_zeroed_slice(self.len())
            .unwrap_or_else(|_| alloc::alloc::handle_alloc_error(self.layout()));
        for i in 0..self.len() {
            new[i].clone_from(&self[i]);
        }
        new
    }
}
