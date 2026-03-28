use core::{marker::PhantomData, mem};

use crate::{Arch, VirtualAddress};

pub trait Flusher<A> {
    fn consume(&mut self, flush: PageFlush<A>);
}

#[must_use = "The page table must be flushed, or the changes unsafely ignored"]
pub struct PageFlush<A> {
    virt: VirtualAddress,
    phantom: PhantomData<A>,
}

impl<A: Arch> PageFlush<A> {
    pub fn new(virt: VirtualAddress) -> Self {
        Self {
            virt,
            phantom: PhantomData,
        }
    }

    pub fn flush(self) {
        unsafe {
            A::invalidate(self.virt);
        }
    }

    pub unsafe fn ignore(self) {
        mem::forget(self);
    }
}

// TODO: Might remove Drop and add #[must_use] again, but ergonomically I prefer being able to pass
// a flusher, and have it dropped by the end of the function it is passed to, in order to flush.
pub struct PageFlushAll<A: Arch> {
    phantom: PhantomData<fn() -> A>,
}

impl<A: Arch> PageFlushAll<A> {
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }

    pub fn flush(self) {}

    pub unsafe fn ignore(self) {
        mem::forget(self);
    }
}
impl<A: Arch> Drop for PageFlushAll<A> {
    fn drop(&mut self) {
        unsafe {
            A::invalidate_all();
        }
    }
}
impl<A: Arch> Flusher<A> for PageFlushAll<A> {
    fn consume(&mut self, flush: PageFlush<A>) {
        unsafe {
            flush.ignore();
        }
    }
}
impl<A: Arch, T: Flusher<A> + ?Sized> Flusher<A> for &mut T {
    fn consume(&mut self, flush: PageFlush<A>) {
        <T as Flusher<A>>::consume(self, flush)
    }
}
impl<A: Arch> Flusher<A> for () {
    fn consume(&mut self, _: PageFlush<A>) {}
}
