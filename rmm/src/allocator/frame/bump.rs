use core::marker::PhantomData;

use crate::{Arch, FrameAllocator, FrameCount, FrameUsage, MemoryArea, PhysicalAddress};

#[derive(Debug)]
pub struct BumpAllocator<A> {
    orig_areas: (&'static [MemoryArea], usize),
    cur_areas: (&'static [MemoryArea], usize),
    _marker: PhantomData<fn() -> A>,
}

impl<A: Arch> BumpAllocator<A> {
    pub fn new(mut areas: &'static [MemoryArea], mut offset: usize) -> Self {
        while let Some(first) = areas.first()
            && first.size <= offset
        {
            offset -= first.size;
            areas = &areas[1..];
        }

        Self {
            orig_areas: (areas, offset),
            cur_areas: (areas, offset),
            _marker: PhantomData,
        }
    }
    pub fn areas(&self) -> &'static [MemoryArea] {
        self.orig_areas.0
    }
    /// Returns one semifree and the fully free areas. The offset is the number of bytes after
    /// which the first area is free.
    pub fn free_areas(&self) -> (&'static [MemoryArea], usize) {
        self.cur_areas
    }
    pub fn abs_offset(&self) -> PhysicalAddress {
        let (areas, off) = self.cur_areas;
        areas
            .first()
            .map_or(PhysicalAddress::new(0), |a| a.base.add(off))
    }
    pub fn offset(&self) -> usize {
        (unsafe { self.usage().total().data() - self.usage().free().data() }) * A::PAGE_SIZE
    }
}

impl<A: Arch> FrameAllocator for BumpAllocator<A> {
    unsafe fn allocate(&mut self, count: FrameCount) -> Option<PhysicalAddress> {
        unsafe {
            let req_size = count.data() * A::PAGE_SIZE;

            let block = loop {
                let area = self.cur_areas.0.first()?;
                let off = self.cur_areas.1;
                if area.size - off < req_size {
                    self.cur_areas = (&self.cur_areas.0[1..], 0);
                    continue;
                }
                self.cur_areas.1 += req_size;

                break area.base.add(off);
            };
            A::write_bytes(A::phys_to_virt(block), 0, req_size);
            Some(block)
        }
    }

    unsafe fn free(&mut self, _address: PhysicalAddress, _count: FrameCount) {
        unimplemented!("BumpAllocator::free not implemented");
    }

    unsafe fn usage(&self) -> FrameUsage {
        let total = self.orig_areas.0.iter().map(|a| a.size).sum::<usize>() - self.orig_areas.1;
        let free = self.cur_areas.0.iter().map(|a| a.size).sum::<usize>() - self.cur_areas.1;
        FrameUsage::new(
            FrameCount::new((total - free) / A::PAGE_SIZE),
            FrameCount::new(total / A::PAGE_SIZE),
        )
    }
}
