//! Recycle allocator
//! Uses freed frames if possible, then uses inner allocator

use alloc::vec::Vec;

use crate::paging::PhysicalAddress;
use super::{Frame, FrameAllocator};

use syscall::{PartialAllocStrategy, PhysallocFlags};

struct Range {
    base: usize,
    count: usize,
}

pub struct RecycleAllocator<T: FrameAllocator> {
    inner: T,
    noncore: bool,
    free: Vec<Range>,
}

impl<T: FrameAllocator> RecycleAllocator<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            noncore: false,
            free: Vec::new(),
        }
    }

    fn free_count(&self) -> usize {
        self.free.len()
    }

    fn merge(&mut self, address: usize, count: usize) -> bool {
        for i in 0 .. self.free.len() {
            let changed = {
                let free = &mut self.free[i];
                if address + count * super::PAGE_SIZE == free.base {
                    free.base = address;
                    free.count += count;
                    true
                } else if free.base + free.count * super::PAGE_SIZE == address {
                    free.count += count;
                    true
                } else {
                    false
                }
            };

            if changed {
                //TODO: Use do not use recursion
                let Range { base: address, count } = self.free[i];
                if self.merge(address, count) {
                    self.free.remove(i);
                }
                return true;
            }
        }

        false
    }
    fn try_recycle(&mut self, count: usize, flags: PhysallocFlags, strategy: Option<PartialAllocStrategy>, min: usize) -> Option<(usize, usize)> {
        let space32 = flags.contains(PhysallocFlags::SPACE_32);
        let partial_alloc = flags.contains(PhysallocFlags::PARTIAL_ALLOC);

        let mut actual_size = count;
        let mut current_optimal_index = None;
        let mut current_optimal = self.free.first()?;

        for (free_range_index, free_range) in self.free.iter().enumerate().skip(1) {
            // Later entries can be removed faster

            if space32 && free_range.base + count * super::PAGE_SIZE >= 0x1_0000_0000 {
                // We need a 32-bit physical address and this range is outside that address
                // space.
                continue;
            }

            if free_range.count < count {
                if partial_alloc && free_range.count >= min && matches!(strategy, Some(PartialAllocStrategy::Greedy)) {
                    // The free range does not fit the entire requested range, but is still
                    // at least as large as the minimum range. When using the "greedy"
                    // strategy, we return immediately.
                    current_optimal_index = Some(free_range_index);
                    actual_size = free_range.count;
                    break;
                }

                // Range has to fit if we want the entire frame requested.
                continue;
            }
            if free_range.count > current_optimal.count {
                // Skip this free range if it wasn't smaller than the old one; we do want to use
                // the smallest range possible to reduce fragmentation as much as possible.
                continue;
            }

            // We found a range that fit.
            current_optimal_index = Some(free_range_index);
            current_optimal = free_range;
        }
        current_optimal_index.map(|idx| (actual_size, idx))
    }
}

impl<T: FrameAllocator> FrameAllocator for RecycleAllocator<T> {
    fn set_noncore(&mut self, noncore: bool) {
        self.noncore = noncore;
    }

    fn free_frames(&self) -> usize {
        self.inner.free_frames() + self.free_count()
    }

    fn used_frames(&self) -> usize {
        self.inner.used_frames() - self.free_count()
    }

    fn allocate_frames3(&mut self, count: usize, flags: PhysallocFlags, strategy: Option<PartialAllocStrategy>, min: usize) -> Option<(Frame, usize)> {
        // TODO: Cover all different strategies.

        if let Some((actual_size, free_range_idx_to_use)) = self.try_recycle(count, flags, strategy, min) {
            let (address, remove) = {
                let free_range = &mut self.free[free_range_idx_to_use];
                free_range.count -= actual_size;
                (free_range.base + free_range.count * super::PAGE_SIZE, free_range.count == 0)
            };

            if remove {
                self.free.remove(free_range_idx_to_use);
            }

            //println!("Restoring frame {:?}, {}", frame, count);
            Some((Frame::containing_address(PhysicalAddress::new(address)), actual_size))
        } else {
            //println!("No saved frames {}", count);
            self.inner.allocate_frames3(count, flags, strategy, min)
        }
    }

    fn deallocate_frames(&mut self, frame: Frame, count: usize) {
        if self.noncore {
            let address = frame.start_address().get();
            if ! self.merge(address, count) {
                self.free.push(Range { base: address, count });
            }
        } else {
            //println!("Could not save frame {:?}, {}", frame, count);
            self.inner.deallocate_frames(frame, count);
        }
    }
}
