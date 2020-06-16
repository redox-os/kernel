//! # Bump frame allocator
//! Some code was borrowed from [Phil Opp's Blog](http://os.phil-opp.com/allocating-frames.html)

use crate::paging::PhysicalAddress;
use super::{Frame, FrameAllocator, MemoryArea, MemoryAreaIter};

use syscall::{PartialAllocStrategy, PhysallocFlags};

pub struct BumpAllocator {
    next_free_frame: Frame,
    current_area: Option<&'static MemoryArea>,
    areas: MemoryAreaIter,
    kernel_start: Frame,
    kernel_end: Frame
}

impl BumpAllocator {
    pub fn new(kernel_start: usize, kernel_end: usize, memory_areas: MemoryAreaIter) -> Self {
        let mut allocator = Self {
            next_free_frame: Frame::containing_address(PhysicalAddress::new(0)),
            current_area: None,
            areas: memory_areas,
            kernel_start: Frame::containing_address(PhysicalAddress::new(kernel_start)),
            kernel_end: Frame::containing_address(PhysicalAddress::new(kernel_end))
        };
        allocator.choose_next_area();
        allocator
    }

    fn choose_next_area(&mut self) {
        self.current_area = self.areas.clone().filter(|area| {
            let address = area.base_addr + area.length - 1;
            Frame::containing_address(PhysicalAddress::new(address as usize)) >= self.next_free_frame
        }).min_by_key(|area| area.base_addr);

        if let Some(area) = self.current_area {
            let start_frame = Frame::containing_address(PhysicalAddress::new(area.base_addr as usize));
            if self.next_free_frame < start_frame {
                self.next_free_frame = start_frame;
            }
        }
    }
}

impl FrameAllocator for BumpAllocator {
    #[allow(unused)]
    fn set_noncore(&mut self, noncore: bool) {}
    
    fn free_frames(&self) -> usize {
        let mut count = 0;

        for area in self.areas.clone() {
            let start_frame = Frame::containing_address(PhysicalAddress::new(area.base_addr as usize));
            let end_frame = Frame::containing_address(PhysicalAddress::new((area.base_addr + area.length - 1) as usize));
            for frame in Frame::range_inclusive(start_frame, end_frame) {
                if frame >= self.kernel_start && frame <= self.kernel_end {
                    // Inside of kernel range
                } else if frame >= self.next_free_frame {
                    // Frame is in free range
                    count += 1;
                } else {
                    // Inside of used range
                }
            }
        }

        count
    }

    fn used_frames(&self) -> usize {
        let mut count = 0;

        for area in self.areas.clone() {
            let start_frame = Frame::containing_address(PhysicalAddress::new(area.base_addr as usize));
            let end_frame = Frame::containing_address(PhysicalAddress::new((area.base_addr + area.length - 1) as usize));
            for frame in Frame::range_inclusive(start_frame, end_frame) {
                if frame >= self.kernel_start && frame <= self.kernel_end {
                    // Inside of kernel range
                    count += 1
                } else if frame >= self.next_free_frame {
                    // Frame is in free range
                } else {
                    count += 1;
                }
            }
        }

        count
    }

    fn allocate_frames3(&mut self, count: usize, flags: PhysallocFlags, strategy: Option<PartialAllocStrategy>, min: usize) -> Option<(Frame, usize)> {
        // TODO: Comply with flags and allocation strategies better.
        if count == 0 {
            return None;
        } else if let Some(area) = self.current_area {
            let space32 = flags.contains(PhysallocFlags::SPACE_32);
            let partial_alloc = flags.contains(PhysallocFlags::PARTIAL_ALLOC);
            let mut actual_size = count;

            // "Clone" the frame to return it if it's free. Frame doesn't
            // implement Clone, but we can construct an identical frame.
            let start_frame = Frame { number: self.next_free_frame.number };
            let mut end_frame = Frame { number: self.next_free_frame.number + (count - 1) };
            let min_end_frame = if partial_alloc { Frame { number: self.next_free_frame.number + (min - 1) } } else { Frame { number: self.next_free_frame.number + (count - 1) } };

            // the last frame of the current area
            let current_area_last_frame = {
                let address = area.base_addr + area.length - 1;
                Frame::containing_address(PhysicalAddress::new(address as usize))
            };

            if end_frame > current_area_last_frame && min_end_frame > current_area_last_frame {
                // all frames of current area are used, switch to next area
                self.choose_next_area();
                return self.allocate_frames3(count, flags, strategy, min)
            } else if partial_alloc {
                end_frame = Frame { number: self.next_free_frame.number + (min - 1) };
                actual_size = min;
            }

            if space32 && end_frame.start_address().get() + super::PAGE_SIZE >= 0x1_0000_0000 {
                // assuming that the bump allocator always advances, and that the memory map is sorted,
                // when allocating in 32-bit space we can only return None when the free range was
                // outside 0x0000_0000-0xFFFF_FFFF.
                //
                // we don't want to skip an entire memory region just because one 32-bit allocation failed.
                return None;
            }

            if (start_frame >= self.kernel_start && start_frame <= self.kernel_end)
                    || (end_frame >= self.kernel_start && end_frame <= self.kernel_end) {
                // `frame` is used by the kernel
                self.next_free_frame = Frame {
                    number: self.kernel_end.number + 1
                };
                // `frame` was not valid, try it again with the updated `next_free_frame`
                return self.allocate_frames3(count, flags, strategy, min)
            }

            // frame is unused, increment `next_free_frame` and return it
            self.next_free_frame.number += actual_size;
            return Some((start_frame, actual_size));
        } else {
            None // no free memory areas left, and thus no frames left
        }
    }

    fn deallocate_frames(&mut self, _frame: Frame, _count: usize) {
        //panic!("BumpAllocator::deallocate_frame: not supported: {:?}", frame);
    }
}
