//! Recycle allocator
//! Uses freed frames if possible, then uses inner allocator

use collections::Vec;

use paging::PhysicalAddress;

use super::{Frame, FrameAllocator, MemoryArea, MemoryAreaIter};

pub struct RecycleAllocator<T: FrameAllocator> {
    inner: T,
    noncore: bool,
    free: Vec<(usize, usize)>,
}

impl<T: FrameAllocator> RecycleAllocator<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner: inner,
            noncore: false,
            free: Vec::new(),
        }
    }

    fn free_count(&self) -> usize {
        let mut count = 0;
        for free in self.free.iter() {
            count += free.1;
        }
        println!("Free count: {} in {} entries", count, self.free.len());
        count
    }

    fn merge(&mut self, address: usize, count: usize) -> bool {
        for i in 0 .. self.free.len() {
            let changed = {
                let mut free = &mut self.free[i];
                if address + count * 4096 == free.0 {
                    free.0 = address;
                    free.1 += count;
                    true
                } else if free.0 + free.1 * 4096 == address {
                    free.1 += count;
                    true
                } else {
                    false
                }
            };

            if changed {
                //TODO: Use do not use recursion
                let (address, count) = self.free[i];
                if self.merge(address, count) {
                    self.free.remove(i);
                }
                return true;
            }
        }

        false
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

    fn allocate_frames(&mut self, count: usize) -> Option<Frame> {
        if count == 1 {
            if ! self.free.is_empty() {
                let mut i = 0;
                {
                    let mut small = self.free[i];
                    for j in 1..self.free.len() {
                        let free = self.free[j];
                        // Later entries can be removed faster
                        if free.1 <= small.1 {
                            i = j;
                            small = free;
                        }
                    }
                }

                let (address, remove) = {
                    let free = &mut self.free[i];
                    free.1 -= 1;
                    (free.0 + free.1 * 4096, free.1 == 0)
                };

                if remove {
                    self.free.remove(i);
                }
                
                //println!("Restoring frame {:?}, {}", frame, count);
                Some(Frame::containing_address(PhysicalAddress::new(address)))
            } else {
                //println!("No saved frames {}", count);
                self.inner.allocate_frames(count)
            }
        } else {
            println!("Could not restore frame {}", count);
            self.inner.allocate_frames(count)
        }
    }

    fn deallocate_frames(&mut self, frame: Frame, count: usize) {
        if self.noncore {
            let address = frame.start_address().get();
            if ! self.merge(address, count) {
                self.free.push((address, count));
            }
        } else {
            println!("Could not save frame {:?}, {}", frame, count);
            self.inner.deallocate_frames(frame, count);
        }
    }
}
