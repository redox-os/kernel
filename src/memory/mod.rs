//! # Memory management
//! Some code was borrowed from [Phil Opp's Blog](http://os.phil-opp.com/allocating-frames.html)

use core::cmp;

use crate::arch::rmm::LockedAllocator;
pub use crate::paging::{PAGE_SIZE, PhysicalAddress};

use rmm::{
    FrameAllocator,
    FrameCount,
};
use crate::syscall::flag::{PartialAllocStrategy, PhysallocFlags};
use crate::syscall::error::{ENOMEM, Error};

/// A memory map area
#[derive(Copy, Clone, Debug, Default)]
#[repr(packed)]
pub struct MemoryArea {
    pub base_addr: u64,
    pub length: u64,
    pub _type: u32,
    pub acpi: u32
}

/// Get the number of frames available
pub fn free_frames() -> usize {
    unsafe {
        LockedAllocator.usage().free().data()
    }
}

/// Get the number of frames used
pub fn used_frames() -> usize {
    unsafe {
        LockedAllocator.usage().used().data()
    }
}

/// Allocate a range of frames
pub fn allocate_frames(count: usize) -> Option<Frame> {
    unsafe {
        LockedAllocator.allocate(FrameCount::new(count)).map(|phys| {
            Frame::containing_address(PhysicalAddress::new(phys.data()))
        })
    }
}
pub fn allocate_frames_complex(count: usize, flags: PhysallocFlags, strategy: Option<PartialAllocStrategy>, min: usize) -> Option<(Frame, usize)> {
    //TODO: support partial allocation
    if flags == PhysallocFlags::SPACE_64 && strategy.is_none() {
        let actual = cmp::max(count, min);
        return allocate_frames(actual).map(|frame| (frame, actual));
    }

    println!(
        "!!!! allocate_frames_complex not implemented for count {}, flags {:?}, strategy {:?}, min {}",
        count,
        flags,
        strategy,
        min
    );
    None
}

/// Deallocate a range of frames frame
pub fn deallocate_frames(frame: Frame, count: usize) {
    unsafe {
        LockedAllocator.free(
            rmm::PhysicalAddress::new(frame.start_address().data()),
            FrameCount::new(count)
        );
    }
}

/// A frame, allocated by the frame allocator.
/// Do not add more derives, or make anything `pub`!
#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct Frame {
    number: usize
}
impl core::fmt::Debug for Frame {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "[frame at {:p}]", self.start_address().data() as *const u8)
    }
}

impl Frame {
    /// Get the address of this frame
    pub fn start_address(&self) -> PhysicalAddress {
        PhysicalAddress::new(self.number * PAGE_SIZE)
    }

    //TODO: Set private
    pub fn clone(&self) -> Frame {
        Frame {
            number: self.number
        }
    }

    /// Create a frame containing `address`
    pub fn containing_address(address: PhysicalAddress) -> Frame {
        Frame {
            number: address.data() / PAGE_SIZE
        }
    }

    //TODO: Set private
    pub fn range_inclusive(start: Frame, end: Frame) -> FrameIter {
        FrameIter { start, end }
    }
    pub fn next_by(&self, n: usize) -> Self {
        Self {
            number: self.number + n,
        }
    }
}

pub struct FrameIter {
    start: Frame,
    end: Frame,
}

impl Iterator for FrameIter {
    type Item = Frame;

    fn next(&mut self) -> Option<Frame> {
        if self.start <= self.end {
            let frame = self.start.clone();
            self.start.number += 1;
            Some(frame)
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub struct Enomem;

impl From<Enomem> for Error {
    fn from(_: Enomem) -> Self {
        Self::new(ENOMEM)
    }
}
