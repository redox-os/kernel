#![no_std]
#![allow(clippy::new_without_default)]
#![feature(slice_shift)]

use core::ops::AddAssign;

pub use crate::{allocator::*, arch::*, page::*};

mod allocator;
mod arch;
mod page;

pub const KILOBYTE: usize = 1024;
pub const MEGABYTE: usize = KILOBYTE * 1024;
pub const GIGABYTE: usize = MEGABYTE * 1024;
#[cfg(target_pointer_width = "64")]
pub const TERABYTE: usize = GIGABYTE * 1024;

/// Specific table to be used, needed on some architectures
//TODO: Use this throughout the code
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TableKind {
    /// Userspace page table
    User,
    /// Kernel page table
    Kernel,
}

/// Physical memory address
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct PhysicalAddress(usize);

impl PhysicalAddress {
    #[inline(always)]
    pub const fn new(address: usize) -> Self {
        Self(address)
    }

    #[inline(always)]
    pub fn data(&self) -> usize {
        self.0
    }

    #[expect(clippy::should_implement_trait)]
    #[inline(always)]
    pub fn add(self, offset: usize) -> Self {
        Self(self.0 + offset)
    }
}

impl core::fmt::Debug for PhysicalAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "[phys {:#0x}]", self.data())
    }
}

/// Virtual memory address
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct VirtualAddress(usize);

impl VirtualAddress {
    #[inline(always)]
    pub const fn new(address: usize) -> Self {
        Self(address)
    }

    #[inline(always)]
    pub fn data(&self) -> usize {
        self.0
    }

    #[expect(clippy::should_implement_trait)]
    #[inline(always)]
    pub fn add(self, offset: usize) -> Self {
        Self(self.0 + offset)
    }

    #[inline(always)]
    pub fn kind(&self) -> TableKind {
        if (self.0 as isize) < 0 {
            TableKind::Kernel
        } else {
            TableKind::User
        }
    }
}

impl core::fmt::Debug for VirtualAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "[virt {:#0x}]", self.data())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct MemoryArea {
    pub base: PhysicalAddress,
    pub size: usize,
}

pub const MAX_MEMORY_AREA_COUNT: usize = 512;

/// A collection of discrete free areas which may or may not be contiguous.
#[derive(Debug)]
pub struct DiscontiguousMemoryArea {
    areas: [MemoryArea; MAX_MEMORY_AREA_COUNT],
    count: usize,
}

impl DiscontiguousMemoryArea {
    pub fn new(areas: &[MemoryArea], offset: usize) -> Self {
        let mut this = Self {
            areas: [MemoryArea {
                base: PhysicalAddress::new(0),
                size: usize::MAX,
            }; MAX_MEMORY_AREA_COUNT],
            count: areas.len(),
        };

        this.areas[..areas.len()].copy_from_slice(areas);
        this.areas[..areas.len()].sort_unstable_by_key(|e| e.base.data());
        this.areas[0].size = this.areas[0].size - offset;
        this.areas[0].base = this.areas[0].base.add(offset);
        this
    }

    /// Returns the free areas to the left or right of the given physical address.
    pub fn bisect(&self, at: PhysicalAddress, left: bool) -> Self {
        let pos = self.areas[..self.count].binary_search_by_key(&at, |e| e.base);

        let mut new = Self {
            areas: [MemoryArea {
                base: PhysicalAddress::new(0),
                size: usize::MAX,
            }; MAX_MEMORY_AREA_COUNT],
            count: self.count,
        };

        match pos {
            Ok(v) => {
                let range = if left { 0..v } else { v..self.count };
                new.count = range.len();
                new.areas[0..new.count].copy_from_slice(&self.areas[range]);
                new
            }
            Err(e) => {
                let range = if left { 0..e } else { e..self.count };
                new.count = range.len();
                new.areas[0..new.count].copy_from_slice(&self.areas[range]);

                if left {
                    let last = new.count.checked_sub(1);
                    if let Some(last) = last
                        && at >= new.areas[last].base
                        && at < new.areas[last].base.add(new.areas[last].size)
                    {
                        new.areas[last].size = at.data() - new.areas[last].base.data();
                    }
                } else {
                    if e != 0
                        && at >= self.areas[e - 1].base
                        && at < self.areas[e - 1].base.add(self.areas[e - 1].size)
                    {
                        let rem = new.areas.shift_right(
                            [MemoryArea {
                                base: at,
                                size: self.areas[e - 1].base.add(self.areas[e - 1].size).data()
                                    - at.data(),
                            }; 1],
                        );
                        assert!(
                            rem.iter().filter(|e| e.size != usize::MAX).count() == 0,
                            "Rem expected to be empty: {:?}",
                            rem
                        );
                        new.count.add_assign(1);
                    }
                }
                new
            }
        }
    }

    pub fn count(&self) -> usize {
        self.count
    }

    pub fn areas(&self) -> &[MemoryArea] {
        &self.areas
    }
}

#[test]
pub fn test_discontiguous_memory_area() {
    let mut areas = [MemoryArea {
        base: PhysicalAddress(0),
        size: 0,
    }; MAX_MEMORY_AREA_COUNT];

    areas[0].base = PhysicalAddress(65_000);
    areas[0].size = 125_000;

    areas[1].base = PhysicalAddress(195_000);
    areas[1].size = 10_000;

    areas[2].base = PhysicalAddress(205_000);
    areas[2].size = 5_000;

    let dis = DiscontiguousMemoryArea::new(&areas[0..3], 0);

    // the case when the bisection point lies in a hole between two free areas
    {
        let bisection_point = PhysicalAddress(192_000);
        let left = dis.bisect(bisection_point, true);
        assert!(
            left.count == 1 && left.areas[0].base.data() == 65_000 && left.areas[0].size == 125_000,
            "Assertion 1 failed: {}, {}, {}",
            left.count,
            left.areas[0].base.data(),
            left.areas[0].size,
        );

        let right = dis.bisect(bisection_point, false);
        assert!(
            right.count == 2
                && right.areas[0].base.data() == 195_000
                && right.areas[0].size == 10_000
                && right.areas[1].base.data() == 205_000
                && right.areas[1].size == 5_000,
            "Assertion 2 failed: {}, {}, {}, {}, {}",
            right.count,
            right.areas[0].base.data(),
            right.areas[0].size,
            right.areas[1].base.data(),
            right.areas[1].size
        );
    } // the case when the bisection point lies in a hole between two free areas

    // the case when the bisection point lies within a free area
    {
        let bisection_point = PhysicalAddress(196_000);

        let left = dis.bisect(bisection_point, true);
        assert!(
            left.count == 2
                && left.areas[0].base.data() == 65_000
                && left.areas[0].size == 125_000
                && left.areas[1].base.data() == 195_000
                && left.areas[1].size == 1000,
            "Assertion 3 failed: {}, {}, {}, {}",
            left.areas[0].base.data(),
            left.areas[0].size,
            left.areas[1].base.data(),
            left.areas[1].size
        );

        let right = dis.bisect(bisection_point, false);
        assert!(
            right.count == 2
                && right.areas[0].base.data() == 196_000
                && right.areas[0].size == 9000
                && right.areas[1].base.data() == 205_000
                && right.areas[1].size == 5000,
            "Assertion 4 failed: {}, {}, {}, {}, {}",
            right.count,
            right.areas[0].base.data(),
            right.areas[0].size,
            right.areas[1].base.data(),
            right.areas[1].size
        );
    } // the  case when the bisection point lies within a free area

    // the case when the bisection point overlaps with the start of a free area
    {
        let bisection_point = PhysicalAddress(195_000);

        let left = dis.bisect(bisection_point, true);
        assert!(
            left.count == 1 && left.areas[0].base.data() == 65_000 && left.areas[0].size == 125_000,
            "Assertion 5 failed: {}, {}, {}",
            left.count,
            left.areas[0].base.data(),
            left.areas[0].size
        );

        let right = dis.bisect(bisection_point, false);
        assert!(
            right.count == 2
                && right.areas[0].base.data() == 195_000
                && right.areas[0].size == 10_000
                && right.areas[1].base.data() == 205_000
                && right.areas[1].size == 5000,
            "Assertion 6 failed: {}, {}, {}, {}, {}",
            right.count,
            right.areas[0].base.data(),
            right.areas[0].size,
            right.areas[1].base.data(),
            right.areas[1].size
        );
    } // the case when the bisection point overlaps with the start of a free area

    areas.iter_mut().for_each(|e| {
        *e = MemoryArea {
            base: PhysicalAddress(0),
            size: usize::MAX,
        }
    });
    areas[0] = MemoryArea {
        base: PhysicalAddress(0x100000000),
        size: 32212254720,
    };

    let dis = DiscontiguousMemoryArea::new(&areas[0..1], 0);

    // the case when the `e` in `Err(e)` is equal to `count`
    {
        let left = dis.bisect(PhysicalAddress(0x100000000 + 0x180000000), true);
        assert!(
            left.count == 1
                && left.areas[0].base.data() == 0x100000000
                && left.areas[0].size == 0x180000000,
            "Assertion 7 failed: {}, {}, {}",
            left.count,
            left.areas[0].base.data(),
            left.areas[0].size
        );

        let right = dis.bisect(PhysicalAddress(0x100000000 + 0x180000000), false);
        assert!(
            right.count == 1
                && right.areas[0].base.data() == 0x100000000 + 0x180000000
                && right.areas[0].size == 25769803776,
            "Assertion 8 failed: {}, {}, {}",
            right.count,
            right.areas[0].base.data(),
            right.areas[0].size
        );
    } // the case when the `e` in `Err(e)` is equal to `count`

    // the case when the `e` in `Err(e)` is equal to 0
    {
        let left = dis.bisect(PhysicalAddress(0), true);
        debug_assert!(left.count() == 0, "Assertion 9 failed: {}", left.count);
    } // the case when the `e` in `Err(e)` is equal to 0
}
