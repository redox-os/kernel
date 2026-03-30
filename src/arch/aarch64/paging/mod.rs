//! # Paging
//! Some code was borrowed from [Phil Opp's Blog](http://os.phil-opp.com/modifying-page-tables.html)

pub use super::CurrentRmmArch as RmmA;
pub use rmm::{
    aarch64::EntryFlags, Arch as RmmArch, PageFlags, PhysicalAddress, TableKind, VirtualAddress,
};

pub type PageMapper = rmm::PageMapper<RmmA, crate::memory::TheFrameAllocator>;

pub mod mapper;

/// Size of pages
pub const PAGE_SIZE: usize = RmmA::PAGE_SIZE;
pub const PAGE_MASK: usize = RmmA::PAGE_OFFSET_MASK;

/// Initialize MAIR
#[cold]
pub unsafe fn init() {
    unsafe {
        rmm::aarch64::init_mair();
    }
}

/// Page
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Page {
    number: usize,
}

impl Page {
    pub fn start_address(self) -> VirtualAddress {
        VirtualAddress::new(self.number * PAGE_SIZE)
    }

    pub fn containing_address(address: VirtualAddress) -> Page {
        //TODO assert!(address.data() < 0x0000_8000_0000_0000 || address.data() >= 0xffff_8000_0000_0000,
        //    "invalid address: 0x{:x}", address.data());
        Page {
            number: address.data() / PAGE_SIZE,
        }
    }

    pub fn range_inclusive(start: Page, r#final: Page) -> PageIter {
        PageIter {
            start,
            end: r#final.next(),
        }
    }
    pub fn next(self) -> Page {
        self.next_by(1)
    }
    pub fn next_by(self, n: usize) -> Page {
        Self {
            number: self.number + n,
        }
    }
    pub fn offset_from(self, other: Self) -> usize {
        self.number - other.number
    }
}

pub struct PageIter {
    start: Page,
    end: Page,
}

impl Iterator for PageIter {
    type Item = Page;

    fn next(&mut self) -> Option<Page> {
        if self.start < self.end {
            let page = self.start;
            self.start = self.start.next();
            Some(page)
        } else {
            None
        }
    }
}

/// Round down to the nearest multiple of page size
pub fn round_down_pages(number: usize) -> usize {
    number - number % PAGE_SIZE
}
/// Round up to the nearest multiple of page size
pub fn round_up_pages(number: usize) -> usize {
    round_down_pages(number + PAGE_SIZE - 1)
}
