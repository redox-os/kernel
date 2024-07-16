//! # Paging
//! Some code was borrowed from [Phil Opp's Blog](http://os.phil-opp.com/modifying-page-tables.html)

use x86::msr;

pub use super::CurrentRmmArch as RmmA;
pub use rmm::{Arch as RmmArch, PageFlags, PhysicalAddress, TableKind, VirtualAddress};

pub type PageMapper = rmm::PageMapper<RmmA, crate::memory::TheFrameAllocator>;

pub mod entry {
    bitflags! {
        pub struct EntryFlags: usize {
            const NO_CACHE =        1 << 4;
            const HUGE_PAGE =       1 << 7;
            const GLOBAL =          1 << 8;
            const DEV_MEM =         0;
        }
    }
}

pub mod mapper;

/// Size of pages
pub const PAGE_SIZE: usize = RmmA::PAGE_SIZE;
pub const PAGE_MASK: usize = RmmA::PAGE_OFFSET_MASK;

/// Setup page attribute table
#[cold]
unsafe fn init_pat() {
    let uncacheable = 0;
    let write_combining = 1;
    let write_through = 4;
    //let write_protected = 5;
    let write_back = 6;
    let uncached = 7;

    let pat0 = write_back;
    let pat1 = write_through;
    let pat2 = uncached;
    let pat3 = uncacheable;

    let pat4 = write_combining;
    let pat5 = pat1;
    let pat6 = pat2;
    let pat7 = pat3;

    msr::wrmsr(
        msr::IA32_PAT,
        pat7 << 56
            | pat6 << 48
            | pat5 << 40
            | pat4 << 32
            | pat3 << 24
            | pat2 << 16
            | pat1 << 8
            | pat0,
    );
}

#[cold]
pub unsafe fn init() {
    init_pat();
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
