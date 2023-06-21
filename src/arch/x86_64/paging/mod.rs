//! # Paging
//! Some code was borrowed from [Phil Opp's Blog](http://os.phil-opp.com/modifying-page-tables.html)

use core::fmt::Debug;

use x86::irq::PageFaultError;
use x86::msr;

pub use rmm::{
    Arch as RmmArch,
    Flusher,
    PageFlags,
    PhysicalAddress,
    TableKind,
    VirtualAddress,
};
pub use super::CurrentRmmArch as RmmA;

pub type PageMapper = rmm::PageMapper<RmmA, crate::arch::rmm::LockedAllocator>;
use crate::context::memory::{AccessMode, try_correcting_page_tables, PfError};
use crate::interrupt::InterruptStack;
pub use crate::rmm::KernelMapper;

pub mod entry;
pub mod mapper;

/// Number of entries per page table
pub const ENTRY_COUNT: usize = RmmA::PAGE_ENTRIES;

/// Size of pages
pub const PAGE_SIZE: usize = RmmA::PAGE_SIZE;

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

/// Initialize PAT
#[cold]
pub unsafe fn init() {
    init_pat();
}

/// Page
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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
        PageIter { start, end: r#final.next() }
    }
    pub fn range_exclusive(start: Page, end: Page) -> PageIter {
        PageIter { start, end }
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
impl Debug for Page {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "[page at {:p}]", self.start_address().data() as *const u8)
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
    number.div_floor(PAGE_SIZE) * PAGE_SIZE
}
/// Round up to the nearest multiple of page size
pub fn round_up_pages(number: usize) -> usize {
    number.next_multiple_of(PAGE_SIZE)
}
pub struct Segv;

pub fn page_fault_handler(stack: &mut InterruptStack, code: PageFaultError, faulting_address: VirtualAddress) -> Result<(), Segv> {
    let faulting_page = Page::containing_address(faulting_address);

    extern "C" {
        static __usercopy_start: u8;
        static __usercopy_end: u8;
    }
    let usercopy_region = unsafe { (&__usercopy_start as *const u8 as usize)..(&__usercopy_end as *const u8 as usize) };

    // TODO: Most likely not necessary, but maybe also check that cr2 is not too close to USER_END.
    let address_is_user = faulting_address.kind() == TableKind::User;

    let invalid_page_tables = code.contains(PageFaultError::RSVD);
    let caused_by_user = code.contains(PageFaultError::US);
    let caused_by_kernel = !caused_by_user;
    let caused_by_write = code.contains(PageFaultError::WR);
    let caused_by_instr_fetch = code.contains(PageFaultError::ID);
    let is_usercopy = usercopy_region.contains(&{ stack.iret.rip });

    let mode = match (caused_by_write, caused_by_instr_fetch) {
        (true, false) => AccessMode::Write,
        (false, false) => AccessMode::Read,
        (false, true) => AccessMode::InstrFetch,
        (true, true) => unreachable!("page fault cannot be caused by both instruction fetch and write"),
    };

    if invalid_page_tables {
        // TODO: Better error code than Segv?
        return Err(Segv);
    }

    if address_is_user && (caused_by_user || is_usercopy) {
        match try_correcting_page_tables(faulting_page, mode) {
            Ok(()) => return Ok(()),
            Err(PfError::Oom) => todo!("oom"),
            Err(PfError::Segv) => (),
            Err(PfError::NonfatalInternalError) => todo!(),
        }
    }

    if address_is_user && caused_by_kernel && mode != AccessMode::InstrFetch && is_usercopy {
        // We were inside a usercopy function that failed. This is handled by setting rax to a
        // nonzero value, and emulating the ret instruction.
        stack.scratch.rax = 1;
        let ret_addr = unsafe { (stack.iret.rsp as *const usize).read() };
        stack.iret.rsp += 8;
        stack.iret.rip = ret_addr;
        stack.iret.rflags &= !(1 << 18);
        return Ok(());
    }

    Err(Segv)
}
