//! # Paging
//! Some code was borrowed from [Phil Opp's Blog](http://os.phil-opp.com/modifying-page-tables.html)

use core::{mem, ptr};

use crate::device::cpu::registers::{control_regs, tlb};

use self::entry::EntryFlags;
use self::mapper::PageFlushAll;

pub use rmm::{
    AArch64Arch as RmmA,
    Arch as RmmArch,
    Flusher,
    PageFlags,
    PhysicalAddress,
    TableKind,
    VirtualAddress,
};

pub type PageMapper = rmm::PageMapper<RmmA, crate::arch::rmm::LockedAllocator>;
pub use crate::rmm::KernelMapper;

pub mod entry;
pub mod mapper;

/// Number of entries per page table
pub const ENTRY_COUNT: usize = RmmA::PAGE_ENTRIES;

/// Size of pages
pub const PAGE_SIZE: usize = RmmA::PAGE_SIZE;

/// Setup Memory Access Indirection Register
unsafe fn init_mair() {
    let mut val: control_regs::MairEl1 = control_regs::mair_el1();

    val.insert(control_regs::MairEl1::DEVICE_MEMORY);
    val.insert(control_regs::MairEl1::NORMAL_UNCACHED_MEMORY);
    val.insert(control_regs::MairEl1::NORMAL_WRITEBACK_MEMORY);

    control_regs::mair_el1_write(val);
}

/// Map percpu
unsafe fn map_percpu(cpu_id: usize, mapper: &mut PageMapper) -> PageFlushAll<RmmA> {
    extern "C" {
        /// The starting byte of the thread data segment
        static mut __tdata_start: u8;
        /// The ending byte of the thread data segment
        static mut __tdata_end: u8;
        /// The starting byte of the thread BSS segment
        static mut __tbss_start: u8;
        /// The ending byte of the thread BSS segment
        static mut __tbss_end: u8;
    }

    let size = &__tbss_end as *const _ as usize - &__tdata_start as *const _ as usize;
    let start = crate::KERNEL_PERCPU_OFFSET + crate::KERNEL_PERCPU_SIZE * cpu_id;
    let end = start + size;

    let mut flush_all = PageFlushAll::new();
    let start_page = Page::containing_address(VirtualAddress::new(start));
    let end_page = Page::containing_address(VirtualAddress::new(end - 1));
    for page in Page::range_inclusive(start_page, end_page) {
        let result = mapper.map(
            page.start_address(),
            PageFlags::new().write(true).custom_flag(EntryFlags::GLOBAL.bits(), cfg!(not(feature = "pti"))),
        )
        .expect("failed to allocate page table frames while mapping percpu");
        flush_all.consume(result);
    }
    flush_all
}

/// Copy tdata, clear tbss, set TCB self pointer
unsafe fn init_tcb(cpu_id: usize) -> usize {
    extern "C" {
        /// The starting byte of the thread data segment
        static mut __tdata_start: u8;
        /// The ending byte of the thread data segment
        static mut __tdata_end: u8;
        /// The starting byte of the thread BSS segment
        static mut __tbss_start: u8;
        /// The ending byte of the thread BSS segment
        static mut __tbss_end: u8;
    }

    let tcb_offset;
    {
        let size = &__tbss_end as *const _ as usize - &__tdata_start as *const _ as usize;
        let tbss_offset = &__tbss_start as *const _ as usize - &__tdata_start as *const _ as usize;

        let start = crate::KERNEL_PERCPU_OFFSET + crate::KERNEL_PERCPU_SIZE * cpu_id;
        println!("SET TPIDR_EL1 TO {:X}", start - 0x10);
        // FIXME: Empirically initializing tpidr to 16 bytes below start works. I do not know
        // whether this is the correct way to handle TLS. Will need to revisit.
        control_regs::tpidr_el1_write((start - 0x10) as u64);
        println!("SET TPIDR_EL1 DONE");

        let end = start + size;
        tcb_offset = end - mem::size_of::<usize>();

        ptr::copy(&__tdata_start as *const u8, start as *mut u8, tbss_offset);
        ptr::write_bytes((start + tbss_offset) as *mut u8, 0, size - tbss_offset);

        *(tcb_offset as *mut usize) = end;
    }
    tcb_offset
}

/// Initialize paging
///
/// Returns page table and thread control block offset
pub unsafe fn init(
    cpu_id: usize,
) -> usize {
    extern "C" {
        /// The starting byte of the text (code) data segment.
        static mut __text_start: u8;
        /// The ending byte of the text (code) data segment.
        static mut __text_end: u8;
        /// The starting byte of the _.rodata_ (read-only data) segment.
        static mut __rodata_start: u8;
        /// The ending byte of the _.rodata_ (read-only data) segment.
        static mut __rodata_end: u8;
        /// The starting byte of the _.data_ segment.
        static mut __data_start: u8;
        /// The ending byte of the _.data_ segment.
        static mut __data_end: u8;
        /// The starting byte of the thread data segment
        static mut __tdata_start: u8;
        /// The ending byte of the thread data segment
        static mut __tdata_end: u8;
        /// The starting byte of the thread BSS segment
        static mut __tbss_start: u8;
        /// The ending byte of the thread BSS segment
        static mut __tbss_end: u8;
        /// The starting byte of the _.bss_ (uninitialized data) segment.
        static mut __bss_start: u8;
        /// The ending byte of the _.bss_ (uninitialized data) segment.
        static mut __bss_end: u8;
    }

    init_mair();

    let flush_all = map_percpu(cpu_id, KernelMapper::lock_manually(cpu_id).get_mut().expect("expected KernelMapper not to be locked re-entrant in paging::init"));
    flush_all.flush();

    return init_tcb(cpu_id);
}

pub unsafe fn init_ap(
    cpu_id: usize,
    bsp_table: &mut KernelMapper,
) -> usize {
    init_mair();

    {
        let flush_all = map_percpu(cpu_id, bsp_table.get_mut().expect("KernelMapper locked re-entrant for AP"));

        // The flush can be ignored as this is not the active table. See later make_current().
        flush_all.ignore();
    };

    bsp_table.make_current();

    init_tcb(cpu_id)
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

    pub fn p4_index(self) -> usize {
        (self.number >> 27) & 0o777
    }

    pub fn p3_index(self) -> usize {
        (self.number >> 18) & 0o777
    }

    pub fn p2_index(self) -> usize {
        (self.number >> 9) & 0o777
    }

    pub fn p1_index(self) -> usize {
        self.number & 0o777
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
