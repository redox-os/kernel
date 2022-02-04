//! # Paging
//! Some code was borrowed from [Phil Opp's Blog](http://os.phil-opp.com/modifying-page-tables.html)

use core::ops::{Deref, DerefMut};
use core::{mem, ptr};
use spin::Mutex;
use x86::msr;

use crate::memory::Frame;

use self::entry::EntryFlags;
use self::mapper::{Mapper, PageFlushAll};
use self::table::{Level4, Table};

pub use rmm::{
    Arch as RmmArch,
    PageFlags,
    PhysicalAddress,
    TableKind,
    VirtualAddress,
    X8664Arch as RmmA,
};

pub mod entry;
pub mod mapper;
pub mod table;
pub mod temporary_page;

/// Number of entries per page table
pub const ENTRY_COUNT: usize = 512;

/// Size of pages
pub const PAGE_SIZE: usize = 4096;

//TODO: This is a rudimentary recursive mutex used to naively fix multi_core issues, replace it!
pub struct PageTableLock {
    cpu_id: usize,
    count: usize,
}

pub static PAGE_TABLE_LOCK: Mutex<PageTableLock> = Mutex::new(PageTableLock {
    cpu_id: 0,
    count: 0,
});

fn page_table_lock() {
    let cpu_id = crate::cpu_id();
    loop {
        {
            let mut lock = PAGE_TABLE_LOCK.lock();
            if lock.count == 0 || lock.cpu_id == cpu_id {
                lock.cpu_id = cpu_id;
                lock.count += 1;
                return;
            }
        }
        crate::arch::interrupt::pause();
    }
}

fn page_table_unlock() {
    let mut lock = PAGE_TABLE_LOCK.lock();
    lock.count -= 1;
}

/// Setup page attribute table
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

/// Map percpu
unsafe fn map_percpu(cpu_id: usize, mapper: &mut Mapper) -> PageFlushAll<RmmA> {
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

    let flush_all = PageFlushAll::new();
    let start_page = Page::containing_address(VirtualAddress::new(start));
    let end_page = Page::containing_address(VirtualAddress::new(end - 1));
    for page in Page::range_inclusive(start_page, end_page) {
        let result = mapper.map(
            page,
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
) -> (ActivePageTable, usize) {
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

    init_pat();

    let mut active_table = ActivePageTable::new_unlocked(TableKind::User);

    let flush_all = map_percpu(cpu_id, &mut active_table);
    flush_all.flush();

    return (active_table, init_tcb(cpu_id));
}

pub unsafe fn init_ap(
    cpu_id: usize,
    bsp_table: usize,
) -> usize {
    init_pat();

    let mut active_table = ActivePageTable::new_unlocked(TableKind::User);

    let mut new_table = InactivePageTable::from_address(bsp_table);

    {
        let flush_all = map_percpu(cpu_id, &mut new_table.mapper());
        // The flush can be ignored as this is not the active table. See later active_table.switch
        flush_all.ignore();
    };

    // This switches the active table, which is setup by the bootloader, to a correct table
    // setup by the lambda above. This will also flush the TLB
    active_table.switch(new_table);

    init_tcb(cpu_id)
}

#[derive(Debug)]
pub struct ActivePageTable {
    mapper: Mapper<'static>,
    locked: bool,
}

impl Deref for ActivePageTable {
    type Target = Mapper<'static>;

    fn deref(&self) -> &Mapper<'static> {
        &self.mapper
    }
}

impl DerefMut for ActivePageTable {
    fn deref_mut(&mut self) -> &mut Mapper<'static> {
        &mut self.mapper
    }
}

impl ActivePageTable {
    pub unsafe fn new(_table_kind: TableKind) -> ActivePageTable {
        page_table_lock();
        ActivePageTable {
            mapper: Mapper::current(),
            locked: true,
        }
    }

    pub unsafe fn new_unlocked(_table_kind: TableKind) -> ActivePageTable {
        ActivePageTable {
            mapper: Mapper::current(),
            locked: false,
        }
    }

    pub fn switch(&mut self, new_table: InactivePageTable) -> InactivePageTable {
        let old_table = InactivePageTable {
            frame: Frame::containing_address(unsafe {
                RmmA::table()
            })
        };
        unsafe {
            // Activate new page table
            RmmA::set_table(new_table.frame.start_address());
            // Update mapper to new page table
            self.mapper = Mapper::current();
        }
        old_table
    }

    pub fn flush(&mut self, page: Page) {
        unsafe {
            RmmA::invalidate(page.start_address());
        }
    }

    pub fn flush_all(&mut self) {
        unsafe {
            RmmA::invalidate_all();
        }
    }

    pub unsafe fn address(&self) -> usize {
        RmmA::table().data()
    }
}

impl Drop for ActivePageTable {
    fn drop(&mut self) {
        if self.locked {
            page_table_unlock();
            self.locked = false;
        }
    }
}

pub struct InactivePageTable {
    frame: Frame,
}

impl InactivePageTable {
    /// Create a new inactive page table, located at a given frame.
    ///
    /// # Safety
    ///
    /// For this to be safe, the caller must have exclusive access to the corresponding virtual
    /// address of the frame.
    pub unsafe fn new(
        _active_table: &mut ActivePageTable,
        frame: Frame,
    ) -> InactivePageTable {
        // FIXME: Use active_table to ensure that the newly-allocated frame be linearly mapped, in
        // case it is outside the pre-mapped physical address range, or if such a range is too
        // large to fit the whole physical address space in the virtual address space.
        {
            let table = linear_phys_to_virt(frame.start_address())
                .expect("cannot initialize InactivePageTable (currently) without the frame being linearly mapped");
            // now we are able to zero the table

            // SAFETY: The caller must ensure exclusive access to the pointed-to virtual address of
            // the frame.
            (&mut *(table.data() as *mut Table::<Level4>)).zero();
        }

        InactivePageTable { frame }
    }

    pub unsafe fn from_address(address: usize) -> InactivePageTable {
        InactivePageTable {
            frame: Frame::containing_address(PhysicalAddress::new(address)),
        }
    }

    pub fn mapper<'inactive_table>(&'inactive_table mut self) -> Mapper<'inactive_table> {
        unsafe { Mapper::from_p4_unchecked(&mut self.frame) }
    }
    pub unsafe fn address(&self) -> usize {
        self.frame.start_address().data()
    }
}

pub fn linear_phys_to_virt(physical: PhysicalAddress) -> Option<VirtualAddress> {
    physical.data().checked_add(crate::PHYS_OFFSET).map(VirtualAddress::new)
}
pub fn linear_virt_to_phys(virt: VirtualAddress) -> Option<PhysicalAddress> {
    virt.data().checked_sub(crate::PHYS_OFFSET).map(PhysicalAddress::new)
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

    pub fn range_inclusive(start: Page, end: Page) -> PageIter {
        PageIter { start, end }
    }

    pub fn next(self) -> Page {
        Self {
            number: self.number + 1,
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
        if self.start <= self.end {
            let page = self.start;
            self.start = self.start.next();
            Some(page)
        } else {
            None
        }
    }
}
