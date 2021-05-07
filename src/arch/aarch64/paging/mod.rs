//! # Paging
//! Some code was borrowed from [Phil Opp's Blog](http://os.phil-opp.com/modifying-page-tables.html)

use core::{mem, ptr};
use core::ops::{Deref, DerefMut};
use spin::Mutex;

use crate::device::cpu::registers::{control_regs, tlb};
use crate::memory::{allocate_frames, Frame};

use self::mapper::{Mapper, PageFlushAll};
use self::temporary_page::TemporaryPage;

pub use rmm::{
    AArch64Arch as RmmA,
    Arch as RmmArch,
    PageFlags,
    PhysicalAddress,
    TableKind,
    VirtualAddress,
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

/// Setup Memory Access Indirection Register
unsafe fn init_mair() {
    let mut val: control_regs::MairEl1 = control_regs::mair_el1();

    val.insert(control_regs::MairEl1::DEVICE_MEMORY);
    val.insert(control_regs::MairEl1::NORMAL_UNCACHED_MEMORY);
    val.insert(control_regs::MairEl1::NORMAL_WRITEBACK_MEMORY);

    control_regs::mair_el1_write(val);
}

/// Map TSS
unsafe fn map_tss(cpu_id: usize) {
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

    let mut mapper = crate::rmm::mapper_current();
    let flush_all = PageFlushAll::new();
    let start_page = Page::containing_address(VirtualAddress::new(start));
    let end_page = Page::containing_address(VirtualAddress::new(end - 1));
    for page in Page::range_inclusive(start_page, end_page) {
        let result = mapper.map(
            page.start_address(),
            PageFlags::new().write(true)
        ).expect("Failed to map TSS page");
        flush_all.consume(result);
    }
    flush_all.flush();
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

    println!("INIT MAIR START");
    init_mair();
    println!("INIT MAIR COMPLETE");

    println!("ACTIVE TABLE START");
    let active_table = ActivePageTable::new_unlocked(TableKind::Kernel);
    println!("ACTIVE TABLE COMPLETE");

    println!("MAP TSS START");
    map_tss(cpu_id);
    println!("MAP TSS COMPLETE");

    println!("INIT TCB START");
    let tcb = init_tcb(cpu_id);
    println!("INIT_TCB COMPLETE");

    return (active_table, tcb);
}

pub unsafe fn init_ap(
    cpu_id: usize,
    bsp_table: usize,
) -> usize {
    init_mair();

    let mut active_table = ActivePageTable::new_unlocked(TableKind::Kernel);

    let mut new_table = InactivePageTable::from_address(bsp_table);

    // This switches the active table, which is setup by the bootloader, to a correct table
    // setup by the lambda above. This will also flush the TLB
    active_table.switch(new_table);

    map_tss(cpu_id);

    init_tcb(cpu_id)
}

#[derive(Debug)]
pub struct ActivePageTable {
    mapper: Mapper,
    locked: bool,
}

impl Deref for ActivePageTable {
    type Target = Mapper;

    fn deref(&self) -> &Mapper {
        &self.mapper
    }
}

impl DerefMut for ActivePageTable {
    fn deref_mut(&mut self) -> &mut Mapper {
        &mut self.mapper
    }
}

impl ActivePageTable {
    pub unsafe fn new(table_kind: TableKind) -> ActivePageTable {
        page_table_lock();
        ActivePageTable {
            mapper: Mapper::new(table_kind),
            locked: true,
        }
    }

    pub unsafe fn new_unlocked(table_kind: TableKind) -> ActivePageTable {
        ActivePageTable {
            mapper: Mapper::new(table_kind),
            locked: false,
        }
    }

    pub fn switch(&mut self, new_table: InactivePageTable) -> InactivePageTable {
        let old_table: InactivePageTable;

        match self.mapper.table_kind {
            TableKind::User => {
                old_table = InactivePageTable { frame: Frame::containing_address(PhysicalAddress::new(unsafe { control_regs::ttbr0_el1() } as usize)) };
                unsafe { control_regs::ttbr0_el1_write(new_table.frame.start_address().data() as u64) };
            },
            TableKind::Kernel =>  {
                old_table = InactivePageTable { frame: Frame::containing_address(PhysicalAddress::new(unsafe { control_regs::ttbr1_el1() } as usize)) };
                unsafe { control_regs::ttbr1_el1_write(new_table.frame.start_address().data() as u64) };
            }
        }

        unsafe { tlb::flush_all() };
        old_table
    }

    pub fn flush(&mut self, page: Page) {
        unsafe {
            tlb::flush(page.start_address().data());
        }
    }

    pub fn flush_all(&mut self) {
        unsafe {
            tlb::flush_all();
        }
    }

    pub fn with<F>(&mut self, table: &mut InactivePageTable, temporary_page: &mut TemporaryPage, f: F)
        where F: FnOnce(&mut Mapper)
    {
        {
            let backup = Frame::containing_address(PhysicalAddress::new(unsafe {
                match self.mapper.table_kind {
                    TableKind::User => control_regs::ttbr0_el1() as usize,
                    TableKind::Kernel => control_regs::ttbr1_el1() as usize,
                }
            }));

            // map temporary_page to current p4 table
            let p4_table = temporary_page.map_table_frame(
                backup.clone(),
                PageFlags::new_table().write(true), //TODO: RISC-V will not like this
                self,
            );

            // overwrite recursive mapping
            self.p4_mut()[crate::RECURSIVE_PAGE_PML4].set(
                table.frame.clone(),
                PageFlags::new_table().write(true), //TODO: RISC-V will not like this
            );
            self.flush_all();

            // execute f in the new context
            f(self);

            // restore recursive mapping to original p4 table
            p4_table[crate::RECURSIVE_PAGE_PML4].set(
                backup,
                PageFlags::new_table().write(true), //TODO: RISC-V will not like this
            );
            self.flush_all();
        }

        temporary_page.unmap(self);
    }

    pub unsafe fn address(&self) -> usize {
        match self.mapper.table_kind {
            TableKind::User => control_regs::ttbr0_el1() as usize,
            TableKind::Kernel => control_regs::ttbr1_el1() as usize,
        }
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
    pub fn new(
        frame: Frame,
        active_table: &mut ActivePageTable,
        temporary_page: &mut TemporaryPage,
    ) -> InactivePageTable {
        {
            let table = temporary_page.map_table_frame(
                frame.clone(),
                PageFlags::new_table().write(true), //TODO: RISC-V will not like this
                active_table,
            );
            // now we are able to zero the table
            table.zero();
            // set up recursive mapping for the table
            table[crate::RECURSIVE_PAGE_PML4].set(
                frame.clone(),
                PageFlags::new_table().write(true), //TODO: RISC-V will not like this
            );
        }
        temporary_page.unmap(active_table);

        InactivePageTable { frame: frame }
    }

    pub unsafe fn from_address(address: usize) -> InactivePageTable {
        InactivePageTable {
            frame: Frame::containing_address(PhysicalAddress::new(address)),
        }
    }

    pub unsafe fn address(&self) -> usize {
        self.frame.start_address().data()
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
