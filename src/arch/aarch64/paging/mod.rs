//! # Paging
//! Some code was borrowed from [Phil Opp's Blog](http://os.phil-opp.com/modifying-page-tables.html)

use core::{mem, ptr};
use core::ops::{Deref, DerefMut};
use spin::Mutex;

use crate::device::cpu::registers::{control_regs, tlb};
use crate::memory::{allocate_frames, Frame};

use self::entry::{EntryFlags, TableDescriptorFlags};
use self::mapper::{Mapper, MapperFlushAll, MapperType};
use self::temporary_page::TemporaryPage;

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
unsafe fn map_tss(cpu_id: usize, mapper: &mut Mapper) -> MapperFlushAll {
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

    let mut flush_all = MapperFlushAll::new();
    let start_page = Page::containing_address(VirtualAddress::new(start));
    let end_page = Page::containing_address(VirtualAddress::new(end - 1));
    for page in Page::range_inclusive(start_page, end_page) {
        let result = mapper.map(
            page,
            EntryFlags::PRESENT
                | EntryFlags::GLOBAL
                | EntryFlags::NO_EXECUTE
                | EntryFlags::WRITABLE,
        );
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

    init_mair();

    let mut active_table = ActivePageTable::new_unlocked(PageTableType::Kernel);

    let flush_all = map_tss(cpu_id, &mut active_table);
    flush_all.flush(&mut active_table);

    return (active_table, init_tcb(cpu_id));
}

pub unsafe fn init_ap(
    cpu_id: usize,
    bsp_table: usize,
) -> usize {
    init_mair();

    let mut active_table = ActivePageTable::new_unlocked(PageTableType::Kernel);

    let mut new_table = InactivePageTable::from_address(bsp_table);

    let mut temporary_page = TemporaryPage::new(Page::containing_address(VirtualAddress::new(
        crate::KERNEL_TMP_MISC_OFFSET,
    )));

    active_table.with(&mut new_table, &mut temporary_page, |mapper| {
        let flush_all = map_tss(cpu_id, mapper);
        // The flush can be ignored as this is not the active table. See later active_table.switch
        flush_all.ignore();
    });

    // This switches the active table, which is setup by the bootloader, to a correct table
    // setup by the lambda above. This will also flush the TLB
    active_table.switch(new_table);

    init_tcb(cpu_id)
}

pub struct ActivePageTable {
    mapper: Mapper,
    locked: bool,
}

pub enum PageTableType {
    User,
    Kernel
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
    //TODO: table_type argument
    pub unsafe fn new(table_type: PageTableType) -> ActivePageTable {
        page_table_lock();
        ActivePageTable {
            mapper: Mapper::new(match table_type {
                PageTableType::User => MapperType::User,
                PageTableType::Kernel => MapperType::Kernel,
            }),
            locked: true,
        }
    }

    //TODO: table_type argument
    pub unsafe fn new_unlocked(table_type: PageTableType) -> ActivePageTable {
        ActivePageTable {
            mapper: Mapper::new(match table_type {
                PageTableType::User => MapperType::User,
                PageTableType::Kernel => MapperType::Kernel,
            }),
            locked: false,
        }
    }

    pub fn switch(&mut self, new_table: InactivePageTable) -> InactivePageTable {
        let old_table: InactivePageTable;

        match self.mapper.mapper_type {
            MapperType::User => {
                old_table = InactivePageTable { p4_frame: Frame::containing_address(PhysicalAddress::new(unsafe { control_regs::ttbr0_el1() } as usize)) };
                unsafe { control_regs::ttbr0_el1_write(new_table.p4_frame.start_address().data() as u64) };
            },
            MapperType::Kernel =>  {
                old_table = InactivePageTable { p4_frame: Frame::containing_address(PhysicalAddress::new(unsafe { control_regs::ttbr1_el1() } as usize)) };
                unsafe { control_regs::ttbr1_el1_write(new_table.p4_frame.start_address().data() as u64) };
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
            let backup: Frame;

            match self.mapper.mapper_type {
                MapperType::User => backup = Frame::containing_address(PhysicalAddress::new(unsafe { control_regs::ttbr0_el1() as usize })),
                MapperType::Kernel => backup = Frame::containing_address(PhysicalAddress::new(unsafe { control_regs::ttbr1_el1() as usize }))
            }

            // map temporary_kpage to current p4 table
            let p4_table = temporary_page.map_table_frame(backup.clone(), EntryFlags::PRESENT | EntryFlags::WRITABLE | EntryFlags::NO_EXECUTE, self);

            // overwrite recursive mapping
            self.p4_mut()[crate::RECURSIVE_PAGE_PML4].page_table_entry_set(
                table.p4_frame.clone(),
                TableDescriptorFlags::VALID | TableDescriptorFlags::TABLE,
            );
            self.flush_all();

            // execute f in the new context
            f(self);

            // restore recursive mapping to original p4 table
            p4_table[crate::RECURSIVE_PAGE_PML4].page_table_entry_set(
                backup,
                TableDescriptorFlags::VALID | TableDescriptorFlags::TABLE,
            );
            self.flush_all();
        }

        temporary_page.unmap(self);
    }

    pub unsafe fn address(&self) -> usize {
        match self.mapper.mapper_type {
            MapperType::User => control_regs::ttbr0_el1() as usize,
            MapperType::Kernel => control_regs::ttbr1_el1() as usize,
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
    p4_frame: Frame,
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
                EntryFlags::PRESENT | EntryFlags::WRITABLE | EntryFlags::NO_EXECUTE,
                active_table,
            );
            // now we are able to zero the table
            table.zero();
            // set up recursive mapping for the table
            table[crate::RECURSIVE_PAGE_PML4].page_table_entry_set(
                frame.clone(),
                TableDescriptorFlags::VALID | TableDescriptorFlags::TABLE
            );
        }
        temporary_page.unmap(active_table);

        InactivePageTable { p4_frame: frame }
    }

    pub unsafe fn from_address(address: usize) -> InactivePageTable {
        InactivePageTable {
            p4_frame: Frame::containing_address(PhysicalAddress::new(address)),
        }
    }

    pub unsafe fn address(&self) -> usize {
        self.p4_frame.start_address().data()
    }
}

/// A physical address.
#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PhysicalAddress(usize);

impl PhysicalAddress {
    pub fn new(address: usize) -> Self {
        PhysicalAddress(address)
    }

    pub fn data(&self) -> usize {
        self.0
    }
}

/// A virtual address.
#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct VirtualAddress(usize);

#[derive(Debug, PartialEq)]
pub enum VirtualAddressType {
    User,
    Kernel
}

impl VirtualAddress {
    pub fn new(address: usize) -> Self {
        VirtualAddress(address)
    }

    pub fn data(&self) -> usize {
        self.0
    }

    pub fn get_type(&self) -> VirtualAddressType {
        if ((self.0 >> 48) & 0xffff) == 0xffff {
            VirtualAddressType::Kernel
        } else {
            VirtualAddressType::User
        }
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
