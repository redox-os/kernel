//! # Paging
//! Some code was borrowed from [Phil Opp's Blog](http://os.phil-opp.com/modifying-page-tables.html)

use core::{mem, ptr};
use core::ops::{Deref, DerefMut};
use x86::shared::{control_regs, msr, tlb};

use memory::{allocate_frames, Frame};

use self::entry::EntryFlags;
use self::mapper::Mapper;
use self::temporary_page::TemporaryPage;

pub mod entry;
pub mod mapper;
pub mod table;
pub mod temporary_page;

/// Number of entries per page table
pub const ENTRY_COUNT: usize = 512;

/// Size of pages
pub const PAGE_SIZE: usize = 4096;

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

    msr::wrmsr(msr::IA32_PAT, pat7 << 56 | pat6 << 48 | pat5 << 40 | pat4 << 32
                            | pat3 << 24 | pat2 << 16 | pat1 << 8 | pat0);
}

/// Copy tdata, clear tbss, set TCB self pointer
unsafe fn init_tcb(cpu_id: usize) -> usize {
    extern {
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
        let size = & __tbss_end as *const _ as usize - & __tdata_start as *const _ as usize;
        let tbss_offset = & __tbss_start as *const _ as usize - & __tdata_start as *const _ as usize;

        let start = ::KERNEL_PERCPU_OFFSET + ::KERNEL_PERCPU_SIZE * cpu_id;
        let end = start + size;
        tcb_offset = end - mem::size_of::<usize>();

        ptr::copy(& __tdata_start as *const u8, start as *mut u8, tbss_offset);
        ptr::write_bytes((start + tbss_offset) as *mut u8, 0, size - tbss_offset);

        *(tcb_offset as *mut usize) = end;
    }
    tcb_offset
}

/// Initialize paging
///
/// Returns page table and thread control block offset
pub unsafe fn init(cpu_id: usize, kernel_start: usize, kernel_end: usize, stack_start: usize, stack_end: usize) -> (ActivePageTable, usize) {
    extern {
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

    let mut active_table = ActivePageTable::new();

    let mut temporary_page = TemporaryPage::new(Page::containing_address(VirtualAddress::new(::USER_TMP_MISC_OFFSET)));

    let mut new_table = {
        let frame = allocate_frames(1).expect("no more frames in paging::init new_table");
        InactivePageTable::new(frame, &mut active_table, &mut temporary_page)
    };

    active_table.with(&mut new_table, &mut temporary_page, |mapper| {
        // Remap stack writable, no execute
        {
            let start_frame = Frame::containing_address(PhysicalAddress::new(stack_start - ::KERNEL_OFFSET));
            let end_frame = Frame::containing_address(PhysicalAddress::new(stack_end - ::KERNEL_OFFSET - 1));
            for frame in Frame::range_inclusive(start_frame, end_frame) {
                let page = Page::containing_address(VirtualAddress::new(frame.start_address().get() + ::KERNEL_OFFSET));
                let result = mapper.map_to(page, frame, EntryFlags::PRESENT | EntryFlags::GLOBAL | EntryFlags::NO_EXECUTE | EntryFlags::WRITABLE);
                // The flush can be ignored as this is not the active table. See later active_table.switch
                unsafe { result.ignore(); }
            }
        }

        // Map all frames in kernel
        {
            let start_frame = Frame::containing_address(PhysicalAddress::new(kernel_start));
            let end_frame = Frame::containing_address(PhysicalAddress::new(kernel_end - 1));
            for frame in Frame::range_inclusive(start_frame, end_frame) {
                let phys_addr = frame.start_address().get();
                let virt_addr = phys_addr + ::KERNEL_OFFSET;

                macro_rules! in_section {
                    ($n: ident) => (
                        virt_addr >= & concat_idents!(__, $n, _start) as *const u8 as usize &&
                        virt_addr < & concat_idents!(__, $n, _end) as *const u8 as usize
                    );
                }

                let flags = if in_section!(text) {
                    // Remap text read-only
                    EntryFlags::PRESENT | EntryFlags::GLOBAL
                } else if in_section!(rodata) {
                    // Remap rodata read-only, no execute
                    EntryFlags::PRESENT | EntryFlags::GLOBAL | EntryFlags::NO_EXECUTE
                } else if in_section!(data) {
                    // Remap data writable, no execute
                    EntryFlags::PRESENT | EntryFlags::GLOBAL | EntryFlags::NO_EXECUTE | EntryFlags::WRITABLE
                } else if in_section!(tdata) {
                    // Remap tdata master read-only, no execute
                    EntryFlags::PRESENT | EntryFlags::GLOBAL | EntryFlags::NO_EXECUTE
                } else if in_section!(bss) {
                    // Remap bss writable, no execute
                    EntryFlags::PRESENT | EntryFlags::GLOBAL | EntryFlags::NO_EXECUTE | EntryFlags::WRITABLE
                } else {
                    // Remap anything else read-only, no execute
                    EntryFlags::PRESENT | EntryFlags::GLOBAL | EntryFlags::NO_EXECUTE
                };

                let page = Page::containing_address(VirtualAddress::new(virt_addr));
                let result = mapper.map_to(page, frame, flags);
                // The flush can be ignored as this is not the active table. See later active_table.switch
                unsafe { result.ignore(); }
            }
        }

        // Map tdata and tbss
        {
            let size = & __tbss_end as *const _ as usize - & __tdata_start as *const _ as usize;

            let start = ::KERNEL_PERCPU_OFFSET + ::KERNEL_PERCPU_SIZE * cpu_id;
            let end = start + size;

            let start_page = Page::containing_address(VirtualAddress::new(start));
            let end_page = Page::containing_address(VirtualAddress::new(end - 1));
            for page in Page::range_inclusive(start_page, end_page) {
                let result = mapper.map(page, EntryFlags::PRESENT | EntryFlags::GLOBAL | EntryFlags::NO_EXECUTE | EntryFlags::WRITABLE);
                // The flush can be ignored as this is not the active table. See later active_table.switch
                result.ignore();
            }
        }
    });

    // This switches the active table, which is setup by the bootloader, to a correct table
    // setup by the lambda above. This will also flush the TLB
    active_table.switch(new_table);

    (active_table, init_tcb(cpu_id))
}

pub unsafe fn init_ap(cpu_id: usize, bsp_table: usize, stack_start: usize, stack_end: usize) -> usize {
    extern {
        /// The starting byte of the thread data segment
        static mut __tdata_start: u8;
        /// The ending byte of the thread data segment
        static mut __tdata_end: u8;
        /// The starting byte of the thread BSS segment
        static mut __tbss_start: u8;
        /// The ending byte of the thread BSS segment
        static mut __tbss_end: u8;
    }

    init_pat();

    let mut active_table = ActivePageTable::new();

    let mut new_table = InactivePageTable::from_address(bsp_table);

    let mut temporary_page = TemporaryPage::new(Page::containing_address(VirtualAddress::new(::USER_TMP_MISC_OFFSET)));

    active_table.with(&mut new_table, &mut temporary_page, |mapper| {
        // Map tdata and tbss
        {
            let size = & __tbss_end as *const _ as usize - & __tdata_start as *const _ as usize;

            let start = ::KERNEL_PERCPU_OFFSET + ::KERNEL_PERCPU_SIZE * cpu_id;
            let end = start + size;

            let start_page = Page::containing_address(VirtualAddress::new(start));
            let end_page = Page::containing_address(VirtualAddress::new(end - 1));
            for page in Page::range_inclusive(start_page, end_page) {
                let result = mapper.map(page, EntryFlags::PRESENT | EntryFlags::GLOBAL | EntryFlags::NO_EXECUTE | EntryFlags::WRITABLE);
                // The flush can be ignored as this is not the active table. See later active_table.switch
                result.ignore();
            }
        }

        let mut remap = |start: usize, end: usize, flags: EntryFlags| {
            if end > start {
                let start_frame = Frame::containing_address(PhysicalAddress::new(start));
                let end_frame = Frame::containing_address(PhysicalAddress::new(end - 1));
                for frame in Frame::range_inclusive(start_frame, end_frame) {
                    let page = Page::containing_address(VirtualAddress::new(frame.start_address().get() + ::KERNEL_OFFSET));
                    let result = mapper.map_to(page, frame, flags);
                    // The flush can be ignored as this is not the active table. See later active_table.switch
                    result.ignore();
                }
            }
        };

        // Remap stack writable, no execute
        remap(stack_start - ::KERNEL_OFFSET, stack_end - ::KERNEL_OFFSET, EntryFlags::PRESENT | EntryFlags::GLOBAL | EntryFlags::NO_EXECUTE | EntryFlags::WRITABLE);
    });

    // This switches the active table, which is setup by the bootloader, to a correct table
    // setup by the lambda above. This will also flush the TLB
    active_table.switch(new_table);

    init_tcb(cpu_id)
}

pub struct ActivePageTable {
    mapper: Mapper,
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
    pub unsafe fn new() -> ActivePageTable {
        ActivePageTable {
            mapper: Mapper::new(),
        }
    }

    pub fn switch(&mut self, new_table: InactivePageTable) -> InactivePageTable {
        let old_table = InactivePageTable {
            p4_frame: Frame::containing_address(
                PhysicalAddress::new(unsafe { control_regs::cr3() } as usize)
            ),
        };
        unsafe {
            control_regs::cr3_write(new_table.p4_frame.start_address().get() as u64);
        }
        old_table
    }

    pub fn flush(&mut self, page: Page) {
        unsafe { tlb::flush(page.start_address().get()); }
    }

    pub fn flush_all(&mut self) {
        unsafe { tlb::flush_all(); }
    }

    pub fn with<F>(&mut self, table: &mut InactivePageTable, temporary_page: &mut TemporaryPage, f: F)
        where F: FnOnce(&mut Mapper)
    {
        {
            let backup = Frame::containing_address(PhysicalAddress::new(unsafe { control_regs::cr3() as usize }));

            // map temporary_page to current p4 table
            let p4_table = temporary_page.map_table_frame(backup.clone(), EntryFlags::PRESENT | EntryFlags::WRITABLE | EntryFlags::NO_EXECUTE, self);

            // overwrite recursive mapping
            self.p4_mut()[::RECURSIVE_PAGE_PML4].set(table.p4_frame.clone(), EntryFlags::PRESENT | EntryFlags::WRITABLE | EntryFlags::NO_EXECUTE);
            self.flush_all();

            // execute f in the new context
            f(self);

            // restore recursive mapping to original p4 table
            p4_table[::RECURSIVE_PAGE_PML4].set(backup, EntryFlags::PRESENT | EntryFlags::WRITABLE | EntryFlags::NO_EXECUTE);
            self.flush_all();
        }

        temporary_page.unmap(self);
    }

    pub unsafe fn address(&self) -> usize {
        control_regs::cr3() as usize
    }
}

pub struct InactivePageTable {
    p4_frame: Frame,
}

impl InactivePageTable {
    pub fn new(frame: Frame, active_table: &mut ActivePageTable, temporary_page: &mut TemporaryPage) -> InactivePageTable {
        {
            let table = temporary_page.map_table_frame(frame.clone(), EntryFlags::PRESENT | EntryFlags::WRITABLE | EntryFlags::NO_EXECUTE, active_table);
            // now we are able to zero the table
            table.zero();
            // set up recursive mapping for the table
            table[::RECURSIVE_PAGE_PML4].set(frame.clone(), EntryFlags::PRESENT | EntryFlags::WRITABLE | EntryFlags::NO_EXECUTE);
        }
        temporary_page.unmap(active_table);

        InactivePageTable { p4_frame: frame }
    }

    pub unsafe fn from_address(cr3: usize) -> InactivePageTable {
        InactivePageTable { p4_frame: Frame::containing_address(PhysicalAddress::new(cr3)) }
    }

    pub unsafe fn address(&self) -> usize {
        self.p4_frame.start_address().get()
    }
}

/// A physical address.
#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PhysicalAddress(usize);

impl PhysicalAddress {
    pub fn new(address: usize) -> Self {
        PhysicalAddress(address)
    }

    pub fn get(&self) -> usize {
        self.0
    }
}

/// A virtual address.
#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct VirtualAddress(usize);

impl VirtualAddress {
    pub fn new(address: usize) -> Self {
        VirtualAddress(address)
    }

    pub fn get(&self) -> usize {
        self.0
    }
}

/// Page
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Page {
    number: usize
}

impl Page {
    pub fn start_address(&self) -> VirtualAddress {
        VirtualAddress::new(self.number * PAGE_SIZE)
    }

    pub fn p4_index(&self) -> usize {
        (self.number >> 27) & 0o777
    }

    pub fn p3_index(&self) -> usize {
        (self.number >> 18) & 0o777
    }

    pub fn p2_index(&self) -> usize {
        (self.number >> 9) & 0o777
    }

    pub fn p1_index(&self) -> usize {
        self.number & 0o777
    }

    pub fn containing_address(address: VirtualAddress) -> Page {
        //TODO assert!(address.get() < 0x0000_8000_0000_0000 || address.get() >= 0xffff_8000_0000_0000,
        //    "invalid address: 0x{:x}", address.get());
        Page { number: address.get() / PAGE_SIZE }
    }

    pub fn range_inclusive(start: Page, end: Page) -> PageIter {
        PageIter {
            start: start,
            end: end,
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
            self.start.number += 1;
            Some(page)
        } else {
            None
        }
    }
}
