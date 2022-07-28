//! # Paging
//! Some code was borrowed from [Phil Opp's Blog](http://os.phil-opp.com/modifying-page-tables.html)

use core::ops::{Deref, DerefMut};
use core::{mem, ptr};
use spin::Mutex;

use crate::memory::Frame;

use self::mapper::{Mapper, PageFlushAll};
use self::temporary_page::TemporaryPage;

pub use rmm::{
    Arch as RmmArch,
    PageFlags,
    PhysicalAddress,
    TableKind,
    VirtualAddress,
    RiscV64Sv48Arch as RmmA,
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
    pub unsafe fn new(_table_kind: TableKind) -> ActivePageTable {
        page_table_lock();
        ActivePageTable {
            mapper: Mapper::new(),
            locked: true,
        }
    }

    pub unsafe fn new_unlocked(_table_kind: TableKind) -> ActivePageTable {
        ActivePageTable {
            mapper: Mapper::new(),
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
            RmmA::set_table(new_table.frame.start_address());
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

    pub fn with<F>(
        &mut self,
        table: &mut InactivePageTable,
        temporary_page: &mut TemporaryPage,
        f: F,
    ) where
        F: FnOnce(&mut Mapper),
    {
        {
            let backup = Frame::containing_address(unsafe {
                RmmA::table()
            });

            // map temporary_page to current p4 table
            let p4_table = temporary_page.map_table_frame(
                backup.clone(),
                PageFlags::new_table(),
                self,
            );

            // overwrite recursive mapping
            self.p4_mut()[crate::RECURSIVE_PAGE_PML4].set(
                table.frame.clone(),
                PageFlags::new_table(),
            );
            self.flush_all();

            // execute f in the new context
            f(self);

            // restore recursive mapping to original p4 table
            p4_table[crate::RECURSIVE_PAGE_PML4].set(
                backup,
                PageFlags::new_table(),
            );
            self.flush_all();
        }

        temporary_page.unmap(self);
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
    pub fn new(
        frame: Frame,
        active_table: &mut ActivePageTable,
        temporary_page: &mut TemporaryPage,
    ) -> InactivePageTable {
        {
            let table = temporary_page.map_table_frame(
                frame.clone(),
                PageFlags::new_table(),
                active_table,
            );
            // now we are able to zero the table
            table.zero();
            // set up recursive mapping for the table
            table[crate::RECURSIVE_PAGE_PML4].set(
                frame.clone(),
                PageFlags::new_table(),
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
