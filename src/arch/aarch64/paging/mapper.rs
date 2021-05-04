use core::mem;
use core::ptr::Unique;

use crate::memory::{allocate_frames, deallocate_frames, Frame};

use super::{ActivePageTable, Page, PAGE_SIZE, PageFlags, PhysicalAddress, TableKind, VirtualAddress};
use super::entry::{EntryFlags, PageDescriptorFlags};
use super::table::{self, Table, Level4};
use super::RmmA;

pub use rmm::{PageFlush, PageFlushAll};

#[derive(Debug)]
pub struct Mapper {
    p4: Unique<Table<Level4>>,
    pub table_kind: TableKind
}

impl Mapper {
    /// Create a new page table
    pub unsafe fn new(table_kind: TableKind) -> Mapper {
        match table_kind {
            TableKind::User => Mapper { p4: Unique::new_unchecked(table::U4), table_kind },
            TableKind::Kernel => Mapper { p4: Unique::new_unchecked(table::P4), table_kind }
        }
    }

    pub fn p4(&self) -> &Table<Level4> {
        unsafe { self.p4.as_ref() }
    }

    pub fn p4_mut(&mut self) -> &mut Table<Level4> {
        unsafe { self.p4.as_mut() }
    }

    /// Map a page to a frame
    pub fn map_to(&mut self, page: Page, frame: Frame, flags: PageFlags<RmmA>) -> PageFlush<RmmA> {
        let p3 = self.p4_mut().next_table_create(page.p4_index());
        let p2 = p3.next_table_create(page.p3_index());
        let p1 = p2.next_table_create(page.p2_index());

        assert!(p1[page.p1_index()].is_unused(),
            "{:X}: Set to {:X}: {:?}, requesting {:X}: {:?}",
            page.start_address().data(),
            p1[page.p1_index()].address().data(), p1[page.p1_index()].flags(),
            frame.start_address().data(), flags);
        p1.increment_entry_count();
        p1[page.p1_index()].set(frame, flags);
        PageFlush::new(page.start_address())
    }

    /// Map a page to the next free frame
    pub fn map(&mut self, page: Page, flags: PageFlags<RmmA>) -> PageFlush<RmmA> {
        let frame = allocate_frames(1).expect("out of frames");
        self.map_to(page, frame, flags)
    }

    /// Update flags for a page
    pub fn remap(&mut self, page: Page, flags: PageFlags<RmmA>) -> PageFlush<RmmA> {
        let p3 = self.p4_mut().next_table_mut(page.p4_index()).expect("failed to remap: no p3");
        let p2 = p3.next_table_mut(page.p3_index()).expect("failed to remap: no p2");
        let p1 = p2.next_table_mut(page.p2_index()).expect("failed to remap: no p1");
        let frame = p1[page.p1_index()].pointed_frame_at_l1().expect("failed to remap: not mapped");
        p1[page.p1_index()].set(frame, flags);
        PageFlush::new(page.start_address())
    }

    /// Identity map a frame
    pub fn identity_map(&mut self, frame: Frame, flags: PageFlags<RmmA>) -> PageFlush<RmmA> {
        let page = Page::containing_address(VirtualAddress::new(frame.start_address().data()));
        self.map_to(page, frame, flags)
    }

    fn unmap_inner(&mut self, page: Page, keep_parents: bool) -> Frame {
        let frame;

        let p4 = self.p4_mut();
        if let Some(p3) = p4.next_table_mut(page.p4_index()) {
            if let Some(p2) = p3.next_table_mut(page.p3_index()) {
                if let Some(p1) = p2.next_table_mut(page.p2_index()) {
                    frame = if let Some(frame) = p1[page.p1_index()].pointed_frame_at_l1() {
                        frame
                    } else {
                        panic!("unmap_inner({:X}): frame not found", page.start_address().data())
                    };

                    p1.decrement_entry_count();
                    p1[page.p1_index()].set_unused();

                    if keep_parents || ! p1.is_unused() {
                        return frame;
                    }
                } else {
                    panic!("unmap_inner({:X}): p1 not found", page.start_address().data());
                }

                if let Some(p1_frame) = p2[page.p2_index()].pointed_frame() {
                    //println!("unmap_inner: Free p1 {:?}", p1_frame);
                    p2.decrement_entry_count();
                    p2[page.p2_index()].set_unused();
                    deallocate_frames(p1_frame, 1);
                } else {
                    panic!("unmap_inner({:X}): p1_frame not found", page.start_address().data());
                }

                if ! p2.is_unused() {
                    return frame;
                }
            } else {
                panic!("unmap_inner({:X}): p2 not found", page.start_address().data());
            }

            if let Some(p2_frame) = p3[page.p3_index()].pointed_frame() {
                //println!("unmap_inner: Free p2 {:?}", p2_frame);
                p3.decrement_entry_count();
                p3[page.p3_index()].set_unused();
                deallocate_frames(p2_frame, 1);
            } else {
                panic!("unmap_inner({:X}): p2_frame not found", page.start_address().data());
            }

            if ! p3.is_unused() {
                return frame;
            }
        } else {
            panic!("unmap_inner({:X}): p3 not found", page.start_address().data());
        }

        if let Some(p3_frame) = p4[page.p4_index()].pointed_frame() {
            //println!("unmap_inner: Free p3 {:?}", p3_frame);
            p4.decrement_entry_count();
            p4[page.p4_index()].set_unused();
            deallocate_frames(p3_frame, 1);
        } else {
            panic!("unmap_inner({:X}): p3_frame not found", page.start_address().data());
        }

        frame
    }

    /// Unmap a page
    pub fn unmap(&mut self, page: Page) -> PageFlush<RmmA> {
        let frame = self.unmap_inner(page, false);
        deallocate_frames(frame, 1);
        PageFlush::new(page.start_address())
    }

    /// Unmap a page, return frame without free
    pub fn unmap_return(&mut self, page: Page, keep_parents: bool) -> (PageFlush<RmmA>, Frame) {
        let frame = self.unmap_inner(page, keep_parents);
        (PageFlush::new(page.start_address()), frame)
    }

    pub fn translate_page(&self, page: Page) -> Option<Frame> {
        self.p4().next_table(page.p4_index())
            .and_then(|p3| p3.next_table(page.p3_index()))
            .and_then(|p2| p2.next_table(page.p2_index()))
            .and_then(|p1| p1[page.p1_index()].pointed_frame())
    }

    pub fn translate_page_flags(&self, page: Page) -> Option<PageFlags<RmmA>> {
        self.p4().next_table(page.p4_index())
            .and_then(|p3| p3.next_table(page.p3_index()))
            .and_then(|p2| p2.next_table(page.p2_index()))
            .and_then(|p1| Some(p1[page.p1_index()].flags()))
    }

    /// Translate a virtual address to a physical one
    pub fn translate(&self, virtual_address: VirtualAddress) -> Option<PhysicalAddress> {
        let offset = virtual_address.data() % PAGE_SIZE;
        self.translate_page(Page::containing_address(virtual_address))
            .map(|frame| PhysicalAddress::new(frame.start_address().data() + offset))
    }
}
