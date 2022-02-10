use core::str;
use spin::Mutex;

use crate::memory::Frame;
use crate::paging::{ActivePageTable, Page, PageFlags, PhysicalAddress, VirtualAddress};
use crate::paging::entry::EntryFlags;
use crate::paging::mapper::PageFlushAll;

pub use self::debug::DebugDisplay;
use self::display::Display;
use self::primitive::fast_set64;

pub mod debug;
pub mod display;
pub mod primitive;

pub static FONT: &'static [u8] = include_bytes!("../../../../res/unifont.font");

pub static DEBUG_DISPLAY: Mutex<Option<DebugDisplay>> = Mutex::new(None);

pub fn init(active_table: &mut ActivePageTable, env: &[u8]) {
    println!("Starting graphical debug");

    let mut width = 0;
    let mut height = 0;
    let mut physbaseptr = 0;

    //TODO: should errors be reported?
    for line in str::from_utf8(env).unwrap_or("").lines() {
        let mut parts = line.splitn(2, '=');
        let name = parts.next().unwrap_or("");
        let value = parts.next().unwrap_or("");

        if name == "FRAMEBUFFER_ADDR" {
            physbaseptr = usize::from_str_radix(value, 16).unwrap_or(0);
        }

        if name == "FRAMEBUFFER_WIDTH" {
            width = usize::from_str_radix(value, 16).unwrap_or(0);
        }

        if name == "FRAMEBUFFER_HEIGHT" {
            height = usize::from_str_radix(value, 16).unwrap_or(0);
        }
    }

    if physbaseptr == 0 || width == 0 || height == 0 {
        println!("Framebuffer not found");
        return;
    }

    println!("Framebuffer {}x{} at {:X}", width, height, physbaseptr);

    {
        let size = width * height * 4;

        let onscreen = physbaseptr + crate::PHYS_OFFSET;
        {
            let flush_all = PageFlushAll::new();
            let start_page = Page::containing_address(VirtualAddress::new(onscreen));
            let end_page = Page::containing_address(VirtualAddress::new(onscreen + size - 1));
            for page in Page::range_inclusive(start_page, end_page) {
                let frame = Frame::containing_address(PhysicalAddress::new(page.start_address().data() - crate::PHYS_OFFSET));
                let flags = PageFlags::new().write(true).custom_flag(EntryFlags::HUGE_PAGE.bits(), true);
                let result = active_table.map_to(page, frame, flags);
                flush_all.consume(result);
            }
            flush_all.flush();
        }

        unsafe { fast_set64(onscreen as *mut u64, 0, size/8) };

        let display = Display::new(width, height, onscreen);
        let debug_display = DebugDisplay::new(display);
        *DEBUG_DISPLAY.lock() = Some(debug_display);
    }
}

pub fn fini(active_table: &mut ActivePageTable) {
    let debug_display_opt = DEBUG_DISPLAY.lock().take();
    if let Some(debug_display) = debug_display_opt {
        let display = debug_display.into_display();
        let onscreen = display.onscreen.as_mut_ptr() as usize;
        let size = display.onscreen.len() * 4;
        //TODO: fix crash if we unmap this memory
        if false {
            let flush_all = PageFlushAll::new();
            let start_page = Page::containing_address(VirtualAddress::new(onscreen));
            let end_page = Page::containing_address(VirtualAddress::new(onscreen + size - 1));
            for page in Page::range_inclusive(start_page, end_page) {
                let (result, _frame) = active_table.unmap_return(page, false);
                flush_all.consume(result);
            }
            flush_all.flush();
        }
    }

    println!("Finished graphical debug");
}
