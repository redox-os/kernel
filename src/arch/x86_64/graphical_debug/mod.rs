use spin::Mutex;

use crate::memory::Frame;
use crate::paging::{ActivePageTable, Page, PhysicalAddress, VirtualAddress};
use crate::paging::entry::EntryFlags;
use crate::paging::mapper::PageFlushAll;

pub use self::debug::DebugDisplay;
use self::display::Display;
use self::mode_info::VBEModeInfo;
use self::primitive::fast_set64;

pub mod debug;
pub mod display;
pub mod mode_info;
pub mod primitive;

pub static FONT: &'static [u8] = include_bytes!("../../../../res/unifont.font");

pub static DEBUG_DISPLAY: Mutex<Option<DebugDisplay>> = Mutex::new(None);

pub fn init(active_table: &mut ActivePageTable) {
    println!("Starting graphical debug");

    let width;
    let height;
    let physbaseptr;

    {
        let mode_info_addr = 0x5200 + crate::PHYS_OFFSET;
        let mode_info = unsafe { &*(mode_info_addr as *const VBEModeInfo) };
        width = mode_info.xresolution as usize;
        height = mode_info.yresolution as usize;
        physbaseptr = mode_info.physbaseptr as usize;
    }

    println!("Framebuffer {}x{} at {:X}", width, height, physbaseptr);

    {
        let size = width * height;

        let onscreen = physbaseptr + crate::PHYS_OFFSET;
        {
            let flush_all = PageFlushAll::new();
            let start_page = Page::containing_address(VirtualAddress::new(onscreen));
            let end_page = Page::containing_address(VirtualAddress::new(onscreen + size * 4));
            for page in Page::range_inclusive(start_page, end_page) {
                let frame = Frame::containing_address(PhysicalAddress::new(page.start_address().data() - crate::PHYS_OFFSET));
                let flags = EntryFlags::PRESENT | EntryFlags::NO_EXECUTE | EntryFlags::WRITABLE | EntryFlags::HUGE_PAGE;
                let result = active_table.map_to(page, frame, flags);
                flush_all.consume(result);
            }
            flush_all.flush(active_table);
        }

        unsafe { fast_set64(onscreen as *mut u64, 0, size/2) };

        let display = Display::new(width, height, onscreen);
        let debug_display = DebugDisplay::new(display);
        *DEBUG_DISPLAY.lock() = Some(debug_display);
    }
}

pub fn fini(active_table: &mut ActivePageTable) {
    if let Some(debug_display) = DEBUG_DISPLAY.lock().take() {
        let display = debug_display.into_display();
        let onscreen = display.onscreen.as_mut_ptr() as usize;
        let size = display.width * display.height;
        {
            let flush_all = PageFlushAll::new();
            let start_page = Page::containing_address(VirtualAddress::new(onscreen));
            let end_page = Page::containing_address(VirtualAddress::new(onscreen + size * 4));
            for page in Page::range_inclusive(start_page, end_page) {
                let (result, _frame) = active_table.unmap_return(page, false);
                flush_all.consume(result);
            }
            flush_all.flush(active_table);
        }
    }

    println!("Finished graphical debug");
}
