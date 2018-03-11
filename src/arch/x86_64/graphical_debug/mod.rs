use spin::Mutex;

use memory::Frame;
use paging::{ActivePageTable, Page, PhysicalAddress, VirtualAddress};
use paging::entry::EntryFlags;

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
    //TODO: Unmap mode_info and map physbaseptr in kernel space

    println!("Starting graphical debug");

    let width;
    let height;
    let physbaseptr;

    {
        let mode_info_addr = 0x5200;

        {
            let page = Page::containing_address(VirtualAddress::new(mode_info_addr));
            let frame = Frame::containing_address(PhysicalAddress::new(page.start_address().get()));
            let result = active_table.map_to(page, frame, EntryFlags::PRESENT | EntryFlags::NO_EXECUTE);
            result.flush(active_table);
        }

        let mode_info = unsafe { &*(mode_info_addr as *const VBEModeInfo) };

        width = mode_info.xresolution as usize;
        height = mode_info.yresolution as usize;
        physbaseptr = mode_info.physbaseptr as usize;
    }

    {
        let size = width * height;

        {
            let start_page = Page::containing_address(VirtualAddress::new(physbaseptr));
            let end_page = Page::containing_address(VirtualAddress::new(physbaseptr + size * 4));
            for page in Page::range_inclusive(start_page, end_page) {
                let frame = Frame::containing_address(PhysicalAddress::new(page.start_address().get()));
                let result = active_table.map_to(page, frame, EntryFlags::PRESENT | EntryFlags::NO_EXECUTE | EntryFlags::WRITABLE | EntryFlags::HUGE_PAGE);
                result.flush(active_table);
            }
        }

        unsafe { fast_set64(physbaseptr as *mut u64, 0, size/2) };

        *DEBUG_DISPLAY.lock() = Some(DebugDisplay::new(Display::new(width, height, physbaseptr)));
    }
}

pub fn fini(_active_table: &mut ActivePageTable) {
    //TODO: Unmap physbaseptr
    *DEBUG_DISPLAY.lock() = None;

    println!("Finished graphical debug");
}
