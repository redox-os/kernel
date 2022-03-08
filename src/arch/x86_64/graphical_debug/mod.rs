use core::str;
use spin::Mutex;

pub use self::debug::DebugDisplay;
use self::display::Display;

pub mod debug;
pub mod display;

pub static FONT: &'static [u8] = include_bytes!("../../../../res/unifont.font");

pub static DEBUG_DISPLAY: Mutex<Option<DebugDisplay>> = Mutex::new(None);

pub fn init(env: &[u8]) {
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

        let virtbaseptr = physbaseptr + crate::PHYS_OFFSET;

        let display = Display::new(width, height, virtbaseptr as *mut u32);
        let debug_display = DebugDisplay::new(display);
        *DEBUG_DISPLAY.lock() = Some(debug_display);
    }
}

pub fn init_heap() {
    if let Some(debug_display) = &mut *DEBUG_DISPLAY.lock() {
        debug_display.display.offscreen = Some(
            debug_display.display.onscreen.to_vec().into_boxed_slice()
        );
    }
}

pub fn fini() {
    DEBUG_DISPLAY.lock().take();

    println!("Finished graphical debug");
}
