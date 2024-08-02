use core::str;
use spin::Mutex;

pub use self::debug::DebugDisplay;
use self::display::Display;

pub mod debug;
pub mod display;

pub static DEBUG_DISPLAY: Mutex<Option<DebugDisplay>> = Mutex::new(None);

pub static FRAMEBUFFER: Mutex<(usize, usize, usize)> = Mutex::new((0, 0, 0));

#[allow(unused)]
pub fn init(env: &[u8]) {
    println!("Starting graphical debug");

    let mut phys = 0;
    let mut virt = 0;
    let mut width = 0;
    let mut height = 0;
    let mut stride = 0;

    //TODO: should errors be reported?
    for line in str::from_utf8(env).unwrap_or("").lines() {
        let mut parts = line.splitn(2, '=');
        let name = parts.next().unwrap_or("");
        let value = parts.next().unwrap_or("");

        if name == "FRAMEBUFFER_ADDR" {
            phys = usize::from_str_radix(value, 16).unwrap_or(0);
        }

        if name == "FRAMEBUFFER_VIRT" {
            virt = usize::from_str_radix(value, 16).unwrap_or(0);
        }

        if name == "FRAMEBUFFER_WIDTH" {
            width = usize::from_str_radix(value, 16).unwrap_or(0);
        }

        if name == "FRAMEBUFFER_HEIGHT" {
            height = usize::from_str_radix(value, 16).unwrap_or(0);
        }

        if name == "FRAMEBUFFER_STRIDE" {
            stride = usize::from_str_radix(value, 16).unwrap_or(0);
        }
    }

    *FRAMEBUFFER.lock() = (phys, virt, stride * height * 4);

    if phys == 0 || virt == 0 || width == 0 || height == 0 || stride == 0 {
        println!("Framebuffer not found");
        return;
    }

    println!(
        "Framebuffer {}x{} stride {} at {:X} mapped to {:X}",
        width, height, stride, phys, virt
    );

    {
        let display = Display::new(width, height, stride, virt as *mut u32);
        let debug_display = DebugDisplay::new(display);
        *DEBUG_DISPLAY.lock() = Some(debug_display);
    }
}

#[allow(unused)]
pub fn init_heap() {
    if let Some(debug_display) = &mut *DEBUG_DISPLAY.lock() {
        debug_display.display.heap_init();
    }
}

#[allow(unused)]
pub fn fini() {
    DEBUG_DISPLAY.lock().take();

    println!("Finished graphical debug");
}
