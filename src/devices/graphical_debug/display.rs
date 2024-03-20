use core::{ptr, slice};

/// A display
pub struct Display {
    pub width: usize,
    pub height: usize,
    pub stride: usize,
    pub onscreen: &'static mut [u32],
}

impl Display {
    pub fn new(width: usize, height: usize, stride: usize, onscreen_ptr: *mut u32) -> Display {
        let size = stride * height;
        let onscreen = unsafe {
            ptr::write_bytes(onscreen_ptr, 0, size);
            slice::from_raw_parts_mut(onscreen_ptr, size)
        };
        Display {
            width,
            height,
            stride,
            onscreen,
        }
    }
}
