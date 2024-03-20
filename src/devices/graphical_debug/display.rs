use core::ptr;

/// A display
pub struct Display {
    pub width: usize,
    pub height: usize,
    pub stride: usize,
    pub onscreen_ptr: *mut u32,
}

unsafe impl Send for Display {}

impl Display {
    pub fn new(width: usize, height: usize, stride: usize, onscreen_ptr: *mut u32) -> Display {
        unsafe {
            ptr::write_bytes(onscreen_ptr, 0, stride * height);
        }
        Display {
            width,
            height,
            stride,
            onscreen_ptr,
        }
    }
}
