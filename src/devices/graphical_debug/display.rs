use core::ptr;

/// A display
pub(super) struct Display {
    pub(super) width: usize,
    pub(super) height: usize,
    pub(super) stride: usize,
    onscreen_ptr: *mut u32,
}

unsafe impl Send for Display {}

impl Display {
    pub(super) fn new(
        width: usize,
        height: usize,
        stride: usize,
        onscreen_ptr: *mut u32,
    ) -> Display {
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

    pub(super) fn data_mut(&mut self) -> *mut u32 {
        self.onscreen_ptr
    }
}
