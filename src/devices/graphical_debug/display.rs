use alloc::boxed::Box;
use core::{ptr, slice};

/// A display
pub(super) struct Display {
    pub(super) width: usize,
    pub(super) height: usize,
    pub(super) stride: usize,
    onscreen_ptr: *mut u32,
    offscreen: Option<Box<[u32]>>,
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
            offscreen: None,
        }
    }

    pub(super) fn heap_init(&mut self) {
        let onscreen =
            unsafe { slice::from_raw_parts(self.onscreen_ptr, self.stride * self.height) };
        self.offscreen = Some(onscreen.to_vec().into_boxed_slice());
    }

    pub(super) fn data_mut(&mut self) -> *mut u32 {
        match &mut self.offscreen {
            Some(offscreen) => offscreen.as_mut_ptr(),
            None => self.onscreen_ptr,
        }
    }

    /// Sync from offscreen to onscreen, unsafe because it trusts provided x, y, w, h
    pub(super) unsafe fn sync(&mut self, x: usize, y: usize, w: usize, mut h: usize) {
        if let Some(offscreen) = &self.offscreen {
            let mut offset = y * self.stride + x;
            while h > 0 {
                ptr::copy(
                    offscreen.as_ptr().add(offset),
                    self.onscreen_ptr.add(offset),
                    w,
                );
                offset += self.stride;
                h -= 1;
            }
        }
    }
}
