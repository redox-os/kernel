use alloc::boxed::Box;
use core::{ptr, slice};

/// A display
pub struct Display {
    pub width: usize,
    pub height: usize,
    pub stride: usize,
    pub onscreen: &'static mut [u32],
    pub offscreen: Option<Box<[u32]>>,
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
            offscreen: None,
        }
    }

    pub fn data_mut(&mut self) -> &mut [u32] {
        match &mut self.offscreen {
            Some(offscreen) => offscreen,
            None => self.onscreen,
        }
    }

    /// Sync from offscreen to onscreen, unsafe because it trusts provided x, y, w, h
    pub unsafe fn sync(&mut self, x: usize, y: usize, w: usize, mut h: usize) {
        if let Some(offscreen) = &self.offscreen {
            let mut offset = y * self.stride + x;
            while h > 0 {
                self.onscreen[offset..offset + w].copy_from_slice(&offscreen[offset..offset + w]);
                offset += self.stride;
                h -= 1;
            }
        }
    }
}
