use alloc::boxed::Box;
use core::{ptr, slice};

/// A display
pub(super) struct Display {
    pub(super) width: usize,
    pub(super) height: usize,
    pub(super) stride: usize,
    onscreen: &'static mut [u32],
    offscreen: Option<Box<[u32]>>,
}

impl Display {
    pub(super) fn new(
        width: usize,
        height: usize,
        stride: usize,
        onscreen_ptr: *mut u32,
    ) -> Display {
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

    pub(super) fn heap_init(&mut self) {
        self.offscreen = Some(self.onscreen.to_vec().into_boxed_slice());
    }

    pub(super) fn data_mut(&mut self) -> &mut [u32] {
        match &mut self.offscreen {
            Some(offscreen) => offscreen,
            None => self.onscreen,
        }
    }

    /// Sync from offscreen to onscreen, unsafe because it trusts provided x, y, w, h
    pub(super) unsafe fn sync(&mut self, x: usize, y: usize, w: usize, mut h: usize) {
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
