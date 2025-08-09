use alloc::boxed::Box;
use core::{ptr, slice};

/// A display
pub(super) struct Display {
    pub(super) width: usize,
    pub(super) height: usize,
    pub(super) stride: usize,
    onscreen_ptr: *mut u32,
    offscreen: Option<Box<[u32]>>,
    pub(super) offset_y: usize,
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
            offset_y: 0,
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
            let mut y = y;
            while h > 0 {
                let src_y = (self.offset_y + y) % self.height;
                let src_offset = src_y * self.stride + x;
                let dst_offset = y * self.stride + x;

                ptr::copy(
                    offscreen.as_ptr().add(src_offset),
                    self.onscreen_ptr.add(dst_offset),
                    w,
                );

                y += 1;
                h -= 1;
            }
        }
    }

    // sync the whole screen (faster)
    pub(super) unsafe fn sync_screen(&mut self) {
        if let Some(offscreen) = &self.offscreen {
            let stride_bytes = self.stride;
            let first_part_len = (self.height - self.offset_y) * stride_bytes;
            let second_part_len = self.offset_y * stride_bytes;

            ptr::copy(
                offscreen.as_ptr().add(self.offset_y * stride_bytes),
                self.onscreen_ptr,
                first_part_len,
            );
            ptr::copy(
                offscreen.as_ptr(),
                self.onscreen_ptr.add(first_part_len),
                second_part_len,
            );
        }
    }
}
