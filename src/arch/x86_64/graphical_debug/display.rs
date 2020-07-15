use core::alloc::{GlobalAlloc, Layout};
use core::{cmp, slice};

use super::FONT;
use super::primitive::{fast_set32, fast_set64, fast_copy};

/// A display
pub struct Display {
    pub width: usize,
    pub height: usize,
    pub onscreen: &'static mut [u32],
    pub offscreen: &'static mut [u32],
}

impl Display {
    pub fn new(width: usize, height: usize, onscreen: usize) -> Display {
        let size = width * height;
        let offscreen = unsafe { crate::ALLOCATOR.alloc(Layout::from_size_align_unchecked(size * 4, 4096)) };
        unsafe { fast_set64(offscreen as *mut u64, 0, size/2) };
        Display {
            width: width,
            height: height,
            onscreen: unsafe { slice::from_raw_parts_mut(onscreen as *mut u32, size) },
            offscreen: unsafe { slice::from_raw_parts_mut(offscreen as *mut u32, size) }
        }
    }

    /// Draw a rectangle
    pub fn rect(&mut self, x: usize, y: usize, w: usize, h: usize, color: u32) {
        let start_y = cmp::min(self.height, y);
        let end_y = cmp::min(self.height, y + h);

        let start_x = cmp::min(self.width, x);
        let len = cmp::min(self.width, x + w) - start_x;

        let mut offscreen_ptr = self.offscreen.as_mut_ptr() as usize;

        let stride = self.width * 4;

        let offset = y * stride + start_x * 4;
        offscreen_ptr += offset;

        let mut rows = end_y - start_y;
        while rows > 0 {
            unsafe {
                fast_set32(offscreen_ptr as *mut u32, color, len);
            }
            offscreen_ptr += stride;
            rows -= 1;
        }
    }

    /// Invert a rectangle
    pub fn invert(&mut self, x: usize, y: usize, w: usize, h: usize) {
        let start_y = cmp::min(self.height, y);
        let end_y = cmp::min(self.height, y + h);

        let start_x = cmp::min(self.width, x);
        let len = cmp::min(self.width, x + w) - start_x;

        let mut offscreen_ptr = self.offscreen.as_mut_ptr() as usize;

        let stride = self.width * 4;

        let offset = y * stride + start_x * 4;
        offscreen_ptr += offset;

        let mut rows = end_y - start_y;
        while rows > 0 {
            let mut row_ptr = offscreen_ptr;
            let mut cols = len;
            while cols > 0 {
                unsafe {
                    let color = *(row_ptr as *mut u32);
                    *(row_ptr as *mut u32) = !color;
                }
                row_ptr += 4;
                cols -= 1;
            }
            offscreen_ptr += stride;
            rows -= 1;
        }
    }

    /// Draw a character
    pub fn char(&mut self, x: usize, y: usize, character: char, color: u32) {
        if x + 8 <= self.width && y + 16 <= self.height {
            let mut dst = self.offscreen.as_mut_ptr() as usize + (y * self.width + x) * 4;

            let font_i = 16 * (character as usize);
            if font_i + 16 <= FONT.len() {
                for row in 0..16 {
                    let row_data = FONT[font_i + row];
                    for col in 0..8 {
                        if (row_data >> (7 - col)) & 1 == 1 {
                            unsafe { *((dst + col * 4) as *mut u32)  = color; }
                        }
                    }
                    dst += self.width * 4;
                }
            }
        }
    }

    // Scroll the screen
    pub fn scroll(&mut self, lines: usize) {
        let offset = cmp::min(self.height, lines) * self.width;
        let size = self.offscreen.len() - offset;
        unsafe {
            let to = self.offscreen.as_mut_ptr();
            let from = to.add(offset);
            fast_copy(to as *mut u8, from as *const u8, size * 4);
        }
    }

    /// Copy from offscreen to onscreen
    pub fn sync(&mut self, x: usize, y: usize, w: usize, h: usize) {
        let start_y = cmp::min(self.height, y);
        let end_y = cmp::min(self.height, y + h);

        let start_x = cmp::min(self.width, x);
        let len = (cmp::min(self.width, x + w) - start_x) * 4;

        let mut offscreen_ptr = self.offscreen.as_mut_ptr() as usize;
        let mut onscreen_ptr = self.onscreen.as_mut_ptr() as usize;

        let stride = self.width * 4;

        let offset = y * stride + start_x * 4;
        offscreen_ptr += offset;
        onscreen_ptr += offset;

        let mut rows = end_y - start_y;
        while rows > 0 {
            unsafe {
                fast_copy(onscreen_ptr as *mut u8, offscreen_ptr as *const u8, len);
            }
            offscreen_ptr += stride;
            onscreen_ptr += stride;
            rows -= 1;
        }
    }
}

impl Drop for Display {
    fn drop(&mut self) {
        unsafe { crate::ALLOCATOR.dealloc(self.offscreen.as_mut_ptr() as *mut u8, Layout::from_size_align_unchecked(self.offscreen.len() * 4, 4096)) };
    }
}
