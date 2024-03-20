use core::{cmp, ptr};

use super::Display;

static FONT: &[u8] = include_bytes!("../../../res/unifont.font");

pub struct DebugDisplay {
    pub(super) display: Display,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
}

impl DebugDisplay {
    pub(super) fn new(display: Display) -> DebugDisplay {
        let w = display.width / 8;
        let h = display.height / 16;
        DebugDisplay {
            display,
            x: 0,
            y: 0,
            w,
            h,
        }
    }

    fn write_char(&mut self, c: char) {
        if self.x >= self.w || c == '\n' {
            self.x = 0;
            self.y += 1;
        }

        if self.y >= self.h {
            let new_y = self.h - 1;
            let d_y = self.y - new_y;

            self.scroll(d_y * 16);

            unsafe {
                self.display
                    .sync(0, 0, self.display.width, self.display.height);
            }

            self.y = new_y;
        }

        if c != '\n' {
            self.char(self.x * 8, self.y * 16, c, 0xFFFFFF);

            unsafe {
                self.display.sync(self.x * 8, self.y * 16, 8, 16);
            }

            self.x += 1;
        }
    }

    pub fn write(&mut self, buf: &[u8]) {
        for &b in buf {
            self.write_char(b as char);
        }
    }

    /// Draw a character
    fn char(&mut self, x: usize, y: usize, character: char, color: u32) {
        if x + 8 <= self.display.width && y + 16 <= self.display.height {
            let mut dst = unsafe { self.display.data_mut().add(y * self.display.stride + x) };

            let font_i = 16 * (character as usize);
            if font_i + 16 <= FONT.len() {
                for row in 0..16 {
                    let row_data = FONT[font_i + row];
                    for col in 0..8 {
                        if (row_data >> (7 - col)) & 1 == 1 {
                            unsafe {
                                *dst.add(col) = color;
                            }
                        }
                    }
                    dst = unsafe { dst.add(self.display.stride) };
                }
            }
        }
    }

    /// Scroll the screen
    fn scroll(&mut self, lines: usize) {
        let offset = cmp::min(self.display.height, lines) * self.display.stride;
        let size = (self.display.stride * self.display.height) - offset;
        unsafe {
            let ptr = self.display.data_mut();
            ptr::copy(ptr.add(offset), ptr, size);
            ptr::write_bytes(ptr.add(size), 0, offset);
        }
    }
}
