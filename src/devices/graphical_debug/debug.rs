use core::ptr;

pub(super) struct Display {
    pub(super) width: usize,
    pub(super) height: usize,
    pub(super) stride: usize,
    onscreen_ptr: *mut u32,
}

unsafe impl Send for Display {}

static FONT: &[u8] = include_bytes!("../../../res/unifont.font");

pub struct DebugDisplay {
    pub(super) display: Display,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
}

impl DebugDisplay {
    pub(super) fn new(
        width: usize,
        height: usize,
        stride: usize,
        onscreen_ptr: *mut u32,
    ) -> DebugDisplay {
        let display = Display {
            width,
            height,
            stride,
            onscreen_ptr,
        };

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

    pub fn write(&mut self, buf: &[u8]) {
        for &b in buf {
            if self.x >= self.w || b == b'\n' {
                self.x = 0;
                self.y = (self.y + 1) % self.h;
            }

            if b == b'\n' {
                continue;
            }

            if self.x == 0 {
                self.clear_row(self.y);
                self.clear_row((self.y + 1) % self.h);
            }

            self.char(self.x * 8, self.y * 16, b as char, 0xFFFFFF);

            self.x += 1;
        }
    }

    fn clear_row(&mut self, y: usize) {
        for row in y * 16..(y + 1) * 16 {
            unsafe {
                ptr::write_bytes(
                    self.display.onscreen_ptr.add(row * self.display.stride),
                    0,
                    self.display.width,
                );
            }
        }
    }

    /// Draw a character
    fn char(&mut self, x: usize, y: usize, character: char, color: u32) {
        if x + 8 <= self.display.width && y + 16 <= self.display.height {
            let phys_y = y % self.display.height;
            let mut dst = unsafe {
                self.display
                    .onscreen_ptr
                    .add(phys_y * self.display.stride + x)
            };

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

                    let next_phys_y = (phys_y + row + 1) % self.display.height;
                    dst = unsafe {
                        self.display
                            .onscreen_ptr
                            .add(next_phys_y * self.display.stride + x)
                    };
                }
            }
        }
    }
}
