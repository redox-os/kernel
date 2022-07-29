use super::Display;

pub struct DebugDisplay {
    pub (crate) display: Display,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
}

impl DebugDisplay {
    pub fn new(display: Display) -> DebugDisplay {
        let w = display.width/8;
        let h = display.height/16;
        DebugDisplay {
            display,
            x: 0,
            y: 0,
            w: w,
            h: h,
        }
    }

    pub fn write_char(&mut self, c: char) {
        if self.x >= self.w || c == '\n' {
            self.x = 0;
            self.y += 1;
        }

        if self.y >= self.h {
            let new_y = self.h - 1;
            let d_y = self.y - new_y;

            self.display.scroll(d_y * 16);

            unsafe {
                self.display.sync(0, 0, self.display.width, self.display.height);
            }

            self.y = new_y;
        }

        if c != '\n' {
            self.display.char(
                self.x * 8, self.y * 16,
                c,
                0xFFFFFF
            );

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
}
