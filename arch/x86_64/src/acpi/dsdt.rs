use core::slice;

use super::sdt::Sdt;

#[derive(Debug)]
pub struct Dsdt(&'static Sdt);

impl Dsdt {
    pub fn new(sdt: &'static Sdt) -> Option<Dsdt> {
        if &sdt.signature == b"DSDT" {
            Some(Dsdt(sdt))
        } else {
            None
        }
    }

    pub fn data(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.0.data_address() as *const u8, self.0.data_len()) }
    }

    pub fn slp_typ(&self) -> Option<(u16, u16)> {
        // Code from http://forum.osdev.org/viewtopic.php?t=16990, should be adapted

        let mut i = 0;
        let data = self.data();

        // search the \_S5 package in the DSDT
        let s5_a = b"\x08_S5_\x12";
        let s5_b = b"\x08\\_S5_\x12";
        while i < data.len() {
            if data[i..].starts_with(s5_a) {
                i += s5_a.len();
                break;
            } else if data[i..].starts_with(s5_b) {
                i += s5_b.len();
                break;
            } else {
                i += 1;
            }
        }

        if i >= data.len() {
            return None;
        }

        // check if \_S5 was found
        let pkglen = ((data[i] & 0xC0) >> 6) + 2;
        i += pkglen as usize;
        if i >= data.len() {
            return None;
        }

        if data[i] == 0x0A {
            i += 1;   // skip byteprefix
            if i >= data.len() {
                return None;
            }
        }

        let SLP_TYPa = (data[i] as u16) << 10;
        i += 1;
        if i >= data.len() {
            return None;
        }

        if data[i] == 0x0A {
            i += 1;   // skip byteprefix
            if i >= data.len() {
                return None;
            }
        }

        let SLP_TYPb = (data[i] as u16) << 10;

        Some((SLP_TYPa, SLP_TYPb))
    }

}
