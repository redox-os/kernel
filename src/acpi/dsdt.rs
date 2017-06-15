use core::slice;

use super::sdt::Sdt;
use super::aml::{parse_aml_table, AmlError, AmlValue, AmlNamespace};

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

    pub fn load_aml(&self) -> Option<AmlNamespace> {
        let data = self.data();
        match parse_aml_table(data) {
            Ok(p) => Some(p),
            Err(_) => None
        }
    }

    pub fn slp_typ(&self) -> Option<(u16, u16)> {
        let aml = match self.load_aml() {
            Some(a) => a,
            None => return None
        };
        
        let s5 = aml.find_str("\\_S5");

        let mut slp_typa: u16 = 0;
        let mut slp_typb: u16 = 0;
        
        match s5 {
            Some(s) => match s {
                AmlValue::Package(p) => {
                    match p[0] {
                        AmlValue::IntegerConstant(i) => slp_typa = i as u16,
                        _ => return None
                    }
                    
                    match p[1] {
                        AmlValue::IntegerConstant(i) => slp_typb = i as u16,
                        _ => return None
                    }
                },
                _ => return None
            },
            None => return None
        }
        
        Some((slp_typa, slp_typb))
    }

}
