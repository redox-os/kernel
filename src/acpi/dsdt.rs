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

    pub fn load_aml(&self) -> Result<AmlNamespace, AmlError> {
        parse_aml_table(self.0)
    }

    pub fn slp_typ(&self) -> Option<(u16, u16)> {
        let aml = match self.load_aml() {
            Ok(a) => a,
            Err(e) => match e {
                AmlError::AmlParseError(s) => {
                    println!("{}", s);
                    return None;
                }
            }
        };
        
        let mut slp_typa: u16 = 0;
        let mut slp_typb: u16 = 0;

        if let Some(s) = aml.find_str("\\_S5") {
            if let Some(p) = s.get_as_package() {
                let slp_typa = p[0].get_as_integer();
                let slp_typb = p[1].get_as_integer();

                if slp_typa.is_some() && slp_typb.is_some() {
                    return Some((slp_typa.expect("") as u16, slp_typb.expect("") as u16));
                }
            }
        }

        None
    }

}
