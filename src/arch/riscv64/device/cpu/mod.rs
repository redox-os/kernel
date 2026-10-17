use core::fmt::{Result, Write};

use fdt::properties::values::StringList;
use sbi_rt::{get_marchid, get_mimpid, get_mvendorid};

use crate::dtb::{global_dtb, Fdt};

pub fn cpu_info<W: Write>(w: &mut W) -> Result {
    writeln!(w, "Vendor ID: 0x{:x}", get_mvendorid())?;
    writeln!(w, "Architecture ID: 0x{:x}", get_marchid())?;
    writeln!(w, "Implementation ID: 0x{:x}", get_mimpid())?;

    if let Some(dtb) = global_dtb() {
        match dtb {
            Ok(fdt) => dtb_info(w, &fdt)?,
            Err(e) => {
                error!("cpu_info: could not read fdt: {}", e);
            }
        }
    }

    Ok(())
}

fn dtb_info<W: Write>(w: &mut W, fdt: &Fdt) -> Result {
    // TODO: Do not assume that all harts have the same ISA
    let Some(cpu) = fdt
        .root()
        .find_node("/cpus")
        .unwrap()
        .children()
        .iter()
        .next()
    else {
        return Ok(());
    };

    if let Some(isa_prop) = cpu.properties().find("riscv,isa-extensions") {
        write!(w, "Features:")?;
        for extension in isa_prop.as_value::<StringList>().unwrap() {
            write!(w, " {}", extension)?;
        }
        writeln!(w)?;
    }

    Ok(())
}
