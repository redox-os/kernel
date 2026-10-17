use core::fmt::{Result, Write};

use fdt::Fdt;
use sbi_rt::{get_marchid, get_mimpid, get_mvendorid};

use crate::dtb::DTB_BINARY;

pub fn cpu_info<W: Write>(w: &mut W) -> Result {
    writeln!(w, "Vendor ID: 0x{:x}", get_mvendorid())?;
    writeln!(w, "Architecture ID: 0x{:x}", get_marchid())?;
    writeln!(w, "Implementation ID: 0x{:x}", get_mimpid())?;

    if let Some(dtb) = DTB_BINARY.get() {
        match Fdt::new(dtb) {
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
    let Some(cpu) = fdt.cpus().next() else {
        return Ok(());
    };

    if let Some(isa_prop) = cpu
        .properties()
        .find(|prop| prop.name == "riscv,isa-extensions")
    {
        write!(w, "Features:")?;
        for extension in isa_prop.iter_str() {
            write!(w, " {}", extension)?;
        }
        writeln!(w)?;
    }

    Ok(())
}
