use alloc::vec::Vec;

use crate::{
    dtb::DTB_BINARY,
    sync::CleanLockToken,
    syscall::error::{Error, Result, ENODEV},
};
use fdt::Fdt;

#[cfg(target_arch = "riscv64")]
use core::arch::asm;

enum SeedStatus {
    BIST, // Built-in self-test
    Wait,
    Entropy(u16), // ES16
    Dead,
}
use SeedStatus::*;

#[cfg(target_arch = "riscv64")]
fn read_seed_csr() -> SeedStatus {
    let output: u32;
    unsafe {
        asm!("csrrw {}, seed, zero", out(reg) output);
    }
    let status = output >> 30;
    match status {
        0b00 => BIST,
        0b01 => Wait,
        0b10 => Entropy(output as u16),
        0b11 => Dead,
        _ => unreachable!(),
    }
}

fn has_isa_extension(extension: &str) -> bool {
    let dtb = DTB_BINARY.get().unwrap();
    let fdt = Fdt::new(dtb).unwrap();

    // TODO: Do not assume that all harts have the same ISA
    let Some(cpu) = fdt.cpus().next() else {
        return false;
    };

    let Some(isa_prop) = cpu
        .properties()
        .find(|prop| prop.name == "riscv,isa-extensions")
    else {
        return false;
    };

    isa_prop.iter_str().find(|ext| *ext == extension).is_some()
}

#[cfg_attr(not(target_arch = "riscv64"), allow(unused))]
pub fn resource(_token: &mut CleanLockToken) -> Result<Vec<u8>> {
    if !cfg!(target_arch = "riscv64") {
        return Err(Error::new(ENODEV));
    }

    if !has_isa_extension("zkr") {
        return Err(Error::new(ENODEV));
    }

    const SEED_BYTES: usize = 32;
    let mut bytes: Vec<u8> = Vec::with_capacity(SEED_BYTES);

    while bytes.len() < SEED_BYTES {
        #[cfg(target_arch = "riscv64")]
        match read_seed_csr() {
            BIST | Wait => {}
            Entropy(seed) => {
                bytes.extend_from_slice(&seed.to_ne_bytes());
            }
            Dead => {
                error!("zkr entropy source is dead!");
                return Err(Error::new(ENODEV));
            }
        }
    }

    Ok(bytes)
}
