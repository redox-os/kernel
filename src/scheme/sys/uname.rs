use alloc::Vec;
use syscall::error::Result;

pub fn resource() -> Result<Vec<u8>> {
    Ok(format!("Redox\n\n{}\n\n{}\n",
               env!("CARGO_PKG_VERSION"),
               env!("TARGET").split('-').next().unwrap()).into_bytes())
}

