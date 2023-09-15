use core::slice;

use alloc::vec::Vec;
use spin::once::Once;

pub static DTB_BINARY: Once<Vec<u8>> = Once::new();

pub unsafe fn init(dtb: Option<(usize, usize)>) {
    let mut initialized = false;
    DTB_BINARY.call_once(|| {
        initialized = true;

        let mut binary = Vec::new();
        if let Some((dtb_base, dtb_size)) = dtb {
            let data = unsafe { slice::from_raw_parts(dtb_base as *const u8, dtb_size) };
            binary.extend(data);
        };
        binary
    });
    if !initialized {
        println!("DTB_BINARY INIT TWICE!");
    }
}
