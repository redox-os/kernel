//! Intrinsics for panic handling

use core::alloc::Layout;
use core::panic::PanicInfo;

use crate::{cpu_id, context, interrupt};

#[lang = "eh_personality"]
#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

/// Required to handle panics
#[panic_handler]
#[no_mangle]
pub extern "C" fn rust_begin_unwind(info: &PanicInfo) -> ! {
    println!("KERNEL PANIC: {}", info);

    unsafe { interrupt::stack_trace(); }

    println!("CPU {}, PID {:?}", cpu_id(), context::context_id());
    //WARNING: name cannot be grabed, it may deadlock

    println!("HALT");
    loop {
        unsafe { interrupt::halt(); }
    }
}

#[lang = "oom"]
#[no_mangle]
pub extern fn rust_oom(_layout: Layout) -> ! {
    panic!("kernel memory allocation failed");
}

#[allow(non_snake_case)]
#[no_mangle]
/// Required to handle panics
pub extern "C" fn _Unwind_Resume() -> ! {
    loop {
        unsafe { interrupt::halt(); }
    }
}
