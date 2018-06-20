//! Intrinsics for panic handling

use core::panic::PanicInfo;

use interrupt;

#[lang = "eh_personality"]
#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

/// Required to handle panics
#[panic_implementation]
#[no_mangle]
pub extern "C" fn rust_begin_unwind(info: &PanicInfo) -> ! {
    println!("KERNEL PANIC: {}", info);

    unsafe { interrupt::stack_trace(); }

    println!("HALT");
    loop {
        unsafe { interrupt::halt(); }
    }
}

#[lang = "oom"]
#[no_mangle]
pub extern fn rust_oom() -> ! {
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
