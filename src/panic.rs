//! Intrinsics for panic handling

use core::alloc::Layout;
use core::panic::PanicInfo;

use crate::{cpu_id, context, interrupt, syscall};

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

    // This could deadlock, but at this point we are going to halt anyways
    {
        let contexts = context::contexts();
        if let Some(context_lock) = contexts.current() {
            let context = context_lock.read();
            println!("NAME: {}", *context.name.read());

            if let Some((a, b, c, d, e, f)) = context.syscall {
                println!("SYSCALL: {}", syscall::debug::format_call(a, b, c, d, e, f));
            }
        }
    }

    println!("HALT");
    loop {
        unsafe { interrupt::halt(); }
    }
}

#[lang = "oom"]
#[no_mangle]
#[allow(improper_ctypes_definitions)] // Layout is not repr(C)
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
