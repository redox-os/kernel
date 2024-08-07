//! Intrinsics for panic handling

use core::panic::PanicInfo;

use crate::{context, cpu_id, interrupt, syscall};

/// Required to handle panics
#[panic_handler]
fn rust_begin_unwind(info: &PanicInfo) -> ! {
    println!("KERNEL PANIC: {}", info);

    unsafe {
        interrupt::stack_trace();
    }
    let context_lock = context::current();

    println!("CPU {}, CID {:p}", cpu_id(), context_lock);

    // This could deadlock, but at this point we are going to halt anyways
    {
        let context = context_lock.read();
        println!("NAME: {}", context.name);

        if let Some([a, b, c, d, e, f]) = context.current_syscall() {
            println!("SYSCALL: {}", syscall::debug::format_call(a, b, c, d, e, f));
        }
    }

    println!("HALT");
    loop {
        unsafe {
            interrupt::halt();
        }
    }
}
