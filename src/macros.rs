/// Print to console
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ({
        use core::fmt::Write;
        let _ = write!($crate::device::serial::COM1.lock(), $($arg)*);
    });
}

/// Print with new line to console
#[macro_export]
macro_rules! println {
    () => (print!("\n"));
    ($fmt:expr) => (print!(concat!($fmt, "\n")));
    ($fmt:expr, $($arg:tt)*) => (print!(concat!($fmt, "\n"), $($arg)*));
}

/// Create an interrupt function that can safely run rust code
#[macro_export]
macro_rules! interrupt {
    ($name:ident, $func:block) => {
        #[naked]
        pub unsafe extern fn $name () {
            #[inline(never)]
            unsafe fn inner() {
                $func
            }

            // Push scratch registers
            asm!("push rax
                push rcx
                push rdx
                push rdi
                push rsi
                push r8
                push r9
                push r10
                push r11
                push fs
                mov rax, 0x18
                mov fs, ax"
                : : : : "intel", "volatile");

            // Call inner rust function
            inner();

            // Pop scratch registers and return
            asm!("pop fs
                pop r11
                pop r10
                pop r9
                pop r8
                pop rsi
                pop rdi
                pop rdx
                pop rcx
                pop rax
                iretq"
                : : : : "intel", "volatile");
        }
    };
}

#[allow(dead_code)]
#[repr(packed)]
pub struct InterruptStack {
    pub fs: usize,
    pub r11: usize,
    pub r10: usize,
    pub r9: usize,
    pub r8: usize,
    pub rsi: usize,
    pub rdi: usize,
    pub rdx: usize,
    pub rcx: usize,
    pub rax: usize,
    pub rip: usize,
    pub cs: usize,
    pub rflags: usize,
}

#[macro_export]
macro_rules! interrupt_stack {
    ($name:ident, $stack: ident, $func:block) => {
        #[naked]
        pub unsafe extern fn $name () {
            #[inline(never)]
            unsafe fn inner($stack: &mut $crate::macros::InterruptStack) {
                $func
            }

            // Push scratch registers
            asm!("push rax
                push rcx
                push rdx
                push rdi
                push rsi
                push r8
                push r9
                push r10
                push r11
                push fs
                mov rax, 0x18
                mov fs, ax"
                : : : : "intel", "volatile");

            // Get reference to stack variables
            let rsp: usize;
            asm!("" : "={rsp}"(rsp) : : : "intel", "volatile");

            // Call inner rust function
            inner(&mut *(rsp as *mut $crate::macros::InterruptStack));

            // Pop scratch registers and return
            asm!("pop fs
                pop r11
                pop r10
                pop r9
                pop r8
                pop rsi
                pop rdi
                pop rdx
                pop rcx
                pop rax
                iretq"
                : : : : "intel", "volatile");
        }
    };
}

#[allow(dead_code)]
#[repr(packed)]
pub struct InterruptErrorStack {
    pub fs: usize,
    pub r11: usize,
    pub r10: usize,
    pub r9: usize,
    pub r8: usize,
    pub rsi: usize,
    pub rdi: usize,
    pub rdx: usize,
    pub rcx: usize,
    pub rax: usize,
    pub code: usize,
    pub rip: usize,
    pub cs: usize,
    pub rflags: usize,
}

#[macro_export]
macro_rules! interrupt_error {
    ($name:ident, $stack:ident, $func:block) => {
        #[naked]
        pub unsafe extern fn $name () {
            #[inline(never)]
            unsafe fn inner($stack: &$crate::macros::InterruptErrorStack) {
                $func
            }

            // Push scratch registers
            asm!("push rax
                push rcx
                push rdx
                push rdi
                push rsi
                push r8
                push r9
                push r10
                push r11
                push fs
                mov rax, 0x18
                mov fs, ax"
                : : : : "intel", "volatile");

            // Get reference to stack variables
            let rsp: usize;
            asm!("" : "={rsp}"(rsp) : : : "intel", "volatile");

            // Call inner rust function
            inner(&*(rsp as *const $crate::macros::InterruptErrorStack));

            // Pop scratch registers, error code, and return
            asm!("pop fs
                pop r11
                pop r10
                pop r9
                pop r8
                pop rsi
                pop rdi
                pop rdx
                pop rcx
                pop rax
                add rsp, 8
                iretq"
                : : : : "intel", "volatile");
        }
    };
}
