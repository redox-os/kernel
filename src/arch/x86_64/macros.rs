/// Print to console
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ({
        use core::fmt::Write;
        let _ = write!($crate::arch::device::serial::COM1.lock(), $($arg)*);
    });
}

/// Print with new line to console
#[macro_export]
macro_rules! println {
    () => (print!("\n"));
    ($fmt:expr) => (print!(concat!($fmt, "\n")));
    ($fmt:expr, $($arg:tt)*) => (print!(concat!($fmt, "\n"), $($arg)*));
}

#[allow(dead_code)]
#[repr(packed)]
pub struct ScratchRegisters {
    pub r11: usize,
    pub r10: usize,
    pub r9: usize,
    pub r8: usize,
    pub rsi: usize,
    pub rdi: usize,
    pub rdx: usize,
    pub rcx: usize,
    pub rax: usize,
}

impl ScratchRegisters {
    pub fn dump(&self) {
        let rax = self.rax;
        let rcx = self.rcx;
        let rdx = self.rdx;
        let rdi = self.rdi;
        let rsi = self.rsi;
        let r8 = self.r8;
        let r9 = self.r9;
        let r10 = self.r10;
        let r11 = self.r11;

        println!("RAX:   {:>016X}", rax);
        println!("RCX:   {:>016X}", rcx);
        println!("RDX:   {:>016X}", rdx);
        println!("RDI:   {:>016X}", rdi);
        println!("RSI:   {:>016X}", rsi);
        println!("R8:    {:>016X}", r8);
        println!("R9:    {:>016X}", r9);
        println!("R10:   {:>016X}", r10);
        println!("R11:   {:>016X}", r11);
    }
}

macro_rules! scratch_push {
    () => (asm!(
        "push rax
        push rcx
        push rdx
        push rdi
        push rsi
        push r8
        push r9
        push r10
        push r11"
        : : : : "intel", "volatile"
    ));
}

macro_rules! scratch_pop {
    () => (asm!(
        "pop r11
        pop r10
        pop r9
        pop r8
        pop rsi
        pop rdi
        pop rdx
        pop rcx
        pop rax"
        : : : : "intel", "volatile"
    ));
}

#[allow(dead_code)]
#[repr(packed)]
pub struct PreservedRegisters {
    pub r15: usize,
    pub r14: usize,
    pub r13: usize,
    pub r12: usize,
    pub rbp: usize,
    pub rbx: usize,
}

impl PreservedRegisters {
    pub fn dump(&self) {
        let rbx = self.rbx;
        let rbp = self.rbp;
        let r12 = self.r12;
        let r13 = self.r13;
        let r14 = self.r14;
        let r15 = self.r15;

        println!("RBX:   {:>016X}", rbx);
        println!("RBP:   {:>016X}", rbp);
        println!("R12:   {:>016X}", r12);
        println!("R13:   {:>016X}", r13);
        println!("R14:   {:>016X}", r14);
        println!("R15:   {:>016X}", r15);
    }
}

macro_rules! preserved_push {
    () => (asm!(
        "push rbx
        push rbp
        push r12
        push r13
        push r14
        push r15"
        : : : : "intel", "volatile"
    ));
}

macro_rules! preserved_pop {
    () => (asm!(
        "pop r15
        pop r14
        pop r13
        pop r12
        pop rbp
        pop rbx"
        : : : : "intel", "volatile"
    ));
}

macro_rules! fs_push {
    () => (asm!(
        "push fs
        mov rax, 0x18
        mov fs, ax"
        : : : : "intel", "volatile"
    ));
}

macro_rules! fs_pop {
    () => (asm!(
        "pop fs"
        : : : : "intel", "volatile"
    ));
}

#[allow(dead_code)]
#[repr(packed)]
pub struct IretRegisters {
    pub rip: usize,
    pub cs: usize,
    pub rflags: usize,
}

impl IretRegisters {
    pub fn dump(&self) {
        let rflags = self.rflags;
        let cs = self.cs;
        let rip = self.rip;

        println!("RFLAG: {:>016X}", rflags);
        println!("CS:    {:>016X}", cs);
        println!("RIP:   {:>016X}", rip);
    }
}

macro_rules! iret {
    () => (asm!(
        "iretq"
        : : : : "intel", "volatile"
    ));
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
            scratch_push!();
            fs_push!();

            // Map kernel
            $crate::arch::x86_64::pti::map();

            // Call inner rust function
            inner();

            // Unmap kernel
            $crate::arch::x86_64::pti::unmap();

            // Pop scratch registers and return
            fs_pop!();
            scratch_pop!();
            iret!();
        }
    };
}

#[allow(dead_code)]
#[repr(packed)]
pub struct InterruptStack {
    pub fs: usize,
    pub scratch: ScratchRegisters,
    pub iret: IretRegisters,
}

impl InterruptStack {
    pub fn dump(&self) {
        self.iret.dump();
        self.scratch.dump();
        println!("FS:    {:>016X}", self.fs);
    }
}

#[macro_export]
macro_rules! interrupt_stack {
    ($name:ident, $stack: ident, $func:block) => {
        #[naked]
        pub unsafe extern fn $name () {
            #[inline(never)]
            unsafe fn inner($stack: &mut $crate::arch::x86_64::macros::InterruptStack) {
                $func
            }

            // Push scratch registers
            scratch_push!();
            fs_push!();

            // Get reference to stack variables
            let rsp: usize;
            asm!("" : "={rsp}"(rsp) : : : "intel", "volatile");

            // Map kernel
            $crate::arch::x86_64::pti::map();

            // Call inner rust function
            inner(&mut *(rsp as *mut $crate::arch::x86_64::macros::InterruptStack));

            // Unmap kernel
            $crate::arch::x86_64::pti::unmap();

            // Pop scratch registers and return
            fs_pop!();
            scratch_pop!();
            iret!();
        }
    };
}

#[allow(dead_code)]
#[repr(packed)]
pub struct InterruptErrorStack {
    pub fs: usize,
    pub scratch: ScratchRegisters,
    pub code: usize,
    pub iret: IretRegisters,
}

impl InterruptErrorStack {
    pub fn dump(&self) {
        self.iret.dump();
        println!("CODE:  {:>016X}", self.code);
        self.scratch.dump();
        println!("FS:    {:>016X}", self.fs);
    }
}

#[macro_export]
macro_rules! interrupt_error {
    ($name:ident, $stack:ident, $func:block) => {
        #[naked]
        pub unsafe extern fn $name () {
            #[inline(never)]
            unsafe fn inner($stack: &$crate::arch::x86_64::macros::InterruptErrorStack) {
                $func
            }

            // Push scratch registers
            scratch_push!();
            fs_push!();

            // Get reference to stack variables
            let rsp: usize;
            asm!("" : "={rsp}"(rsp) : : : "intel", "volatile");

            // Map kernel
            $crate::arch::x86_64::pti::map();

            // Call inner rust function
            inner(&*(rsp as *const $crate::arch::x86_64::macros::InterruptErrorStack));

            // Unmap kernel
            $crate::arch::x86_64::pti::unmap();

            // Pop scratch registers, error code, and return
            fs_pop!();
            scratch_pop!();
            asm!("add rsp, 8" : : : : "intel", "volatile");
            iret!();
        }
    };
}

#[allow(dead_code)]
#[repr(packed)]
pub struct InterruptStackP {
    pub fs: usize,
    pub preserved: PreservedRegisters,
    pub scratch: ScratchRegisters,
    pub iret: IretRegisters,
}

impl InterruptStackP {
    pub fn dump(&self) {
        self.iret.dump();
        self.scratch.dump();
        self.preserved.dump();
        println!("FS:    {:>016X}", self.fs);
    }
}

#[macro_export]
macro_rules! interrupt_stack_p {
    ($name:ident, $stack: ident, $func:block) => {
        #[naked]
        pub unsafe extern fn $name () {
            #[inline(never)]
            unsafe fn inner($stack: &mut $crate::arch::x86_64::macros::InterruptStackP) {
                $func
            }

            // Push scratch registers
            scratch_push!();
            preserved_push!();
            fs_push!();

            // Get reference to stack variables
            let rsp: usize;
            asm!("" : "={rsp}"(rsp) : : : "intel", "volatile");

            // Map kernel
            $crate::arch::x86_64::pti::map();

            // Call inner rust function
            inner(&mut *(rsp as *mut $crate::arch::x86_64::macros::InterruptStackP));

            // Unmap kernel
            $crate::arch::x86_64::pti::unmap();

            // Pop scratch registers and return
            fs_pop!();
            preserved_pop!();
            scratch_pop!();
            iret!();
        }
    };
}

#[allow(dead_code)]
#[repr(packed)]
pub struct InterruptErrorStackP {
    pub fs: usize,
    pub preserved: PreservedRegisters,
    pub scratch: ScratchRegisters,
    pub code: usize,
    pub iret: IretRegisters,
}

impl InterruptErrorStackP {
    pub fn dump(&self) {
        self.iret.dump();
        println!("CODE:  {:>016X}", self.code);
        self.scratch.dump();
        self.preserved.dump();
        println!("FS:    {:>016X}", self.fs);
    }
}

#[macro_export]
macro_rules! interrupt_error_p {
    ($name:ident, $stack:ident, $func:block) => {
        #[naked]
        pub unsafe extern fn $name () {
            #[inline(never)]
            unsafe fn inner($stack: &$crate::arch::x86_64::macros::InterruptErrorStackP) {
                $func
            }

            // Push scratch registers
            scratch_push!();
            preserved_push!();
            fs_push!();

            // Get reference to stack variables
            let rsp: usize;
            asm!("" : "={rsp}"(rsp) : : : "intel", "volatile");

            // Map kernel
            $crate::arch::x86_64::pti::map();

            // Call inner rust function
            inner(&*(rsp as *const $crate::arch::x86_64::macros::InterruptErrorStackP));

            // Unmap kernel
            $crate::arch::x86_64::pti::unmap();

            // Pop scratch registers, error code, and return
            fs_pop!();
            preserved_pop!();
            scratch_pop!();
            asm!("add rsp, 8" : : : : "intel", "volatile");
            iret!();
        }
    };
}
