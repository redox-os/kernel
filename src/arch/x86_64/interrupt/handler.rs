use core::mem;

use crate::syscall::IntRegisters;

use super::super::flags::*;

#[derive(Default)]
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
        println!("RAX:   {:>016X}", { self.rax });
        println!("RCX:   {:>016X}", { self.rcx });
        println!("RDX:   {:>016X}", { self.rdx });
        println!("RDI:   {:>016X}", { self.rdi });
        println!("RSI:   {:>016X}", { self.rsi });
        println!("R8:    {:>016X}", { self.r8 });
        println!("R9:    {:>016X}", { self.r9 });
        println!("R10:   {:>016X}", { self.r10 });
        println!("R11:   {:>016X}", { self.r11 });
    }
}

#[derive(Default)]
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
        println!("RBX:   {:>016X}", { self.rbx });
        println!("RBP:   {:>016X}", { self.rbp });
        println!("R12:   {:>016X}", { self.r12 });
        println!("R13:   {:>016X}", { self.r13 });
        println!("R14:   {:>016X}", { self.r14 });
        println!("R15:   {:>016X}", { self.r15 });
    }
}

#[derive(Default)]
#[repr(packed)]
pub struct IretRegisters {
    pub rip: usize,
    pub cs: usize,
    pub rflags: usize,

    // ----
    // The following will only be present if interrupt is raised from another
    // privilege ring. Otherwise, they are undefined values.
    // ----

    pub rsp: usize,
    pub ss: usize
}

impl IretRegisters {
    pub fn dump(&self) {
        println!("RFLAG: {:>016X}", { self.rflags });
        println!("CS:    {:>016X}", { self.cs });
        println!("RIP:   {:>016X}", { self.rip });

        if self.cs & 0b11 != 0b00 {
            println!("RSP:   {:>016X}", { self.rsp });
            println!("SS:    {:>016X}", { self.ss });
        }
        unsafe {
            let fsbase = x86::msr::rdmsr(x86::msr::IA32_FS_BASE);
            let gsbase = x86::msr::rdmsr(x86::msr::IA32_KERNEL_GSBASE);
            println!("FSBASE {:>016X}\nGSBASE {:016X}", fsbase, gsbase);
        }
    }
}

#[derive(Default)]
#[repr(packed)]
pub struct InterruptStack {
    pub preserved: PreservedRegisters,
    pub scratch: ScratchRegisters,
    pub iret: IretRegisters,
}

impl InterruptStack {
    pub fn dump(&self) {
        self.iret.dump();
        self.scratch.dump();
        self.preserved.dump();
    }
    /// Saves all registers to a struct used by the proc:
    /// scheme to read/write registers.
    pub fn save(&self, all: &mut IntRegisters) {
        all.r15 = self.preserved.r15;
        all.r14 = self.preserved.r14;
        all.r13 = self.preserved.r13;
        all.r12 = self.preserved.r12;
        all.rbp = self.preserved.rbp;
        all.rbx = self.preserved.rbx;
        all.r11 = self.scratch.r11;
        all.r10 = self.scratch.r10;
        all.r9 = self.scratch.r9;
        all.r8 = self.scratch.r8;
        all.rsi = self.scratch.rsi;
        all.rdi = self.scratch.rdi;
        all.rdx = self.scratch.rdx;
        all.rcx = self.scratch.rcx;
        all.rax = self.scratch.rax;
        all.rip = self.iret.rip;
        all.cs = self.iret.cs;
        all.rflags = self.iret.rflags;

        // Set rsp and ss:

        const CPL_MASK: usize = 0b11;

        let cs: usize;
        unsafe {
            asm!("mov {}, cs", out(reg) cs);
        }

        if self.iret.cs & CPL_MASK == cs & CPL_MASK {
            // Privilege ring didn't change, so neither did the stack
            all.rsp = self as *const Self as usize // rsp after Self was pushed to the stack
                + mem::size_of::<Self>() // disregard Self
                - mem::size_of::<usize>() * 2; // well, almost: rsp and ss need to be excluded as they aren't present
            unsafe {
                asm!("mov {}, ss", out(reg) all.ss);
            }
        } else {
            all.rsp = self.iret.rsp;
            all.ss = self.iret.ss;
        }
    }
    /// Loads all registers from a struct used by the proc:
    /// scheme to read/write registers.
    pub fn load(&mut self, all: &IntRegisters) {
        // TODO: Which of these should be allowed to change?

        // self.fs = all.fs;
        self.preserved.r15 = all.r15;
        self.preserved.r14 = all.r14;
        self.preserved.r13 = all.r13;
        self.preserved.r12 = all.r12;
        self.preserved.rbp = all.rbp;
        self.preserved.rbx = all.rbx;
        self.scratch.r11 = all.r11;
        self.scratch.r10 = all.r10;
        self.scratch.r9 = all.r9;
        self.scratch.r8 = all.r8;
        self.scratch.rsi = all.rsi;
        self.scratch.rdi = all.rdi;
        self.scratch.rdx = all.rdx;
        self.scratch.rcx = all.rcx;
        self.scratch.rax = all.rax;
        self.iret.rip = all.rip;

        // These should probably be restricted
        // self.iret.cs = all.cs;
        // self.iret.rflags = all.eflags;
    }
    /// Enables the "Trap Flag" in the FLAGS register, causing the CPU
    /// to send a Debug exception after the next instruction. This is
    /// used for singlestep in the proc: scheme.
    pub fn set_singlestep(&mut self, enabled: bool) {
        if enabled {
            self.iret.rflags |= FLAG_SINGLESTEP;
        } else {
            self.iret.rflags &= !FLAG_SINGLESTEP;
        }
    }
    /// Checks if the trap flag is enabled, see `set_singlestep`
    pub fn is_singlestep(&self) -> bool {
        self.iret.rflags & FLAG_SINGLESTEP == FLAG_SINGLESTEP
    }
}

#[derive(Default)]
#[repr(packed)]
pub struct InterruptErrorStack {
    pub code: usize,
    pub inner: InterruptStack,
}

impl InterruptErrorStack {
    pub fn dump(&self) {
        println!("CODE:  {:>016X}", { self.code });
        self.inner.dump();
    }
}

#[macro_export]
macro_rules! intel_asm {
    ($($strings:expr,)+) => {
        global_asm!(concat!(
            $($strings),+,
        ));
    };
}
#[macro_export]
macro_rules! function {
    ($name:ident => { $($body:expr,)+ }) => {
        intel_asm!(
            ".global ", stringify!($name), "\n",
            ".type ", stringify!($name), ", @function\n",
            ".section .text.", stringify!($name), ", \"ax\", @progbits\n",
            // Align the function to a 16-byte boundary, padding with multi-byte NOPs.
            ".p2align 4,,15\n",
            stringify!($name), ":\n",
            $($body),+,
            ".size ", stringify!($name), ", . - ", stringify!($name), "\n",
            ".text\n",
        );
        extern "C" {
            pub fn $name();
        }
    };
}

#[macro_export]
macro_rules! push_scratch {
    () => { "
        // Push scratch registers
        push rcx
        push rdx
        push rdi
        push rsi
        push r8
        push r9
        push r10
        push r11
    " };
}
#[macro_export]
macro_rules! pop_scratch {
    () => { "
        // Pop scratch registers
        pop r11
        pop r10
        pop r9
        pop r8
        pop rsi
        pop rdi
        pop rdx
        pop rcx
        pop rax
    " };
}

#[macro_export]
macro_rules! push_preserved {
    () => { "
        // Push preserved registers
        push rbx
        push rbp
        push r12
        push r13
        push r14
        push r15
    " };
}
#[macro_export]
macro_rules! pop_preserved {
    () => { "
        // Pop preserved registers
        pop r15
        pop r14
        pop r13
        pop r12
        pop rbp
        pop rbx
    " };
}
macro_rules! swapgs_iff_ring3_fast {
    () => { "
        // Check whether the last two bits RSP+8 (code segment) are equal to zero.
        test QWORD PTR [rsp + 8], 0x3
        // Skip the SWAPGS instruction if CS & 0b11 == 0b00.
        jz 1f
        swapgs
        1:
    " };
}
macro_rules! swapgs_iff_ring3_fast_errorcode {
    () => { "
        test QWORD PTR [rsp + 16], 0x3
        jz 1f
        swapgs
        1:
    " };
}
#[macro_export]
macro_rules! swapgs_iff_ring3_slow {
    () => { "
    push rax
    push rdx
    push rcx
    mov ecx, 0xC0000102
    rdmsr
    shl rdx, 32
    or eax, edx
    test rdx, rdx
    jnz 1f
    swapgs
    1:
    pop rcx
    pop rdx
    pop rax
    " }
}

#[macro_export]
macro_rules! interrupt_stack {
    // XXX: Apparently we cannot use $expr and check for bool exhaustiveness, so we will have to
    // use idents directly instead.
    ($name:ident, super_atomic: $is_super_atomic:ident!, |$stack:ident| $code:block) => {
        paste::item! {
            #[no_mangle]
            unsafe extern "C" fn [<__interrupt_ $name>]($stack: &mut $crate::arch::x86_64::interrupt::InterruptStack) {
                let _guard = $crate::ptrace::set_process_regs($stack);

                // TODO: Force the declarations to specify unsafe?

                #[allow(unused_unsafe)]
                unsafe {
                    $code
                }
            }

            function!($name => {
                // Backup all userspace registers to stack
                $is_super_atomic!(),
                "push rax\n",
                push_scratch!(),
                push_preserved!(),

                // TODO: Map PTI
                // $crate::arch::x86_64::pti::map();

                // Call inner function with pointer to stack
                "mov rdi, rsp\n",
                "call __interrupt_", stringify!($name), "\n",

                // TODO: Unmap PTI
                // $crate::arch::x86_64::pti::unmap();

                // Restore all userspace registers
                pop_preserved!(),
                pop_scratch!(),

                $is_super_atomic!(),
                "iretq\n",
            });
        }
    };
    ($name:ident, |$stack:ident| $code:block) => { interrupt_stack!($name, super_atomic: swapgs_iff_ring3_fast!, |$stack| $code); };
}

#[macro_export]
macro_rules! interrupt {
    ($name:ident, || $code:block) => {
        paste::item! {
            #[no_mangle]
            unsafe extern "C" fn [<__interrupt_ $name>]() {
                $code
            }

            function!($name => {
                // Backup all userspace registers to stack
                swapgs_iff_ring3_fast!(),
                "push rax\n",
                push_scratch!(),

                // TODO: Map PTI
                // $crate::arch::x86_64::pti::map();

                // Call inner function with pointer to stack
                "call __interrupt_", stringify!($name), "\n",

                // TODO: Unmap PTI
                // $crate::arch::x86_64::pti::unmap();

                // Restore all userspace registers
                pop_scratch!(),

                swapgs_iff_ring3_fast!(),
                "iretq\n",
            });
        }
    };
}

#[macro_export]
macro_rules! interrupt_error {
    ($name:ident, |$stack:ident| $code:block) => {
        paste::item! {
            #[no_mangle]
            unsafe extern "C" fn [<__interrupt_ $name>]($stack: &mut $crate::arch::x86_64::interrupt::handler::InterruptErrorStack) {
                let _guard = $crate::ptrace::set_process_regs(&mut $stack.inner);

                #[allow(unused_unsafe)]
                unsafe {
                    $code
                }
            }

            function!($name => {
                swapgs_iff_ring3_fast_errorcode!(),
                // Move rax into code's place, put code in last instead (to be
                // compatible with InterruptStack)
                "xchg [rsp], rax\n",

                // Push all userspace registers
                push_scratch!(),
                push_preserved!(),

                // Put code in, it's now in rax
                "push rax\n",

                // TODO: Map PTI
                // $crate::arch::x86_64::pti::map();

                // Call inner function with pointer to stack
                "mov rdi, rsp\n",
                "call __interrupt_", stringify!($name), "\n",

                // TODO: Unmap PTI
                // $crate::arch::x86_64::pti::unmap();

                // Pop code
                "add rsp, 8\n",

                // Restore all userspace registers
                pop_preserved!(),
                pop_scratch!(),

                swapgs_iff_ring3_fast_errorcode!(),
                "iretq\n",
            });
        }
    };
}
