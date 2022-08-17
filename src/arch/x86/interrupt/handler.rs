use core::mem;

use crate::syscall::IntRegisters;

use super::super::flags::*;

#[derive(Default)]
#[repr(packed)]
pub struct ScratchRegisters {
    pub edx: usize,
    pub ecx: usize,
    pub eax: usize,
}

impl ScratchRegisters {
    pub fn dump(&self) {
        println!("EAX:   {:016x}", { self.eax });
        println!("ECX:   {:016x}", { self.ecx });
        println!("EDX:   {:016x}", { self.edx });
    }
}

#[derive(Default)]
#[repr(packed)]
pub struct PreservedRegisters {
    pub ebp: usize,
    pub esi: usize,
    pub edi: usize,
    pub ebx: usize,
}

impl PreservedRegisters {
    pub fn dump(&self) {
        println!("EBX:   {:016x}", { self.ebx });
        println!("EDI:   {:016x}", { self.edi });
        println!("ESI:   {:016x}", { self.esi });
        println!("EBP:   {:016x}", { self.ebp });
    }
}

#[derive(Default)]
#[repr(packed)]
pub struct IretRegisters {
    pub eip: usize,
    pub cs: usize,
    pub eflags: usize,

    // ----
    // The following will only be present if interrupt is raised from another
    // privilege ring. Otherwise, they are undefined values.
    // ----

    pub esp: usize,
    pub ss: usize
}

impl IretRegisters {
    pub fn dump(&self) {
        println!("EFLAG: {:016x}", { self.eflags });
        println!("CS:    {:016x}", { self.cs });
        println!("EIP:   {:016x}", { self.eip });

        if self.cs & 0b11 != 0b00 {
            println!("ESP:   {:016x}", { self.esp });
            println!("SS:    {:016x}", { self.ss });
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
        all.ebp = self.preserved.ebp;
        all.esi = self.preserved.esi;
        all.edi = self.preserved.edi;
        all.ebx = self.preserved.ebx;
        all.edx = self.scratch.edx;
        all.ecx = self.scratch.ecx;
        all.eax = self.scratch.eax;
        all.eip = self.iret.eip;
        all.cs = self.iret.cs;
        all.eflags = self.iret.eflags;

        // Set esp and ss:

        const CPL_MASK: usize = 0b11;

        let cs: usize;
        unsafe {
            core::arch::asm!("mov {}, cs", out(reg) cs);
        }

        if self.iret.cs & CPL_MASK == cs & CPL_MASK {
            // Privilege ring didn't change, so neither did the stack
            all.esp = self as *const Self as usize // esp after Self was pushed to the stack
                + mem::size_of::<Self>() // disregard Self
                - mem::size_of::<usize>() * 2; // well, almost: esp and ss need to be excluded as they aren't present
            unsafe {
                core::arch::asm!("mov {}, ss", out(reg) all.ss);
            }
        } else {
            all.esp = self.iret.esp;
            all.ss = self.iret.ss;
        }
    }
    /// Loads all registers from a struct used by the proc:
    /// scheme to read/write registers.
    pub fn load(&mut self, all: &IntRegisters) {
        // TODO: Which of these should be allowed to change?

        self.preserved.ebp = all.ebp;
        self.preserved.esi = all.esi;
        self.preserved.edi = all.edi;
        self.preserved.ebx = all.ebx;
        self.scratch.edx = all.edx;
        self.scratch.ecx = all.ecx;
        self.scratch.eax = all.eax;
        self.iret.eip = all.eip;

        // These should probably be restricted
        // self.iret.cs = all.cs;
        // self.iret.eflags = all.eflags;
    }
    /// Enables the "Trap Flag" in the FLAGS register, causing the CPU
    /// to send a Debug exception after the next instruction. This is
    /// used for singlestep in the proc: scheme.
    pub fn set_singlestep(&mut self, enabled: bool) {
        if enabled {
            self.iret.eflags |= FLAG_SINGLESTEP;
        } else {
            self.iret.eflags &= !FLAG_SINGLESTEP;
        }
    }
    /// Checks if the trap flag is enabled, see `set_singlestep`
    pub fn is_singlestep(&self) -> bool {
        self.iret.eflags & FLAG_SINGLESTEP == FLAG_SINGLESTEP
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
        println!("CODE:  {:016x}", { self.code });
        self.inner.dump();
    }
}

#[macro_export]
macro_rules! push_scratch {
    () => { "
        // Push scratch registers (minus eax)
        push ecx
        push edx
    " };
}
#[macro_export]
macro_rules! pop_scratch {
    () => { "
        // Pop scratch registers
        pop edx
        pop ecx
        pop eax
    " };
}

#[macro_export]
macro_rules! push_preserved {
    () => { "
        // Push preserved registers
        push ebx
        push edi
        push esi
        push ebp
    " };
}
#[macro_export]
macro_rules! pop_preserved {
    () => { "
        // Pop preserved registers
        pop ebp
        pop esi
        pop edi
        pop ebx
    " };
}

#[macro_export]
macro_rules! interrupt_stack {
    // XXX: Apparently we cannot use $expr and check for bool exhaustiveness, so we will have to
    // use idents directly instead.
    ($name:ident, is_paranoid: $is_paranoid:expr, |$stack:ident| $code:block) => {
        #[naked]
        pub unsafe extern "C" fn $name() {
            unsafe extern "C" fn inner($stack: &mut $crate::arch::x86::interrupt::InterruptStack) {
                let _guard;

                if !$is_paranoid {
                    // Deadlock safety: (non-paranoid) interrupts are not normally enabled in the
                    // kernel, except in kmain. However, no locks for context list nor even
                    // individual context locks, are ever meant to be acquired there.
                    _guard = $crate::ptrace::set_process_regs($stack);
                }

                // TODO: Force the declarations to specify unsafe?

                #[allow(unused_unsafe)]
                unsafe {
                    $code
                }
            }
            core::arch::asm!(concat!(
                // Backup all userspace registers to stack
                "push eax\n",
                push_scratch!(),
                push_preserved!(),

                // TODO: Map PTI
                // $crate::arch::x86::pti::map();

                // Call inner function with pointer to stack
                "
                push esp
                call {inner}
                pop esp
                ",

                // TODO: Unmap PTI
                // $crate::arch::x86::pti::unmap();

                // Restore all userspace registers
                pop_preserved!(),
                pop_scratch!(),

                "iretd\n",
            ),

            inner = sym inner,

            options(noreturn),

            );
        }
    };
    ($name:ident, |$stack:ident| $code:block) => { interrupt_stack!($name, is_paranoid: false, |$stack| $code); };
    ($name:ident, @paranoid, |$stack:ident| $code:block) => { interrupt_stack!($name, is_paranoid: true, |$stack| $code); }
}

#[macro_export]
macro_rules! interrupt {
    ($name:ident, || $code:block) => {
        #[naked]
        pub unsafe extern "C" fn $name() {
            unsafe extern "C" fn inner() {
                $code
            }

            core::arch::asm!(concat!(
                // Backup all userspace registers to stack
                "push eax\n",
                push_scratch!(),

                // TODO: Map PTI
                // $crate::arch::x86::pti::map();

                // Call inner function with pointer to stack
                "call {inner}\n",

                // TODO: Unmap PTI
                // $crate::arch::x86::pti::unmap();

                // Restore all userspace registers
                pop_scratch!(),

                "iretd\n",
            ),

            inner = sym inner,

            options(noreturn),
            );
        }
    };
}

#[macro_export]
macro_rules! interrupt_error {
    ($name:ident, |$stack:ident| $code:block) => {
        #[naked]
        pub unsafe extern "C" fn $name() {
            unsafe extern "C" fn inner($stack: &mut $crate::arch::x86::interrupt::handler::InterruptErrorStack) {
                let _guard;

                // Only set_ptrace_process_regs if this error occured from userspace. If this fault
                // originated from kernel mode, we have no idea what it might have locked (and
                // kernel mode faults are never meant to occur unless something is wrong, and will
                // not context switch anyway, rendering that statement useless in such a case
                // anyway).
                //
                // Check the privilege level of CS against ring 3.
                if $stack.inner.iret.cs & 0b11 == 0b11 {
                    _guard = $crate::ptrace::set_process_regs(&mut $stack.inner);
                }

                #[allow(unused_unsafe)]
                unsafe {
                    $code
                }
            }

            core::arch::asm!(concat!(
                // Move eax into code's place, put code in last instead (to be
                // compatible with InterruptStack)
                "xchg [esp], eax\n",

                // Push all userspace registers
                push_scratch!(),
                push_preserved!(),

                // Put code in, it's now in eax
                "push eax\n",

                // TODO: Map PTI
                // $crate::arch::x86::pti::map();

                // Call inner function with pointer to stack
                "
                push esp
                call {inner}
                pop esp
                ",

                // TODO: Unmap PTI
                // $crate::arch::x86::pti::unmap();

                // Pop code
                "add esp, 8\n",

                // Restore all userspace registers
                pop_preserved!(),
                pop_scratch!(),

                // The error code has already been popped, so use the regular macro.
                "iretd\n",
            ),

            inner = sym inner,

            options(noreturn));
        }
    };
}
