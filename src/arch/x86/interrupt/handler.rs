use core::mem;

use crate::{memory::ArchIntCtx, syscall::IntRegisters};

use super::super::flags::*;

#[derive(Default)]
#[repr(C, packed)]
pub struct ScratchRegisters {
    pub edx: usize,
    pub ecx: usize,
    pub eax: usize,
}

impl ScratchRegisters {
    pub fn dump(&self) {
        println!("EAX:   {:08x}", { self.eax });
        println!("ECX:   {:08x}", { self.ecx });
        println!("EDX:   {:08x}", { self.edx });
    }
}

#[derive(Default)]
#[repr(C, packed)]
pub struct PreservedRegisters {
    pub ebp: usize,
    pub esi: usize,
    pub edi: usize,
    pub ebx: usize,
}

impl PreservedRegisters {
    pub fn dump(&self) {
        println!("EBX:   {:08x}", { self.ebx });
        println!("EDI:   {:08x}", { self.edi });
        println!("ESI:   {:08x}", { self.esi });
        println!("EBP:   {:08x}", { self.ebp });
    }
}

#[derive(Default)]
#[repr(C, packed)]
pub struct IretRegisters {
    pub eip: usize,
    pub cs: usize,
    pub eflags: usize,

    // ----
    // The following will only be present if interrupt is raised from another
    // privilege ring. Otherwise, they are undefined values.
    // ----
    pub esp: usize,
    pub ss: usize,
}

impl IretRegisters {
    pub fn dump(&self) {
        println!("EFLAG: {:08x}", { self.eflags });
        println!("CS:    {:08x}", { self.cs });
        println!("EIP:   {:08x}", { self.eip });

        if self.cs & 0b11 != 0b00 {
            println!("ESP:   {:08x}", { self.esp });
            println!("SS:    {:08x}", { self.ss });
        }
    }
}

#[derive(Default)]
#[repr(C, packed)]
pub struct InterruptStack {
    pub gs: usize,
    pub preserved: PreservedRegisters,
    pub scratch: ScratchRegisters,
    pub iret: IretRegisters,
}

impl InterruptStack {
    pub fn init(&mut self) {
        // Always enable interrupts!
        self.iret.eflags = x86::bits32::eflags::EFlags::FLAGS_IF.bits() as usize;
        self.iret.ss = (crate::gdt::GDT_USER_DATA << 3) | 3;
        self.iret.cs = (crate::gdt::GDT_USER_CODE << 3) | 3;
        self.gs = (crate::gdt::GDT_USER_GS << 3) | 3;
    }
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
    pub fn set_stack_pointer(&mut self, esp: usize) {
        self.iret.esp = esp;
    }
    pub fn instr_pointer(&self) -> usize {
        self.iret.eip
    }
    pub fn sig_archdep_reg(&self) -> usize {
        self.iret.eflags
    }
    pub fn set_instr_pointer(&mut self, eip: usize) {
        self.iret.eip = eip;
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

        // FIXME: The interrupt stack on which this is called, is always from userspace, but make
        // the API safer.
        self.iret.esp = all.esp;

        // OF, DF, 0, TF => D
        // SF, ZF, 0, AF => D
        // 0, PF, 1, CF => 5
        const ALLOWED_EFLAGS: usize = 0xDD5;

        // These should probably be restricted
        // self.iret.cs = all.cs;
        self.iret.eflags &= !ALLOWED_EFLAGS;
        self.iret.eflags |= all.eflags & ALLOWED_EFLAGS;
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
}

#[derive(Default)]
#[repr(C, packed)]
pub struct InterruptErrorStack {
    pub code: usize,
    pub inner: InterruptStack,
}

impl InterruptErrorStack {
    pub fn dump(&self) {
        println!("CODE:  {:08x}", { self.code });
        self.inner.dump();
    }
}

#[macro_export]
macro_rules! push_scratch {
    () => {
        "
        // Push scratch registers (minus eax)
        push ecx
        push edx
    "
    };
}
#[macro_export]
macro_rules! pop_scratch {
    () => {
        "
        // Pop scratch registers
        pop edx
        pop ecx
        pop eax
    "
    };
}

#[macro_export]
macro_rules! push_preserved {
    () => {
        "
        // Push preserved registers
        push ebx
        push edi
        push esi
        push ebp
    "
    };
}
#[macro_export]
macro_rules! pop_preserved {
    () => {
        "
        // Pop preserved registers
        pop ebp
        pop esi
        pop edi
        pop ebx
    "
    };
}

// Must always happen after push_scratch
macro_rules! enter_gs {
    () => {
        "
        // Enter kernel GS segment
        mov ecx, gs
        push ecx
        mov ecx, 0x18
        mov gs, ecx
    "
    };
}

// Must always happen before pop_scratch
macro_rules! exit_gs {
    () => {
        "
        // Exit kernel GS segment
        pop ecx
        mov gs, ecx
    "
    };
}

#[macro_export]
macro_rules! interrupt_stack {
    // XXX: Apparently we cannot use $expr and check for bool exhaustiveness, so we will have to
    // use idents directly instead.
    ($name:ident, |$stack:ident| $code:block) => {
        #[naked]
        pub unsafe extern "C" fn $name() {
            unsafe extern "fastcall" fn inner($stack: &mut $crate::arch::x86::interrupt::InterruptStack) {
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

                // Enter kernel TLS segment
                enter_gs!(),

                // TODO: Map PTI
                // $crate::arch::x86::pti::map();

                // Call inner function with pointer to stack
                "
                mov ecx, esp
                call {inner}
                ",

                // TODO: Unmap PTI
                // $crate::arch::x86::pti::unmap();

                // Exit kernel TLS segment
                exit_gs!(),

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
    ($name:ident, |$stack:ident| $code:block) => { interrupt_stack!($name, |$stack| $code); };
    ($name:ident, @paranoid, |$stack:ident| $code:block) => { interrupt_stack!($name, |$stack| $code); }
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

                // Enter kernel TLS segment
                enter_gs!(),

                // TODO: Map PTI
                // $crate::arch::x86::pti::map();

                // Call inner function with pointer to stack
                "call {inner}\n",

                // TODO: Unmap PTI
                // $crate::arch::x86::pti::unmap();

                // Exit kernel TLS segment
                exit_gs!(),

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

                // Enter kernel TLS segment
                enter_gs!(),

                // Put code in, it's now in eax
                "push eax\n",

                // TODO: Map PTI
                // $crate::arch::x86::pti::map();

                // Call inner function with pointer to stack
                "
                push esp
                call {inner}
                ",
                // add esp, 4

                // TODO: Unmap PTI (split "add esp, 8" into two "add esp, 4"s maybe?)
                // $crate::arch::x86::pti::unmap();

                // Pop previous esp and code
                "add esp, 8\n",

                // Exit kernel TLS segment
                exit_gs!(),

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
#[naked]
unsafe extern "C" fn usercopy_trampoline() {
    core::arch::asm!(
        "
        pop esi
        pop edi

        mov eax, 1
        ret
    ",
        options(noreturn)
    );
}

impl ArchIntCtx for InterruptStack {
    fn ip(&self) -> usize {
        self.iret.eip
    }
    fn recover_and_efault(&mut self) {
        // Unlike on x86_64, Protected Mode interrupts will not save/restore esp and ss unless
        // privilege rings changed, which they won't here as we are catching a kernel-induced page
        // fault.
        //
        // Thus, it is only possible to change scratch/preserved registers, and EIP. While it may
        // be feasible to set ECX to zero to stop the REP MOVSB, or increase EIP by 2 (REP MOVSB is
        // f3 a4, i.e. 2 bytes), this trampoline allows any memcpy implementation, that reasonably
        // pushes preserved registers to the stack.
        self.iret.eip = usercopy_trampoline as usize;
    }
}

#[naked]
pub unsafe extern "C" fn enter_usermode() {
    core::arch::asm!(
        concat!(
            // TODO: Unmap PTI
            // $crate::arch::x86::pti::unmap();

            // Exit kernel TLS segment
            exit_gs!(),
            // Restore all userspace registers
            pop_preserved!(),
            pop_scratch!(),
            "iretd\n",
        ),
        options(noreturn)
    )
}
