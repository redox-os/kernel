use core::mem;

use crate::memory::ArchIntCtx;
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
        println!("RAX:   {:016x}", { self.rax });
        println!("RCX:   {:016x}", { self.rcx });
        println!("RDX:   {:016x}", { self.rdx });
        println!("RDI:   {:016x}", { self.rdi });
        println!("RSI:   {:016x}", { self.rsi });
        println!("R8:    {:016x}", { self.r8 });
        println!("R9:    {:016x}", { self.r9 });
        println!("R10:   {:016x}", { self.r10 });
        println!("R11:   {:016x}", { self.r11 });
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
        println!("RBX:   {:016x}", { self.rbx });
        println!("RBP:   {:016x}", { self.rbp });
        println!("R12:   {:016x}", { self.r12 });
        println!("R13:   {:016x}", { self.r13 });
        println!("R14:   {:016x}", { self.r14 });
        println!("R15:   {:016x}", { self.r15 });
    }
}

#[derive(Default)]
#[repr(packed)]
pub struct IretRegisters {
    pub rip: usize,
    pub cs: usize,
    pub rflags: usize,

    // In x86 Protected Mode, i.e. 32-bit kernels, the following two registers are conditionally
    // pushed if the privilege ring changes. In x86 Long Mode however, i.e. 64-bit kernels, they
    // are unconditionally pushed, mostly due to stack alignment requirements.

    pub rsp: usize,
    pub ss: usize,
}

impl IretRegisters {
    pub fn dump(&self) {
        println!("RFLAG: {:016x}", { self.rflags });
        println!("CS:    {:016x}", { self.cs });
        println!("RIP:   {:016x}", { self.rip });

        println!("RSP:   {:016x}", { self.rsp });
        println!("SS:    {:016x}", { self.ss });

        unsafe {
            let fsbase = x86::msr::rdmsr(x86::msr::IA32_FS_BASE);
            let gsbase = x86::msr::rdmsr(x86::msr::IA32_KERNEL_GSBASE);
            let kgsbase = x86::msr::rdmsr(x86::msr::IA32_GS_BASE);
            println!("FSBASE  {:016x}\nGSBASE  {:016x}\nKGSBASE {:016x}", fsbase, gsbase, kgsbase);
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
            core::arch::asm!("mov {}, cs", out(reg) cs);
        }

        if self.iret.cs & CPL_MASK == cs & CPL_MASK {
            // Privilege ring didn't change, so neither did the stack
            all.rsp = self as *const Self as usize // rsp after Self was pushed to the stack
                + mem::size_of::<Self>() // disregard Self
                - mem::size_of::<usize>() * 2; // well, almost: rsp and ss need to be excluded as they aren't present
            unsafe {
                core::arch::asm!("mov {}, ss", out(reg) all.ss);
            }
        } else {
            all.rsp = self.iret.rsp;
            all.ss = self.iret.ss;
        }
    }
    /// Loads all registers from a struct used by the proc:
    /// scheme to read/write registers.
    pub fn load(&mut self, all: &IntRegisters) {
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
        self.iret.rsp = all.rsp;

        // CS and SS are immutable

        // TODO: RFLAGS should be restricted before being changeable
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
    // TODO: Spectre V1: LFENCE?
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
    // TODO: Spectre V1: LFENCE?
    () => { "
        test QWORD PTR [rsp + 16], 0x3
        jz 1f
        swapgs
        1:
    " };
}

macro_rules! conditional_swapgs_paranoid {
    // For regular interrupt handlers and the syscall handler, managing IA32_GS_BASE and
    // IA32_KERNEL_GS_BASE (the "GSBASE registers") is more or less trivial when using the SWAPGS
    // instruction.
    //
    // The syscall handler simply runs SWAPGS, as syscalls can only originate from usermode,
    // whereas interrupt handlers conditionally SWAPGS unless the interrupt was triggered from
    // kernel mode, in which case the "swap state" is already valid, and there is no need to
    // SWAPGS.
    //
    // Handling GSBASE correctly for paranoid interrupts however, is not as simple. NMIs can occur
    // between the check of whether an interrupt came from usermode, and the actual SWAPGS
    // instruction. #DB can also be triggered inside of a kernel interrupt handler, due to
    // breakpoints, even though setting up such breakpoints in the first place, is not yet
    // supported by the kernel.
    //
    // Luckily, the GDT always resides in the PCR (at least after init_paging, but there are no
    // interrupt handlers set up before that), allowing GSBASE to be calculated relatively cheaply.
    // Out of the two GSBASE registers, at least one must be *the* kernel GSBASE, allowing for a
    // simple conditional SWAPGS.
    //
    // (An alternative to conditionally executing SWAPGS, would be to save and restore GSBASE via
    // e.g. the stack. That would nonetheless require saving and restoring both GSBASE registers,
    // if the interrupt handler should be allowed to context switch, which the current #DB handler
    // may do.)
    //
    // TODO: Handle nested NMIs like Linux does (https://lwn.net/Articles/484932/)?.

    () => { concat!(
        // Put the GDT base pointer in RDI.
        "
        sub rsp, 16
        sgdt [rsp + 6]
        mov rdi, [rsp + 8]
        add rsp, 16
        ",
        // Calculate the PCR address by subtracting the offset of the GDT in the PCR struct.
        "sub rdi, {PCR_GDT_OFFSET};",

        // Read the current IA32_GS_BASE value into RDX.
        alternative!(
            feature: "fsgsbase",
            then: ["rdgsbase rdx"],
            default: ["
                mov ecx, {IA32_GS_BASE}
                rdmsr
                shl rdx, 32
                or rdx, rax
            "]
        ),

        // If they were not equal, the PCR address must instead be in IA32_KERNEL_GS_BASE,
        // requiring a SWAPGS. GSBASE needs to be swapped back, so store the same flag in RBX.

        // TODO: Spectre V1: LFENCE?
        "
        cmp rdx, rdi
        sete bl
        je 1f
        swapgs
        1:
        ",
    ) }
}
macro_rules! conditional_swapgs_back_paranoid {
    () => { "
        test bl, bl
        jnz 1f
        swapgs
        1:
    " }
}
macro_rules! nop {
    () => { "
        // Unused: {IA32_GS_BASE} {PCR_GDT_OFFSET}
        " }
}

#[macro_export]
macro_rules! interrupt_stack {
    // XXX: Apparently we cannot use $expr and check for bool exhaustiveness, so we will have to
    // use idents directly instead.
    ($name:ident, $save1:ident!, $save2:ident!, $rstor2:ident!, $rstor1:ident!, is_paranoid: $is_paranoid:expr, |$stack:ident| $code:block) => {
        #[naked]
        pub unsafe extern "C" fn $name() {
            unsafe extern "C" fn inner($stack: &mut $crate::arch::x86_64::interrupt::InterruptStack) {
                let _guard;

                if !$is_paranoid {
                    // Deadlock safety: (non-paranoid) interrupts are not normally enabled in the
                    // kernel, except in kmain. However, no locks for context list nor even
                    // individual context locks, are ever meant to be acquired there.
                    _guard = $crate::ptrace::set_process_regs($stack);
                }

                // TODO: Force the declarations to specify unsafe? For example, accessing a global
                // core::cell::Cell is safe when running at the "bottom level" (interrupt from
                // userspace or prior to entering userspace), but UB if simultaneously accessed
                // from an interrupt.

                #[allow(unused_unsafe)]
                unsafe {
                    $code
                }
            }
            core::arch::asm!(concat!(
                // Clear direction flag, required by ABI when running any Rust code in the kernel.
                "cld;",

                // Backup all userspace registers to stack
                $save1!(),
                "push rax\n",
                push_scratch!(),
                push_preserved!(),

                $save2!(),

                // TODO: Map PTI
                // $crate::arch::x86_64::pti::map();

                // Call inner function with pointer to stack
                "
                mov rdi, rsp
                call {inner}
                ",

                // TODO: Unmap PTI
                // $crate::arch::x86_64::pti::unmap();

                $rstor2!(),

                // Restore all userspace registers
                pop_preserved!(),
                pop_scratch!(),

                $rstor1!(),
                "iretq\n",
            ),

            inner = sym inner,
            IA32_GS_BASE = const(x86::msr::IA32_GS_BASE),

            PCR_GDT_OFFSET = const(memoffset::offset_of!(crate::gdt::ProcessorControlRegion, gdt)),

            options(noreturn),

            );
        }
    };
    ($name:ident, |$stack:ident| $code:block) => { interrupt_stack!($name, swapgs_iff_ring3_fast!, nop!, nop!, swapgs_iff_ring3_fast!, is_paranoid: false, |$stack| $code); };
    ($name:ident, @paranoid, |$stack:ident| $code:block) => { interrupt_stack!($name, nop!, conditional_swapgs_paranoid!, conditional_swapgs_back_paranoid!, nop!, is_paranoid: true, |$stack| $code); }
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
                // Clear direction flag, required by ABI when running any Rust code in the kernel.
                "cld;",

                // Backup all userspace registers to stack
                swapgs_iff_ring3_fast!(),
                "push rax\n",
                push_scratch!(),

                // TODO: Map PTI
                // $crate::arch::x86_64::pti::map();

                // Call inner function with pointer to stack
                "call {inner}\n",

                // TODO: Unmap PTI
                // $crate::arch::x86_64::pti::unmap();

                // Restore all userspace registers
                pop_scratch!(),

                swapgs_iff_ring3_fast!(),
                "iretq\n",
            ),

            inner = sym inner,

            options(noreturn),
            );
        }
    };
}

#[macro_export]
macro_rules! interrupt_error {
    ($name:ident, |$stack:ident, $error_code:ident| $code:block) => {
        #[naked]
        pub unsafe extern "C" fn $name() {
            unsafe extern "C" fn inner($stack: &mut $crate::arch::x86_64::interrupt::handler::InterruptStack, $error_code: usize) {
                let _guard;

                // Only set_ptrace_process_regs if this error occured from userspace. If this fault
                // originated from kernel mode, we have no idea what it might have locked (and
                // kernel mode faults are never meant to occur unless something is wrong, and will
                // not context switch anyway, rendering that statement useless in such a case
                // anyway).
                //
                // Check the privilege level of CS against ring 3.
                if $stack.iret.cs & 0b11 == 0b11 {
                    _guard = $crate::ptrace::set_process_regs($stack);
                }

                #[allow(unused_unsafe)]
                unsafe {
                    $code
                }
            }

            core::arch::asm!(concat!(
                // Clear direction flag, required by ABI when running any Rust code in the kernel.
                "cld;",

                swapgs_iff_ring3_fast_errorcode!(),

                // Don't push RAX yet, as the error code is already stored in RAX's position.

                // Push all userspace registers
                push_scratch!(),
                push_preserved!(),

                // Now that we have a couple of usable registers, put the error code in the second
                // argument register for the inner function, and save RAX where it would normally
                // be.
                "mov rsi, [rsp + {rax_offset}];",
                "mov [rsp + {rax_offset}], rax;",

                // TODO: Map PTI
                // $crate::arch::x86_64::pti::map();

                // Call inner function with pointer to stack, and error code.
                "mov rdi, rsp;",
                "call {inner};",

                // TODO: Unmap PTI
                // $crate::arch::x86_64::pti::unmap();

                // Restore all userspace registers
                pop_preserved!(),
                pop_scratch!(),

                // The error code has already been popped, so use the regular macro.
                swapgs_iff_ring3_fast!(),
                "iretq;",
            ),

            inner = sym inner,
            rax_offset = const(::core::mem::size_of::<$crate::interrupt::handler::PreservedRegisters>() + ::core::mem::size_of::<$crate::interrupt::handler::ScratchRegisters>() - 8),

            options(noreturn));
        }
    };
}

impl ArchIntCtx for InterruptStack {
    fn ip(&self) -> usize {
        self.iret.rip
    }
    fn recover_and_efault(&mut self) {
        // We were inside a usercopy function that failed. This is handled by setting rax to a
        // nonzero value, and emulating the ret instruction.
        self.scratch.rax = 1;
        let ret_addr = unsafe { (self.iret.rsp as *const usize).read() };
        self.iret.rsp += 8;
        self.iret.rip = ret_addr;
        self.iret.rflags &= !(1 << 18);
    }
}
