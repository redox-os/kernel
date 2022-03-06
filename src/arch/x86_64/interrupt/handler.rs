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

    // ----
    // The following will only be present if interrupt is raised from another
    // privilege ring. Otherwise, they are undefined values.
    // ----

    pub rsp: usize,
    pub ss: usize
}

impl IretRegisters {
    pub fn dump(&self) {
        println!("RFLAG: {:016x}", { self.rflags });
        println!("CS:    {:016x}", { self.cs });
        println!("RIP:   {:016x}", { self.rip });

        if self.cs & 0b11 != 0b00 {
            println!("RSP:   {:016x}", { self.rsp });
            println!("SS:    {:016x}", { self.ss });
        }
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
        // TODO: Which of these should be allowed to change?

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
        println!("CODE:  {:016x}", { self.code });
        self.inner.dump();
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

#[cfg(feature = "x86_fsgsbase")]
macro_rules! save_gsbase_paranoid {
    () => { "
        // Unused: {IA32_GS_BASE}
        rdgsbase rax
        push rax
    " }
}
#[cfg(feature = "x86_fsgsbase")]
macro_rules! restore_gsbase_paranoid {
    () => { "
        // Unused: {IA32_GS_BASE}
        pop rax
        wrgsbase rax
    " }
}
#[cfg(not(feature = "x86_fsgsbase"))]
macro_rules! save_gsbase_paranoid {
    () => { "
        mov ecx, {IA32_GS_BASE}
        rdmsr
        shl rdx, 32
        or rax, rdx

        push rax
    " }
}
#[cfg(not(feature = "x86_fsgsbase"))]
macro_rules! restore_gsbase_paranoid {
    () => { "
        pop rdx

        mov ecx, {IA32_GS_BASE}
        mov eax, edx
        shr rdx, 32
        wrmsr
    " }
}

#[cfg(feature = "x86_fsgsbase")]
macro_rules! set_gsbase_paranoid {
    () => { "
        // Unused: {IA32_GS_BASE}
        wrgsbase rdx
    " }
}
#[cfg(not(feature = "x86_fsgsbase"))]
macro_rules! set_gsbase_paranoid {
    () => { "
        mov ecx, {IA32_GS_BASE}
        mov eax, edx
        shr rdx, 32
        wrmsr
    " }
}

macro_rules! save_and_set_gsbase_paranoid {
    // For paranoid interrupt entries, we have to be extremely careful with how we use IA32_GS_BASE
    // and IA32_KERNEL_GS_BASE. If FSGSBASE is enabled, then we have no way to differentiate these
    // two, as paranoid interrupts (e.g. NMIs) can occur even in kernel mode. In fact, they can
    // even occur within another IRQ, so we cannot check the the privilege level via the stack.
    //
    // What we do instead, is using a special entry in the GDT, since we know that the GDT will
    // always be thread local, as it contains the TSS. This gives us more than 32 bits to work
    // with, which already is the largest x2APIC ID that an x86 CPU can handle. Luckily we can also
    // use the stack, even though there might be interrupts in between.
    //
    // TODO: Linux uses the Interrupt Stack Table to figure out which NMIs were nested. Perhaps
    // this could be done here, because if nested (sp > initial_sp), that means the NMI could not
    // have come from userspace. But then, knowing the initial sp would somehow have to involve
    // percpu, which brings us back to square one. But it might be useful if we would allow faults
    // in NMIs. If we do detect a nested interrupt, then we can perform the iretq procedure
    // ourselves, so that the newly nested NMI still blocks additional interrupts while still
    // returning to the previously (faulting) NMI. See https://lwn.net/Articles/484932/, although I
    // think the solution becomes a bit simpler when we cannot longer rely on GSBASE anymore.

    () => { concat!(
        save_gsbase_paranoid!(),

        // Allocate stack space for 8 bytes GDT base and 2 bytes size (ignored).
        "sub rsp, 16\n",
        // Set it to the GDT base.
        "sgdt [rsp + 6]\n",
        // Get the base pointer
        "
        mov rax, [rsp + 8]
        add rsp, 16
        ",
        // Load the lower 32 bits of that GDT entry.
        "mov edx, [rax + {gdt_cpu_id_offset}]\n",
        // Calculate the percpu offset.
        "
        mov rbx, {KERNEL_PERCPU_OFFSET}
        shl rdx, {KERNEL_PERCPU_SHIFT}
        add rdx, rbx
        ",
        // Set GSBASE to RAX accordingly
        set_gsbase_paranoid!(),
    ) }
}
macro_rules! nop {
    () => { "
        // Unused: {IA32_GS_BASE} {KERNEL_PERCPU_OFFSET} {KERNEL_PERCPU_SHIFT} {gdt_cpu_id_offset}
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

                // TODO: Force the declarations to specify unsafe?

                #[allow(unused_unsafe)]
                unsafe {
                    $code
                }
            }
            core::arch::asm!(concat!(
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
            KERNEL_PERCPU_SHIFT = const(crate::KERNEL_PERCPU_SHIFT),
            KERNEL_PERCPU_OFFSET = const(crate::KERNEL_PERCPU_OFFSET),

            gdt_cpu_id_offset = const(crate::gdt::GDT_CPU_ID_CONTAINER * core::mem::size_of::<crate::gdt::GdtEntry>()),

            options(noreturn),

            );
        }
    };
    ($name:ident, |$stack:ident| $code:block) => { interrupt_stack!($name, swapgs_iff_ring3_fast!, nop!, nop!, swapgs_iff_ring3_fast!, is_paranoid: false, |$stack| $code); };
    ($name:ident, @paranoid, |$stack:ident| $code:block) => { interrupt_stack!($name, nop!, save_and_set_gsbase_paranoid!, restore_gsbase_paranoid!, nop!, is_paranoid: true, |$stack| $code); }
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
    ($name:ident, |$stack:ident| $code:block) => {
        #[naked]
        pub unsafe extern "C" fn $name() {
            unsafe extern "C" fn inner($stack: &mut $crate::arch::x86_64::interrupt::handler::InterruptErrorStack) {
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
                "
                mov rdi, rsp
                call {inner}
                ",

                // TODO: Unmap PTI
                // $crate::arch::x86_64::pti::unmap();

                // Pop code
                "add rsp, 8\n",

                // Restore all userspace registers
                pop_preserved!(),
                pop_scratch!(),

                // The error code has already been popped, so use the regular macro.
                swapgs_iff_ring3_fast!(),
                "iretq\n",
            ),

            inner = sym inner,

            options(noreturn));
        }
    };
}
