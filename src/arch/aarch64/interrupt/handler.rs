use crate::syscall::IntRegisters;

#[derive(Default)]
#[repr(packed)]
pub struct ScratchRegisters {
    pub x0: usize,
    pub x1: usize,
    pub x2: usize,
    pub x3: usize,
    pub x4: usize,
    pub x5: usize,
    pub x6: usize,
    pub x7: usize,
    pub x8: usize,
    pub x9: usize,
    pub x10: usize,
    pub x11: usize,
    pub x12: usize,
    pub x13: usize,
    pub x14: usize,
    pub x15: usize,
    pub x16: usize,
    pub x17: usize,
    pub x18: usize,
    pub padding: usize,
}

impl ScratchRegisters {
    pub fn dump(&self) {
        println!("X0:    {:>016X}", { self.x0 });
        println!("X1:    {:>016X}", { self.x1 });
        println!("X2:    {:>016X}", { self.x2 });
        println!("X3:    {:>016X}", { self.x3 });
        println!("X4:    {:>016X}", { self.x4 });
        println!("X5:    {:>016X}", { self.x5 });
        println!("X6:    {:>016X}", { self.x6 });
        println!("X7:    {:>016X}", { self.x7 });
        println!("X8:    {:>016X}", { self.x8 });
        println!("X9:    {:>016X}", { self.x9 });
        println!("X10:   {:>016X}", { self.x10 });
        println!("X11:   {:>016X}", { self.x11 });
        println!("X12:   {:>016X}", { self.x12 });
        println!("X13:   {:>016X}", { self.x13 });
        println!("X14:   {:>016X}", { self.x14 });
        println!("X15:   {:>016X}", { self.x15 });
        println!("X16:   {:>016X}", { self.x16 });
        println!("X17:   {:>016X}", { self.x17 });
        println!("X18:   {:>016X}", { self.x18 });
    }
}

#[derive(Default)]
#[repr(packed)]
pub struct PreservedRegisters {
    //TODO: is X30 a preserved register?
    pub x19: usize,
    pub x20: usize,
    pub x21: usize,
    pub x22: usize,
    pub x23: usize,
    pub x24: usize,
    pub x25: usize,
    pub x26: usize,
    pub x27: usize,
    pub x28: usize,
    pub x29: usize,
    pub x30: usize,
}

impl PreservedRegisters {
    pub fn dump(&self) {
        println!("X19:   {:>016X}", { self.x19 });
        println!("X20:   {:>016X}", { self.x20 });
        println!("X21:   {:>016X}", { self.x21 });
        println!("X22:   {:>016X}", { self.x22 });
        println!("X23:   {:>016X}", { self.x23 });
        println!("X24:   {:>016X}", { self.x24 });
        println!("X25:   {:>016X}", { self.x25 });
        println!("X26:   {:>016X}", { self.x26 });
        println!("X27:   {:>016X}", { self.x27 });
        println!("X28:   {:>016X}", { self.x28 });
        println!("X29:   {:>016X}", { self.x29 });
        println!("X30:   {:>016X}", { self.x30 });
    }
}

#[derive(Default)]
#[repr(packed)]
pub struct IretRegisters {
                            // occurred
                            // The exception vector disambiguates at which EL the interrupt
    pub sp_el0: usize,      // Shouldn't be used if interrupt occurred at EL1
    pub esr_el1: usize,
    pub spsr_el1: usize,
    pub tpidrro_el0: usize,
    pub tpidr_el0: usize,
    pub elr_el1: usize,
}

impl IretRegisters {
    pub fn dump(&self) {
        println!("ELR_EL1: {:>016X}", { self.elr_el1 });
        println!("TPIDR_EL0: {:>016X}", { self.tpidr_el0 });
        println!("TPIDRRO_EL0: {:>016X}", { self.tpidrro_el0 });
        println!("SPSR_EL1: {:>016X}", { self.spsr_el1 });
        println!("ESR_EL1: {:>016X}", { self.esr_el1 });
        println!("SP_EL0: {:>016X}", { self.sp_el0 });
    }
}

#[derive(Default)]
#[repr(packed)]
pub struct InterruptStack {
    pub iret: IretRegisters,
    pub scratch: ScratchRegisters,
    pub preserved: PreservedRegisters,
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
        all.elr_el1 = self.iret.elr_el1;
        all.tpidr_el0 = self.iret.tpidr_el0;
        all.tpidrro_el0 = self.iret.tpidrro_el0;
        all.spsr_el1 = self.iret.spsr_el1;
        all.esr_el1 = self.iret.esr_el1;
        all.sp_el0 = self.iret.sp_el0;
        all.padding = 0;
        all.x30 = self.preserved.x30;
        all.x29 = self.preserved.x29;
        all.x28 = self.preserved.x28;
        all.x27 = self.preserved.x27;
        all.x26 = self.preserved.x26;
        all.x25 = self.preserved.x25;
        all.x24 = self.preserved.x24;
        all.x23 = self.preserved.x23;
        all.x22 = self.preserved.x22;
        all.x21 = self.preserved.x21;
        all.x20 = self.preserved.x20;
        all.x19 = self.preserved.x19;
        all.x18 = self.scratch.x18;
        all.x17 = self.scratch.x17;
        all.x16 = self.scratch.x16;
        all.x15 = self.scratch.x15;
        all.x14 = self.scratch.x14;
        all.x13 = self.scratch.x13;
        all.x12 = self.scratch.x12;
        all.x11 = self.scratch.x11;
        all.x10 = self.scratch.x10;
        all.x9 = self.scratch.x9;
        all.x8 = self.scratch.x8;
        all.x7 = self.scratch.x7;
        all.x6 = self.scratch.x6;
        all.x5 = self.scratch.x5;
        all.x4 = self.scratch.x4;
        all.x3 = self.scratch.x3;
        all.x2 = self.scratch.x2;
        all.x1 = self.scratch.x1;
        all.x0 = self.scratch.x0;
    }

    //TODO
    pub fn is_singlestep(&self) -> bool { false }
    pub fn set_singlestep(&mut self, singlestep: bool) {}
}

#[macro_export]
macro_rules! aarch64_asm {
    ($($strings:expr,)+) => {
        global_asm!(concat!(
            $($strings),+,
        ));
    };
}

#[macro_export]
macro_rules! function {
    ($name:ident => { $($body:expr,)+ }) => {
        aarch64_asm!(
            ".global ", stringify!($name), "\n",
            ".type ", stringify!($name), ", @function\n",
            ".section .text.", stringify!($name), ", \"ax\", @progbits\n",
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
        stp     x18, x18, [sp, #-16]!
        stp     x16, x17, [sp, #-16]!
        stp     x14, x15, [sp, #-16]!
        stp     x12, x13, [sp, #-16]!
        stp     x10, x11, [sp, #-16]!
        stp     x8, x9, [sp, #-16]!
        stp     x6, x7, [sp, #-16]!
        stp     x4, x5, [sp, #-16]!
        stp     x2, x3, [sp, #-16]!
        stp     x0, x1, [sp, #-16]!
    " };
}

#[macro_export]
macro_rules! pop_scratch {
    () => { "
        // Pop scratch registers
        ldp     x0, x1, [sp], #16
        ldp     x2, x3, [sp], #16
        ldp     x4, x5, [sp], #16
        ldp     x6, x7, [sp], #16
        ldp     x8, x9, [sp], #16
        ldp     x10, x11, [sp], #16
        ldp     x12, x13, [sp], #16
        ldp     x14, x15, [sp], #16
        ldp     x16, x17, [sp], #16
        ldp     x18, x18, [sp], #16
    " };
}

#[macro_export]
macro_rules! push_preserved {
    () => { "
        // Push preserved registers
        stp     x29, x30, [sp, #-16]!
        stp     x27, x28, [sp, #-16]!
        stp     x25, x26, [sp, #-16]!
        stp     x23, x24, [sp, #-16]!
        stp     x21, x22, [sp, #-16]!
        stp     x19, x20, [sp, #-16]!
    " };
}

#[macro_export]
macro_rules! pop_preserved {
    () => { "
        // Pop preserved registers
        ldp     x19, x20, [sp], #16
        ldp     x21, x22, [sp], #16
        ldp     x23, x24, [sp], #16
        ldp     x25, x26, [sp], #16
        ldp     x27, x28, [sp], #16
        ldp     x29, x30, [sp], #16
    " };
}

#[macro_export]
macro_rules! push_special {
    () => { "
        mrs     x14, tpidr_el0
        mrs     x15, elr_el1
        stp     x14, x15, [sp, #-16]!

        mrs     x14, spsr_el1
        mrs     x15, tpidrro_el0
        stp     x14, x15, [sp, #-16]!

        mrs     x14, sp_el0
        mrs     x15, esr_el1
        stp     x14, x15, [sp, #-16]!
    " };
}

#[macro_export]
macro_rules! pop_special {
    () => { "
        ldp     x14, x15, [sp], 16
        msr     esr_el1, x15
        msr     sp_el0, x14

        ldp     x14, x15, [sp], 16
        msr     tpidrro_el0, x15
        msr     spsr_el1, x14

        ldp     x14, x15, [sp], 16
        msr     elr_el1, x15
        msr     tpidr_el0, x14
    " };
}

#[macro_export]
macro_rules! exception_stack {
    ($name:ident, |$stack:ident| $code:block) => {
        paste::item! {
            #[no_mangle]
            unsafe extern "C" fn [<__exception_ $name>](stack: *mut $crate::arch::aarch64::interrupt::InterruptStack) {
                // This inner function is needed because macros are buggy:
                // https://github.com/dtolnay/paste/issues/7
                #[inline(always)]
                unsafe fn inner($stack: &mut $crate::arch::aarch64::interrupt::InterruptStack) {
                    $code
                }
                inner(&mut *stack);
            }

            function!($name => {
                // Backup all userspace registers to stack
                push_preserved!(),
                push_scratch!(),
                push_special!(),

                // Call inner function with pointer to stack
                "mov x29, sp\n",
                "mov x0, sp\n",
                "bl __exception_", stringify!($name), "\n",

                // Restore all userspace registers
                pop_special!(),
                pop_scratch!(),
                pop_preserved!(),

                "eret\n",
            });
        }
    };
}
