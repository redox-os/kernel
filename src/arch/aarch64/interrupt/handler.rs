#[derive(Default)]
#[repr(packed)]
pub struct ScratchRegisters {
    pub x18: usize,
    pub x17: usize,
    pub x16: usize,
    pub x15: usize,
    pub x14: usize,
    pub x13: usize,
    pub x12: usize,
    pub x11: usize,
    pub x10: usize,
    pub x9: usize,
    pub x8: usize,
    pub x7: usize,
    pub x6: usize,
    pub x5: usize,
    pub x4: usize,
    pub x3: usize,
    pub x2: usize,
    pub x1: usize,
    pub x0: usize,
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
    pub x30: usize,
    pub x29: usize,
    pub x28: usize,
    pub x27: usize,
    pub x26: usize,
    pub x25: usize,
    pub x24: usize,
    pub x23: usize,
    pub x22: usize,
    pub x21: usize,
    pub x20: usize,
    pub x19: usize,
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
pub struct InterruptStack {
    pub elr_el1: usize,
    //TODO: should this push be removed?
    pub unknown: usize,
    pub tpidr_el0: usize,
    pub tpidrro_el0: usize,
    pub spsr_el1: usize,
    pub esr_el1: usize,
    pub sp_el0: usize,
    pub preserved: PreservedRegisters,
    pub scratch: ScratchRegisters,
    //TODO: eret registers
}

impl InterruptStack {
    pub fn dump(&self) {
        self.scratch.dump();
        self.preserved.dump();
        println!("SP_EL0:      {:>016X}", { self.sp_el0 });
        println!("ESR_EL1:     {:>016X}", { self.esr_el1 });
        println!("SPSR_EL1:    {:>016X}", { self.spsr_el1 });
        println!("TPIDRRO_EL0: {:>016X}", { self.tpidrro_el0 });
        println!("TPIDR_EL0:   {:>016X}", { self.tpidr_el0 });
        println!("UNKNOWN:     {:>016X}", { self.unknown });
        println!("ELR_EL1:     {:>016X}", { self.elr_el1 });
    }

    //TODO
    pub fn is_singlestep(&self) -> bool { false }
    pub fn set_singlestep(&mut self, singlestep: bool) {}
}
