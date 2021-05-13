use crate::syscall::IntRegisters;

#[derive(Default)]
#[repr(packed)]
pub struct ScratchRegisters {
    pub ra: usize,
    pub t0: usize,
    pub t1: usize,
    pub t2: usize,
    pub t3: usize,
    pub t4: usize,
    pub t5: usize,
    pub t6: usize,
    pub a0: usize,
    pub a1: usize,
    pub a2: usize,
    pub a3: usize,
    pub a4: usize,
    pub a5: usize,
    pub a6: usize,
    pub a7: usize,
}

impl ScratchRegisters {
    pub fn dump(&self) {
        println!("RA:    {:>016X}", { self.ra });
        println!("T0:    {:>016X}", { self.t0 });
        println!("T1:    {:>016X}", { self.t1 });
        println!("T2:    {:>016X}", { self.t2 });
        println!("T3:    {:>016X}", { self.t3 });
        println!("T4:    {:>016X}", { self.t4 });
        println!("T5:    {:>016X}", { self.t5 });
        println!("T6:    {:>016X}", { self.t6 });
        println!("A0:    {:>016X}", { self.a0 });
        println!("A1:    {:>016X}", { self.a1 });
        println!("A2:    {:>016X}", { self.a2 });
        println!("A3:    {:>016X}", { self.a3 });
        println!("A4:    {:>016X}", { self.a4 });
        println!("A5:    {:>016X}", { self.a5 });
        println!("A6:    {:>016X}", { self.a6 });
        println!("A7:    {:>016X}", { self.a7 });
    }
}

#[derive(Default)]
#[repr(packed)]
pub struct PreservedRegisters {
    //TODO: SP, GP, and TP
    s0: usize,
    s1: usize,
    s2: usize,
    s3: usize,
    s4: usize,
    s5: usize,
    s6: usize,
    s7: usize,
    s8: usize,
    s9: usize,
    s10: usize,
    s11: usize,
}

impl PreservedRegisters {
    pub fn dump(&self) {
        println!("S0:    {:>016X}", { self.s0 });
        println!("S1:    {:>016X}", { self.s1 });
        println!("S2:    {:>016X}", { self.s2 });
        println!("S3:    {:>016X}", { self.s3 });
        println!("S4:    {:>016X}", { self.s4 });
        println!("S5:    {:>016X}", { self.s5 });
        println!("S6:    {:>016X}", { self.s6 });
        println!("S7:    {:>016X}", { self.s7 });
        println!("S8:    {:>016X}", { self.s8 });
        println!("S9:    {:>016X}", { self.s9 });
        println!("S10:   {:>016X}", { self.s10 });
        println!("S11:   {:>016X}", { self.s11 });
    }
}

#[derive(Default)]
#[repr(packed)]
pub struct IretRegisters {
    //TODO
}

impl IretRegisters {
    pub fn dump(&self) {}
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

    //TODO
    pub fn is_singlestep(&self) -> bool { false }
    pub fn set_singlestep(&mut self, singlestep: bool) {}
}
