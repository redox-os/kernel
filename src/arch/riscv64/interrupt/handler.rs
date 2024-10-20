use crate::{memory::ArchIntCtx, syscall::IntRegisters};
use core::mem::size_of;

#[derive(Default)]
#[repr(C)]
pub struct Registers {
    pub x1: usize,  // ra
    pub x2: usize,  // sp
    pub x3: usize,  // gp
    pub x4: usize,  // tp
    pub x5: usize,  // t0
    pub x6: usize,  // t1
    pub x7: usize,  // t2
    pub x8: usize,  // s0/fp
    pub x9: usize,  // s1
    pub x10: usize, // a0...
    pub x11: usize,
    pub x12: usize,
    pub x13: usize,
    pub x14: usize,
    pub x15: usize,
    pub x16: usize,
    pub x17: usize, // a7
    pub x18: usize, // s2...
    pub x19: usize,
    pub x20: usize,
    pub x21: usize,
    pub x22: usize,
    pub x23: usize,
    pub x24: usize,
    pub x25: usize,
    pub x26: usize,
    pub x27: usize, // s11
    pub x28: usize, // t3...
    pub x29: usize,
    pub x30: usize,
    pub x31: usize, // t6
}

impl Registers {
    pub fn dump(&self) {
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
        println!("X31:   {:>016X}", { self.x31 });
    }
}

#[derive(Default)]
#[repr(C)]
pub struct IretRegisters {
    pub sepc: usize,
}

impl IretRegisters {
    pub fn dump(&self) {
        println!("SEPC: {:>016X}", { self.sepc });
    }
}

// NOTE: Layout of this structure must be synced with assembly code in exception.rs
#[derive(Default)]
#[repr(C)]
pub struct InterruptStack {
    pub registers: Registers,
    pub iret: IretRegisters,
}

impl InterruptStack {
    pub fn init(&mut self) {
        const {
            assert!(32 * 8 == size_of::<InterruptStack>());
        }
    }
    pub fn set_stack_pointer(&mut self, sp: usize) {
        self.registers.x2 = sp;
    }
    pub fn stack_pointer(&self) -> usize {
        self.registers.x2
    }
    pub fn set_instr_pointer(&mut self, ip: usize) {
        self.iret.sepc = ip;
    }
    pub fn instr_pointer(&self) -> usize {
        self.iret.sepc
    }
    pub fn sig_archdep_reg(&self) -> usize {
        self.registers.x5
    }

    pub fn set_syscall_ret_reg(&mut self, ret: usize) {
        self.registers.x10 = ret;
    }

    pub fn dump(&self) {
        self.iret.dump();
        self.registers.dump();
    }

    /// Saves all registers to a struct used by the proc:
    /// scheme to read/write registers.
    pub fn save(&self, all: &mut IntRegisters) {
        all.pc = self.iret.sepc;
        all.x31 = self.registers.x31;
        all.x30 = self.registers.x30;
        all.x29 = self.registers.x29;
        all.x28 = self.registers.x28;
        all.x27 = self.registers.x27;
        all.x26 = self.registers.x26;
        all.x25 = self.registers.x25;
        all.x24 = self.registers.x24;
        all.x23 = self.registers.x23;
        all.x22 = self.registers.x22;
        all.x21 = self.registers.x21;
        all.x20 = self.registers.x20;
        all.x19 = self.registers.x19;
        all.x18 = self.registers.x18;
        all.x17 = self.registers.x17;
        all.x16 = self.registers.x16;
        all.x15 = self.registers.x15;
        all.x14 = self.registers.x14;
        all.x13 = self.registers.x13;
        all.x12 = self.registers.x12;
        all.x11 = self.registers.x11;
        all.x10 = self.registers.x10;
        all.x9 = self.registers.x9;
        all.x8 = self.registers.x8;
        all.x7 = self.registers.x7;
        all.x6 = self.registers.x6;
        all.x5 = self.registers.x5;
        all.x2 = self.registers.x2;
        all.x1 = self.registers.x1;
    }

    /// Loads all registers from a struct used by the proc:
    /// scheme to read/write registers.
    pub fn load(&mut self, all: &IntRegisters) {
        self.iret.sepc = all.pc;
        self.registers.x31 = all.x31;
        self.registers.x30 = all.x30;
        self.registers.x29 = all.x29;
        self.registers.x28 = all.x28;
        self.registers.x27 = all.x27;
        self.registers.x26 = all.x26;
        self.registers.x25 = all.x25;
        self.registers.x24 = all.x24;
        self.registers.x23 = all.x23;
        self.registers.x22 = all.x22;
        self.registers.x21 = all.x21;
        self.registers.x20 = all.x20;
        self.registers.x19 = all.x19;
        self.registers.x18 = all.x18;
        self.registers.x17 = all.x17;
        self.registers.x16 = all.x16;
        self.registers.x15 = all.x15;
        self.registers.x14 = all.x14;
        self.registers.x13 = all.x13;
        self.registers.x12 = all.x12;
        self.registers.x11 = all.x11;
        self.registers.x10 = all.x10;
        self.registers.x9 = all.x9;
        self.registers.x8 = all.x8;
        self.registers.x7 = all.x7;
        self.registers.x6 = all.x6;
        self.registers.x5 = all.x5;
        self.registers.x2 = all.x2;
        self.registers.x1 = all.x1;
    }

    //TODO
    pub fn is_singlestep(&self) -> bool {
        false
    }
    pub fn set_singlestep(&mut self, _singlestep: bool) {}
}

impl ArchIntCtx for InterruptStack {
    fn ip(&self) -> usize {
        self.iret.sepc
    }
    fn recover_and_efault(&mut self) {
        // Set the return value to nonzero to indicate usercopy failure (EFAULT), and emulate the
        // return instruction by setting the return pointer to the saved LR value.
        self.iret.sepc = self.registers.x1; // ra
        self.registers.x10 = 1; // a0
    }
}

/// Except for sp and tp
#[macro_export]
macro_rules! push_registers {
    () => {
        "
    addi    sp, sp, -32 * 8
    sd      x1, (0 * 8)(sp)
    // skip sp
    sd      x3, (2 * 8)(sp)
    // skip tp
    sd      x5, (4 * 8)(sp)
    sd      x6, (5 * 8)(sp)
    sd      x7, (6 * 8)(sp)
    sd      x8, (7 * 8)(sp)
    sd      x9, (8 * 8)(sp)
    sd      x10, (9 * 8)(sp)
    sd      x11, (10 * 8)(sp)
    sd      x12, (11 * 8)(sp)
    sd      x13, (12 * 8)(sp)
    sd      x14, (13 * 8)(sp)
    sd      x15, (14 * 8)(sp)
    sd      x16, (15 * 8)(sp)
    sd      x17, (16 * 8)(sp)
    sd      x18, (17 * 8)(sp)
    sd      x19, (18 * 8)(sp)
    sd      x20, (19 * 8)(sp)
    sd      x21, (20 * 8)(sp)
    sd      x22, (21 * 8)(sp)
    sd      x23, (22 * 8)(sp)
    sd      x24, (23 * 8)(sp)
    sd      x25, (24 * 8)(sp)
    sd      x26, (25 * 8)(sp)
    sd      x27, (26 * 8)(sp)
    sd      x28, (27 * 8)(sp)
    sd      x29, (28 * 8)(sp)
    sd      x30, (29 * 8)(sp)
    sd      x31, (30 * 8)(sp)

    csrr    t0, sepc
    sd      t0, (31 * 8)(sp)
    "
    }; // keep sepc value in t0 on exit
}

#[macro_export]
macro_rules! pop_registers {
    () => {
        "
    ld      t0, (31 * 8)(sp)
    csrw    sepc, t0

    ld      x1, (0 * 8)(sp)
    // skip sp, it'll be restored later
    ld      x3, (2 * 8)(sp)
    ld      x4, (3 * 8)(sp)
    ld      x5, (4 * 8)(sp)
    ld      x6, (5 * 8)(sp)
    ld      x7, (6 * 8)(sp)
    ld      x8, (7 * 8)(sp)
    ld      x9, (8 * 8)(sp)
    ld      x10, (9 * 8)(sp)
    ld      x11, (10 * 8)(sp)
    ld      x12, (11 * 8)(sp)
    ld      x13, (12 * 8)(sp)
    ld      x14, (13 * 8)(sp)
    ld      x15, (14 * 8)(sp)
    ld      x16, (15 * 8)(sp)
    ld      x17, (16 * 8)(sp)
    ld      x18, (17 * 8)(sp)
    ld      x19, (18 * 8)(sp)
    ld      x20, (19 * 8)(sp)
    ld      x21, (20 * 8)(sp)
    ld      x22, (21 * 8)(sp)
    ld      x23, (22 * 8)(sp)
    ld      x24, (23 * 8)(sp)
    ld      x25, (24 * 8)(sp)
    ld      x26, (25 * 8)(sp)
    ld      x27, (26 * 8)(sp)
    ld      x28, (27 * 8)(sp)
    ld      x29, (28 * 8)(sp)
    ld      x30, (29 * 8)(sp)
    ld      x31, (30 * 8)(sp)
    ld      sp, (1 * 8)(sp)
    "
    };
}

#[naked]
pub unsafe extern "C" fn enter_usermode() -> ! {
    core::arch::asm!(
        concat!(
            "jalr    s11\n",
            "li      t0, 1 << 8\n", // force U mode on sret
            "csrc    sstatus, t0\n",
            "li      t0, 0x6000\n", // set FS to dirty (enable FPU in U mode)
            "csrs    sstatus, t0\n",
            "addi    t0, sp, 32 * 8\n", // save S mode stack to percpu
            "sd      t0, 8(tp)\n",
            pop_registers!(),
            "sret\n",
        ),
        options(noreturn)
    )
}
