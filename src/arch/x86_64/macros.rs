use core::mem;
use syscall::data::IntRegisters;

/// Print to console
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ({
        use core::fmt::Write;
        let _ = write!($crate::arch::debug::Writer::new(), $($arg)*);
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
        println!("RBX:   {:>016X}", { self.rbx });
        println!("RBP:   {:>016X}", { self.rbp });
        println!("R12:   {:>016X}", { self.r12 });
        println!("R13:   {:>016X}", { self.r13 });
        println!("R14:   {:>016X}", { self.r14 });
        println!("R15:   {:>016X}", { self.r15 });
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
    // Will only be present if interrupt is raised from another
    // privilege ring
    pub rsp: usize,
    pub ss: usize
}

impl IretRegisters {
    pub fn dump(&self) {
        println!("RFLAG: {:>016X}", { self.rflags });
        println!("CS:    {:>016X}", { self.cs });
        println!("RIP:   {:>016X}", { self.rip });
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
    pub preserved: PreservedRegisters,
    pub scratch: ScratchRegisters,
    pub iret: IretRegisters,
}

impl InterruptStack {
    pub fn dump(&self) {
        self.iret.dump();
        self.scratch.dump();
        self.preserved.dump();
        println!("FS:    {:>016X}", { self.fs });
    }
    /// Saves all registers to a struct used by the proc:
    /// scheme to read/write registers.
    pub fn save(&self, all: &mut IntRegisters) {
        all.fs = self.fs;

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
            asm!("mov $0, cs" : "=r"(cs) ::: "intel");
        }

        if self.iret.cs & CPL_MASK == cs & CPL_MASK {
            // Privilege ring didn't change, so neither did the stack
            all.rsp = self as *const Self as usize // rsp after Self was pushed to the stack
                + mem::size_of::<Self>() // disregard Self
                - mem::size_of::<usize>() * 2; // well, almost: rsp and ss need to be excluded as they aren't present
            unsafe {
                asm!("mov $0, ss" : "=r"(all.ss) ::: "intel");
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
            self.iret.rflags |= 1 << 8;
        } else {
            self.iret.rflags &= !(1 << 8);
        }
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
            preserved_push!();
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
            preserved_pop!();
            scratch_pop!();
            iret!();
        }
    };
}

#[allow(dead_code)]
#[repr(packed)]
pub struct InterruptErrorStack {
    pub fs: usize,
    pub preserved: PreservedRegisters,
    pub scratch: ScratchRegisters,
    pub code: usize,
    pub iret: IretRegisters,
}

impl InterruptErrorStack {
    pub fn dump(&self) {
        self.iret.dump();
        println!("CODE:  {:>016X}", { self.code });
        self.scratch.dump();
        self.preserved.dump();
        println!("FS:    {:>016X}", { self.fs });
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
            preserved_push!();
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
            preserved_pop!();
            scratch_pop!();
            asm!("add rsp, 8" : : : : "intel", "volatile");
            iret!();
        }
    };
}
#[macro_export]
macro_rules! irqs(
    ( [ $( ($idt:expr, $number:literal, $name:ident) ,)* ], $submac:ident ) => {
        $(
            $submac!($idt, $number, $name);
        )*
    }
);

// define the irq numbers specified in the list above, as functions of the names
// allocatable_irq_NUM.
#[macro_export]
macro_rules! default_irqs(
    ($idt:expr, $submac:ident) => {
        irqs!([
            // interrupt vectors below 32 are exceptions
            // vectors 32..=47 are used for standard 8259 pic irqs.
            // 48 and 49 are used for the local APIC timer and error register, respectively.
            ($idt, 50, irq_50), ($idt, 51, irq_51), ($idt, 52, irq_52), ($idt, 53, irq_53), ($idt, 54, irq_54), ($idt, 55, irq_55), ($idt, 56, irq_56), ($idt, 57, irq_57), ($idt, 58, irq_58), ($idt, 59, irq_59),
            ($idt, 60, irq_60), ($idt, 61, irq_61), ($idt, 62, irq_62), ($idt, 63, irq_63),
            // 64..=67 used for IPI
            ($idt, 68, irq_68), ($idt, 69, irq_69),
            ($idt, 70, irq_70), ($idt, 71, irq_71), ($idt, 72, irq_72), ($idt, 73, irq_73), ($idt, 74, irq_74), ($idt, 75, irq_75), ($idt, 76, irq_76), ($idt, 77, irq_77), ($idt, 78, irq_78), ($idt, 79, irq_79),
            ($idt, 80, irq_80), ($idt, 81, irq_81), ($idt, 82, irq_82), ($idt, 83, irq_83), ($idt, 84, irq_84), ($idt, 85, irq_85), ($idt, 86, irq_86), ($idt, 87, irq_87), ($idt, 88, irq_88), ($idt, 89, irq_89),
            ($idt, 90, irq_90), ($idt, 91, irq_91), ($idt, 92, irq_92), ($idt, 93, irq_93), ($idt, 94, irq_94), ($idt, 95, irq_95), ($idt, 96, irq_96), ($idt, 97, irq_97), ($idt, 98, irq_98), ($idt, 99, irq_99),
            ($idt, 100, irq_100), ($idt, 101, irq_101), ($idt, 102, irq_102), ($idt, 103, irq_103), ($idt, 104, irq_104), ($idt, 105, irq_105), ($idt, 106, irq_106), ($idt, 107, irq_107), ($idt, 108, irq_108), ($idt, 109, irq_109),
            ($idt, 110, irq_110), ($idt, 111, irq_111), ($idt, 112, irq_112), ($idt, 113, irq_113), ($idt, 114, irq_114), ($idt, 115, irq_115), ($idt, 116, irq_116), ($idt, 117, irq_117), ($idt, 118, irq_118), ($idt, 119, irq_119),
            ($idt, 120, irq_120), ($idt, 121, irq_121), ($idt, 122, irq_122), ($idt, 123, irq_123), ($idt, 124, irq_124), ($idt, 125, irq_125), ($idt, 126, irq_126), ($idt, 127, irq_127),
            // 128 is used for software interrupts
            ($idt, 129, irq_129),
            ($idt, 130, irq_130), ($idt, 131, irq_131), ($idt, 132, irq_132), ($idt, 133, irq_133), ($idt, 134, irq_134), ($idt, 135, irq_135), ($idt, 136, irq_136), ($idt, 137, irq_137), ($idt, 138, irq_138), ($idt, 139, irq_139),
            ($idt, 140, irq_140), ($idt, 141, irq_141), ($idt, 142, irq_142), ($idt, 143, irq_143), ($idt, 144, irq_144), ($idt, 145, irq_145), ($idt, 146, irq_146), ($idt, 147, irq_147), ($idt, 148, irq_148), ($idt, 149, irq_149),
            ($idt, 150, irq_150), ($idt, 151, irq_151), ($idt, 152, irq_152), ($idt, 153, irq_153), ($idt, 154, irq_154), ($idt, 155, irq_155), ($idt, 156, irq_156), ($idt, 157, irq_157), ($idt, 158, irq_158), ($idt, 159, irq_159),
            ($idt, 160, irq_160), ($idt, 161, irq_161), ($idt, 162, irq_162), ($idt, 163, irq_163), ($idt, 164, irq_164), ($idt, 165, irq_165), ($idt, 166, irq_166), ($idt, 167, irq_167), ($idt, 168, irq_168), ($idt, 169, irq_169),
            ($idt, 170, irq_170), ($idt, 171, irq_171), ($idt, 172, irq_172), ($idt, 173, irq_173), ($idt, 174, irq_174), ($idt, 175, irq_175), ($idt, 176, irq_176), ($idt, 177, irq_177), ($idt, 178, irq_178), ($idt, 179, irq_179),
            ($idt, 180, irq_180), ($idt, 181, irq_181), ($idt, 182, irq_182), ($idt, 183, irq_183), ($idt, 184, irq_184), ($idt, 185, irq_185), ($idt, 186, irq_186), ($idt, 187, irq_187), ($idt, 188, irq_188), ($idt, 189, irq_189),
            ($idt, 190, irq_190), ($idt, 191, irq_191), ($idt, 192, irq_192), ($idt, 193, irq_193), ($idt, 194, irq_194), ($idt, 195, irq_195), ($idt, 196, irq_196), ($idt, 197, irq_197), ($idt, 198, irq_198), ($idt, 199, irq_199),
            ($idt, 200, irq_200), ($idt, 201, irq_201), ($idt, 202, irq_202), ($idt, 203, irq_203), ($idt, 204, irq_204), ($idt, 205, irq_205), ($idt, 206, irq_206), ($idt, 207, irq_207), ($idt, 208, irq_208), ($idt, 209, irq_209),
            ($idt, 210, irq_210), ($idt, 211, irq_211), ($idt, 212, irq_212), ($idt, 213, irq_213), ($idt, 214, irq_214), ($idt, 215, irq_215), ($idt, 216, irq_216), ($idt, 217, irq_217), ($idt, 218, irq_218), ($idt, 219, irq_219),
            ($idt, 220, irq_220), ($idt, 221, irq_221), ($idt, 222, irq_222), ($idt, 223, irq_223), ($idt, 224, irq_224), ($idt, 225, irq_225), ($idt, 226, irq_226), ($idt, 227, irq_227), ($idt, 228, irq_228), ($idt, 229, irq_229),
            ($idt, 230, irq_230), ($idt, 231, irq_231), ($idt, 232, irq_232), ($idt, 233, irq_233), ($idt, 234, irq_234), ($idt, 235, irq_235), ($idt, 236, irq_236), ($idt, 237, irq_237), ($idt, 238, irq_238), ($idt, 239, irq_239),
            ($idt, 240, irq_240), ($idt, 241, irq_241), ($idt, 242, irq_242), ($idt, 243, irq_243), ($idt, 244, irq_244), ($idt, 245, irq_245), ($idt, 246, irq_246), ($idt, 247, irq_247), ($idt, 248, irq_248), ($idt, 249, irq_249),
            ($idt, 250, irq_250), ($idt, 251, irq_251), ($idt, 252, irq_252), ($idt, 253, irq_253), ($idt, 254, irq_254), ($idt, 255, irq_255),
        ], $submac);
    }
);

macro_rules! define_default_irqs(
    () => {
        default_irqs!((), allocatable_irq);
    }
);
