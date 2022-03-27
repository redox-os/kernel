use core::mem;
use core::sync::atomic::AtomicBool;

use crate::syscall::FloatRegisters;

use memoffset::offset_of;

/// This must be used by the kernel to ensure that context switches are done atomically
/// Compare and exchange this to true when beginning a context switch on any CPU
/// The `Context::switch_to` function will set it back to false, allowing other CPU's to switch
/// This must be done, as no locks can be held on the stack during switch
pub static CONTEXT_SWITCH_LOCK: AtomicBool = AtomicBool::new(false);

const ST_RESERVED: u128 = 0xFFFF_FFFF_FFFF_0000_0000_0000_0000_0000;

#[derive(Clone, Debug)]
#[repr(C)]
pub struct Context {
    /// FX location
    fx: usize,
    /// Page table pointer
    cr3: usize,
    /// RFLAGS register
    rflags: usize,
    /// RBX register
    rbx: usize,
    /// R12 register
    r12: usize,
    /// R13 register
    r13: usize,
    /// R14 register
    r14: usize,
    /// R15 register
    r15: usize,
    /// Base pointer
    rbp: usize,
    /// Stack pointer
    rsp: usize,
    /// FSBASE.
    ///
    /// NOTE: Same fsgsbase behavior as with gsbase.
    pub(crate) fsbase: usize,
    /// GSBASE.
    ///
    /// NOTE: Without fsgsbase, this register will strictly be equal to the register value when
    /// running. With fsgsbase, this is neither saved nor restored upon every syscall (there is no
    /// need to!), and thus it must be re-read from the register before copying this struct.
    pub(crate) gsbase: usize,
    /// FX valid?
    loadable: AbiCompatBool,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AbiCompatBool {
    False,
    True,
}

impl Context {
    pub fn new() -> Context {
        Context {
            loadable: AbiCompatBool::False,
            fx: 0,
            cr3: 0,
            rflags: 0,
            rbx: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rbp: 0,
            rsp: 0,
            fsbase: 0,
            gsbase: 0,
        }
    }

    pub fn get_page_utable(&self) -> usize {
        self.cr3
    }

    pub fn get_fx_regs(&self) -> Option<FloatRegisters> {
        if self.loadable == AbiCompatBool::False {
            return None;
        }
        let mut regs = unsafe { *(self.fx as *const FloatRegisters) };
        regs._reserved = 0;
        let mut new_st = regs.st_space;
        for st in &mut new_st {
            // Only allow access to the 80 lowest bits
            *st &= !ST_RESERVED;
        }
        regs.st_space = new_st;
        Some(regs)
    }

    pub fn set_fx_regs(&mut self, mut new: FloatRegisters) -> bool {
        if self.loadable == AbiCompatBool::False {
            return false;
        }

        {
            let old = unsafe { &*(self.fx as *const FloatRegisters) };
            new._reserved = old._reserved;
            let old_st = new.st_space;
            let mut new_st = new.st_space;
            for (new_st, old_st) in new_st.iter_mut().zip(&old_st) {
                *new_st &= !ST_RESERVED;
                *new_st |= old_st & ST_RESERVED;
            }
            new.st_space = new_st;

            // Make sure we don't use `old` from now on
        }

        unsafe {
            *(self.fx as *mut FloatRegisters) = new;
        }
        true
    }

    pub fn set_fx(&mut self, address: usize) {
        self.fx = address;
    }

    pub fn set_page_utable(&mut self, address: usize) {
        self.cr3 = address;
    }

    pub fn set_stack(&mut self, address: usize) {
        self.rsp = address;
    }

    pub unsafe fn signal_stack(&mut self, handler: extern fn(usize), sig: u8) {
        self.push_stack(sig as usize);
        self.push_stack(handler as usize);
        self.push_stack(signal_handler_wrapper as usize);
    }

    pub unsafe fn push_stack(&mut self, value: usize) {
        self.rsp -= mem::size_of::<usize>();
        *(self.rsp as *mut usize) = value;
    }

    pub unsafe fn pop_stack(&mut self) -> usize {
        let value = *(self.rsp as *const usize);
        self.rsp += mem::size_of::<usize>();
        value
    }
}

macro_rules! load_msr(
    ($name:literal, $offset:literal) => {
        concat!("
            mov ecx, {", $name, "}
            mov rdx, [rsi + {", $offset, "}]
            mov eax, edx
            shr rdx, 32

            // MSR <= EDX:EAX
            wrmsr
        ")
    }
);

// NOTE: RAX is a scratch register and can be set to whatever. There is also no return
// value in switch_to, to it will also never be read. The same goes for RDX, and RCX.
// TODO: Use runtime code patching (perhaps in the bootloader) by pushing alternative code
// sequences into a specialized section, with some macro resembling Linux's `.ALTERNATIVE`.
#[cfg(feature = "x86_fsgsbase")]
macro_rules! switch_fsgsbase(
    () => {
        "
            // placeholder: {MSR_FSBASE} {MSR_KERNELGSBASE}

            rdfsbase rax
            mov [rdi + {off_fsbase}], rax
            mov rax, [rsi + {off_fsbase}]
            wrfsbase rax

            swapgs
            rdgsbase rax
            mov [rdi + {off_gsbase}], rax
            mov rax, [rsi + {off_gsbase}]
            wrgsbase rax
            swapgs
        "
    }
);

#[cfg(not(feature = "x86_fsgsbase"))]
macro_rules! switch_fsgsbase(
    () => {
        concat!(
            load_msr!("MSR_FSBASE", "off_fsbase"),
            load_msr!("MSR_KERNELGSBASE", "off_gsbase"),
        )
    }
);


/// Switch to the next context by restoring its stack and registers
/// Check disassembly!
#[naked]
pub unsafe extern "C" fn switch_to(_prev: &mut Context, _next: &mut Context) {
    use Context as Cx;

    core::arch::asm!(
        // As a quick reminder for those who are unfamiliar with the System V ABI (extern "C"):
        //
        // - the current parameters are passed in the registers `rdi`, `rsi`,
        // - we can modify scratch registers, e.g. rax
        // - we cannot change callee-preserved registers arbitrarily, e.g. rbx, which is why we
        //   store them here in the first place.
        concat!("
        // load `prev.fx`
        mov rax, [rdi + {off_fx}]

        // save processor SSE/FPU/AVX state in `prev.fx` pointee
        fxsave64 [rax]

        // set `prev.loadable` to true
        mov BYTE PTR [rdi + {off_loadable}], {true}
        // compare `next.loadable` with true
        cmp BYTE PTR [rsi + {off_loadable}], {true}
        je 3f

        fninit
        jmp 3f

2:
        mov rax, [rsi + {off_fx}]
        fxrstor64 [rax]

3:
        // Save the current CR3, and load the next CR3 if not identical
        mov rcx, cr3
        mov [rdi + {off_cr3}], rcx
        mov rax, [rsi + {off_cr3}]
        cmp rax, rcx

        je 4f
        mov cr3, rax

4:
        // Save old registers, and load new ones
        mov [rdi + {off_rbx}], rbx
        mov rbx, [rsi + {off_rbx}]

        mov [rdi + {off_r12}], r12
        mov r12, [rsi + {off_r12}]

        mov [rdi + {off_r13}], r13
        mov r13, [rsi + {off_r13}]

        mov [rdi + {off_r14}], r14
        mov r14, [rsi + {off_r14}]

        mov [rdi + {off_r15}], r15
        mov r15, [rsi + {off_r15}]

        mov [rdi + {off_rbp}], rbp
        mov rbp, [rsi + {off_rbp}]

        mov [rdi + {off_rsp}], rsp
        mov rsp, [rsi + {off_rsp}]

        ",
        switch_fsgsbase!(),
        "

        // push RFLAGS (can only be modified via stack)
        pushfq
        // pop RFLAGS into `self.rflags`
        pop QWORD PTR [rdi + {off_rflags}]

        // push `next.rflags`
        push QWORD PTR [rsi + {off_rflags}]
        // pop into RFLAGS
        popfq

        // When we return, we cannot even guarantee that the return address on the stack, points to
        // the calling function, `context::switch`. Thus, we have to execute this Rust hook by
        // ourselves, which will unlock the contexts before the later switch.

        // Note that switch_finish_hook will be responsible for executing `ret`.
        jmp {switch_hook}

        "),

        off_fx = const(offset_of!(Cx, fx)),
        off_cr3 = const(offset_of!(Cx, cr3)),
        off_rflags = const(offset_of!(Cx, rflags)),
        off_loadable = const(offset_of!(Cx, loadable)),

        off_rbx = const(offset_of!(Cx, rbx)),
        off_r12 = const(offset_of!(Cx, r12)),
        off_r13 = const(offset_of!(Cx, r13)),
        off_r14 = const(offset_of!(Cx, r14)),
        off_r15 = const(offset_of!(Cx, r15)),
        off_rbp = const(offset_of!(Cx, rbp)),
        off_rsp = const(offset_of!(Cx, rsp)),

        off_fsbase = const(offset_of!(Cx, fsbase)),
        off_gsbase = const(offset_of!(Cx, gsbase)),

        MSR_FSBASE = const(x86::msr::IA32_FS_BASE),
        MSR_KERNELGSBASE = const(x86::msr::IA32_KERNEL_GSBASE),

        true = const(AbiCompatBool::True as u8),
        switch_hook = sym crate::context::switch_finish_hook,
        options(noreturn),
    );
}
#[allow(dead_code)]
#[repr(packed)]
pub struct SignalHandlerStack {
    r11: usize,
    r10: usize,
    r9: usize,
    r8: usize,
    rsi: usize,
    rdi: usize,
    rdx: usize,
    rcx: usize,
    rax: usize,
    handler: extern fn(usize),
    sig: usize,
    rip: usize,
}

#[naked]
unsafe extern fn signal_handler_wrapper() {
    #[inline(never)]
    unsafe extern "C" fn inner(stack: &SignalHandlerStack) {
        (stack.handler)(stack.sig);
    }

    // Push scratch registers
    core::arch::asm!(
        "
            push rax
            push rcx
            push rdx
            push rdi
            push rsi
            push r8
            push r9
            push r10
            push r11

            mov rdi, rsp
            call {inner}

            pop r11
            pop r10
            pop r9
            pop r8
            pop rsi
            pop rdi
            pop rdx
            pop rcx
            pop rax
            add rsp, 16
            ret
        ",

        inner = sym inner,
        options(noreturn),
    );
}
