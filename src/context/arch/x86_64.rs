use core::mem;
use core::sync::atomic::AtomicBool;

use crate::syscall::FloatRegisters;

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
            rsp: 0
        }
    }

    pub fn get_page_utable(&mut self) -> usize {
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

/// Switch to the next context by restoring its stack and registers
/// Check disassembly!
#[cold]
#[inline(never)]
#[naked]
pub unsafe extern "C" fn switch_to(_prev: &mut Context, _next: &mut Context) {
    asm!(
        // As a quick reminder for those who are unfamiliar with the System V ABI (extern "C"):
        //
        // - the current parameters are passed in the registers `rdi`, `rsi`,
        // - we can modify scratch registers, e.g. rax
        // - we cannot change callee-preserved registers arbitrarily, e.g. rbx, which is why we
        //   store them here in the first place.
        "
        // load `prev.fx`
        mov rax, [rdi + 0x00]

        // save processor SSE/FPU/AVX state in `prev.fx` pointee
        fxsave64 [rax]

        // set `prev.loadable` to true
        mov BYTE PTR [rdi + 0x50], {true}
        // compare `next.loadable` with true
        cmp BYTE PTR [rsi + 0x50], {true}
        je switch_to.next_is_loadable

        fninit
        jmp switch_to.after_fx

        switch_to.next_is_loadable:
        mov rax, [rsi + 0x00]
        fxrstor64 [rax]

        switch_to.after_fx:
        // Save the current CR3, and load the next CR3 if not identical
        mov rcx, cr3
        mov [rdi + 0x08], rcx
        mov rax, [rsi + 0x08]
        cmp rax, rcx

        je switch_to.same_cr3
        mov cr3, rax

        switch_to.same_cr3:
        // Save old registers, and load new ones
        mov [rdi + 0x18], rbx
        mov rbx, [rsi + 0x18]

        mov [rdi + 0x20], r12
        mov r12, [rsi + 0x20]

        mov [rdi + 0x28], r13
        mov r13, [rsi + 0x28]

        mov [rdi + 0x30], r14
        mov r14, [rsi + 0x30]

        mov [rdi + 0x38], r15
        mov r15, [rsi + 0x38]

        mov [rdi + 0x40], rbp
        mov rbp, [rsi + 0x40]

        mov [rdi + 0x48], rsp
        mov rsp, [rsi + 0x48]

        // push RFLAGS (can only be modified via stack)
        pushfq
        // pop RFLAGS into `self.rflags`
        pop QWORD PTR [rdi + 0x10]

        // push `next.rflags`
        push QWORD PTR [rsi + 0x10]
        // pop into RFLAGS
        popfq

        // When we return, we cannot even guarantee that the return address on the stack, points to
        // the calling function, `context::switch`. Thus, we have to execute this Rust hook by
        // ourselves, which will unlock the contexts before the later switch.

        call {switch_hook}

        ",

        true = const(AbiCompatBool::True as u8),
        switch_hook = sym crate::context::switch_finish_hook,
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
    asm!(
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
        ",

        inner = sym inner,
    );
}
