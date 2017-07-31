#[naked]
pub unsafe extern fn syscall() {
    #[inline(never)]
    unsafe fn inner(stack: &mut SyscallStack) {
        extern {
            fn syscall(a: usize, b: usize, c: usize, d: usize, e: usize, f: usize, rbp: usize, stack: &mut SyscallStack) -> usize;
        }

        let mut a;
        {
            let b;
            let rbp;
            asm!("" : "={rax}"(a), "={rbx}"(b), "={rbp}"(rbp)
                : : : "intel", "volatile");

            a = syscall(a, b, stack.rcx, stack.rdx, stack.rsi, stack.rdi, rbp, stack);
        }

        asm!("" : : "{rax}"(a) : : "intel", "volatile");
    }

    // Push scratch registers, minus rax for the return value
    asm!("push rcx
        push rdx
        push rdi
        push rsi
        push r8
        push r9
        push r10
        push r11
        push fs
        mov r11, 0x18
        mov fs, r11"
        : : : : "intel", "volatile");

    // Get reference to stack variables
    let rsp: usize;
    asm!("" : "={rsp}"(rsp) : : : "intel", "volatile");

    inner(&mut *(rsp as *mut SyscallStack));

    // Interrupt return
    asm!("pop fs
        pop r11
        pop r10
        pop r9
        pop r8
        pop rsi
        pop rdi
        pop rdx
        pop rcx
        iretq"
        : : : : "intel", "volatile");
}

#[allow(dead_code)]
#[repr(packed)]
pub struct SyscallStack {
    pub fs: usize,
    pub r11: usize,
    pub r10: usize,
    pub r9: usize,
    pub r8: usize,
    pub rsi: usize,
    pub rdi: usize,
    pub rdx: usize,
    pub rcx: usize,
    pub rip: usize,
    pub cs: usize,
    pub rflags: usize,
}

#[naked]
pub unsafe extern fn clone_ret() -> usize {
    asm!("pop rbp"
        : : : : "intel", "volatile");
        0
}
