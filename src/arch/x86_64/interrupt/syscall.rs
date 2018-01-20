use arch::x86_64::pti;
use syscall;

#[naked]
pub unsafe extern fn syscall() {
    #[inline(never)]
    unsafe fn inner(stack: &mut SyscallStack) -> usize {
        let rbp;
        asm!("" : "={rbp}"(rbp) : : : "intel", "volatile");

        syscall::syscall(stack.rax, stack.rbx, stack.rcx, stack.rdx, stack.rsi, stack.rdi, rbp, stack)
    }

    // Push scratch registers
    asm!("push rax
         push rbx
         push rcx
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

    // Map kernel
    pti::map();

    let a = inner(&mut *(rsp as *mut SyscallStack));

    // Unmap kernel
    pti::unmap();

    asm!("" : : "{rax}"(a) : : "intel", "volatile");

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
          pop rbx
          add rsp, 8
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
    pub rbx: usize,
    pub rax: usize,
    pub rip: usize,
    pub cs: usize,
    pub rflags: usize,
}

#[naked]
pub unsafe extern fn clone_ret() {
    asm!("pop rbp" : : : : "intel", "volatile");
    asm!("" : : "{rax}"(0) : : "intel", "volatile");
}
