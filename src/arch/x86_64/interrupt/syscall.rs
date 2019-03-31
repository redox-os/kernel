use arch::{gdt, pti};
use syscall;
use x86::shared::msr;

pub unsafe fn init() {
    msr::wrmsr(msr::IA32_STAR, ((gdt::GDT_KERNEL_CODE as u64) << 3) << 32);
    msr::wrmsr(msr::IA32_LSTAR, syscall_instruction as u64);
    msr::wrmsr(msr::IA32_FMASK, 1 << 9);
    msr::wrmsr(msr::IA32_KERNEL_GS_BASE, &gdt::TSS as *const _ as u64);

    let efer = msr::rdmsr(msr::IA32_EFER);
    msr::wrmsr(msr::IA32_EFER, efer | 1);
}

#[naked]
pub unsafe extern fn syscall_instruction() {
    #[inline(never)]
    unsafe fn inner(stack: &mut SyscallStack) -> usize {
        let rbp;
        asm!("" : "={rbp}"(rbp) : : : "intel", "volatile");

        syscall::syscall(stack.rax, stack.rdi, stack.rsi, stack.rdx, stack.r10, stack.r8, rbp, stack)
    }

    // Yes, this is magic. No, you don't need to understand
    asm!("
          swapgs                    // Set gs segment to TSS
          mov gs:[28], rsp          // Save userspace rsp
          mov rsp, gs:[4]           // Load kernel rsp
          push 5 * 8 + 3            // Push userspace data segment
          push qword ptr gs:[28]    // Push userspace rsp
          mov qword ptr gs:[28], 0  // Clear userspace rsp
          push r11                  // Push rflags
          push 4 * 8 + 3            // Push userspace code segment
          push rcx                  // Push userspace return pointer
          swapgs                    // Restore gs
          "
          :
          :
          :
          : "intel", "volatile");

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
    // Will only be present if syscall is called from another ring
    pub rsp: usize,
    pub ss: usize,
}

#[naked]
pub unsafe extern fn clone_ret() {
    asm!("
        pop rbp
        xor rax, rax
        "
        : : : : "intel", "volatile");
}
