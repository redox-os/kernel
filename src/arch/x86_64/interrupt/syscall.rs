use crate::{
    arch::{gdt, interrupt::InterruptStack},
    ptrace, syscall,
    syscall::flag::{PTRACE_FLAG_IGNORE, PTRACE_STOP_POST_SYSCALL, PTRACE_STOP_PRE_SYSCALL},
};
use core::mem::offset_of;
use x86::{
    bits64::{rflags::RFlags, task::TaskStateSegment},
    msr,
    segmentation::SegmentSelector,
};

pub unsafe fn init() {
    // IA32_STAR[31:0] are reserved.

    // The base selector of the two consecutive segments for kernel code and the immediately
    // suceeding stack (data).
    let syscall_cs_ss_base = (gdt::GDT_KERNEL_CODE as u16) << 3;
    // The base selector of the three consecutive segments (of which two are used) for user code
    // and user data. It points to a 32-bit code segment, which must be followed by a data segment
    // (stack), and a 64-bit code segment.
    let sysret_cs_ss_base = ((gdt::GDT_USER_CODE32_UNUSED as u16) << 3) | 3;
    let star_high = u32::from(syscall_cs_ss_base) | (u32::from(sysret_cs_ss_base) << 16);

    msr::wrmsr(msr::IA32_STAR, u64::from(star_high) << 32);
    msr::wrmsr(msr::IA32_LSTAR, syscall_instruction as u64);

    // DF needs to be cleared, required by the compiler ABI. If DF were not part of FMASK,
    // userspace would be able to reverse the direction of in-kernel REP MOVS/STOS/(CMPS/SCAS), and
    // cause all sorts of memory corruption.
    //
    // IF needs to be cleared, as the kernel currently assumes interrupts are disabled except in
    // usermode and in kmain.
    //
    // TF needs to be cleared, as enabling userspace-rflags-controlled singlestep in the kernel
    // would be a bad idea.
    //
    // AC it should always be cleared when entering the kernel (and never be set except in usercopy
    // functions), if for some reason AC was set before entering userspace (AC can only be modified
    // by kernel code).
    //
    // The other flags could indeed be preserved and excluded from FMASK, but since they are not
    // used to pass data to the kernel, they might as well be masked with *marginal* security
    // benefits.
    //
    // Flags not included here are IOPL (not relevant to the kernel at all), "CPUID flag" (not used
    // at all in 64-bit mode), RF (not used yet, but DR breakpoints would remain enabled both in
    // user and kernel mode), VM8086 (not used at all), and VIF/VIP (system-level status flags?).

    let mask_critical = RFlags::FLAGS_DF | RFlags::FLAGS_IF | RFlags::FLAGS_TF | RFlags::FLAGS_AC;
    let mask_other = RFlags::FLAGS_CF
        | RFlags::FLAGS_PF
        | RFlags::FLAGS_AF
        | RFlags::FLAGS_ZF
        | RFlags::FLAGS_SF
        | RFlags::FLAGS_OF;
    msr::wrmsr(msr::IA32_FMASK, (mask_critical | mask_other).bits());

    let efer = msr::rdmsr(msr::IA32_EFER);
    msr::wrmsr(msr::IA32_EFER, efer | 1);
}

#[no_mangle]
pub unsafe extern "C" fn __inner_syscall_instruction(stack: *mut InterruptStack) {
    let allowed = ptrace::breakpoint_callback(PTRACE_STOP_PRE_SYSCALL, None)
        .and_then(|_| ptrace::next_breakpoint().map(|f| !f.contains(PTRACE_FLAG_IGNORE)));

    if allowed.unwrap_or(true) {
        let scratch = &(*stack).scratch;

        let ret = syscall::syscall(
            scratch.rax,
            scratch.rdi,
            scratch.rsi,
            scratch.rdx,
            scratch.r10,
            scratch.r8,
        );
        (*stack).scratch.rax = ret;
    }

    ptrace::breakpoint_callback(PTRACE_STOP_POST_SYSCALL, None);
}

#[naked]
#[allow(named_asm_labels)]
pub unsafe extern "C" fn syscall_instruction() {
    core::arch::asm!(concat!(
    // Yes, this is magic. No, you don't need to understand
    "swapgs;",                    // Swap KGSBASE with GSBASE, allowing fast TSS access.
    "mov gs:[{sp}], rsp;",        // Save userspace stack pointer
    "mov rsp, gs:[{ksp}];",       // Load kernel stack pointer
    "push QWORD PTR {ss_sel};",   // Push fake userspace SS (resembling iret frame)
    "push QWORD PTR gs:[{sp}];",  // Push userspace rsp
    "push r11;",                  // Push rflags
    "push QWORD PTR {cs_sel};",   // Push fake CS (resembling iret stack frame)
    "push rcx;",                  // Push userspace return pointer

    // Push context registers
    "push rax;",
    push_scratch!(),
    push_preserved!(),

    // TODO: Map PTI
    // $crate::arch::x86_64::pti::map();

    // Call inner funtion
    "mov rdi, rsp;",
    "call __inner_syscall_instruction;",

    // TODO: Unmap PTI
    // $crate::arch::x86_64::pti::unmap();

    "
    .globl enter_usermode
    enter_usermode:
    ",

    // Pop context registers
    pop_preserved!(),
    pop_scratch!(),

    // Restore user GSBASE by swapping GSBASE and KGSBASE.
    "swapgs;",

    // TODO: Should we unconditionally jump or avoid jumping, to hint to the branch predictor that
    // singlestep is NOT set?
    //
    // It appears Intel CPUs assume (previously unknown) forward conditional branches to not be
    // taken, and AMD appears to assume all previously unknown conditional branches will not be
    // taken.

    // Check if the Trap Flag (singlestep flag) is set. If so, sysretq will return to before the
    // instruction, whereas debuggers expect the iretq behavior of returning to after the
    // instruction.

    // TODO: Which one is faster?
    //      bt DWORD PTR [rsp + 16], 8
    //  or,
    //      bt BYTE PTR [rsp + 17], 0
    //  or,
    //      test BYTE PTR [rsp + 17], 1
    //  or,
    //      test WORD PTR [rsp + 16], 0x100
    //  or,
    //      test DWORD PTR [rsp + 16], 0x100
    //  ?

    "test BYTE PTR [rsp + 17], 1;",
    // If set, return using IRETQ instead.
    "jnz 2f;",

    // Otherwise, continue with the fast sysretq.

    // Pop userspace return pointer
    "pop rcx;",

    // We must ensure RCX is canonical; if it is not when running sysretq, the consequences can be
    // fatal from a security perspective.
    //
    // See https://xenproject.org/2012/06/13/the-intel-sysret-privilege-escalation/.
    //
    // This is not just theoretical; ptrace allows userspace to change RCX (via RIP) of target
    // processes.
    //
    // While we could also conditionally IRETQ here, an easier method is to simply sign-extend RCX:

    // Shift away the upper 16 bits (0xBAAD_8000_DEAD_BEEF => 0x8000_DEAD_BEEF_XXXX).
    "shl rcx, 16;",
    // Shift arithmetically right by 16 bits, effectively extending the 47th sign bit to bits
    // 63:48 (0x8000_DEAD_BEEF_XXXX => 0xFFFF_8000_DEAD_BEEF).
    "sar rcx, 16;",

    "add rsp, 8;",              // Pop fake userspace CS
    "pop r11;",                 // Pop rflags
    "pop rsp;",                 // Restore userspace stack pointer
    "sysretq;",                 // Return into userspace; RCX=>RIP,R11=>RFLAGS

    // IRETQ fallback:
    "
    .p2align 4
2:
    xor rcx, rcx
    xor r11, r11
    iretq
    "),

    sp = const(offset_of!(gdt::ProcessorControlRegion, user_rsp_tmp)),
    ksp = const(offset_of!(gdt::ProcessorControlRegion, tss) + offset_of!(TaskStateSegment, rsp)),
    ss_sel = const(SegmentSelector::new(gdt::GDT_USER_DATA as u16, x86::Ring::Ring3).bits()),
    cs_sel = const(SegmentSelector::new(gdt::GDT_USER_CODE as u16, x86::Ring::Ring3).bits()),

    options(noreturn),
    );
}
extern "C" {
    // TODO: macro?
    pub fn enter_usermode();
}
