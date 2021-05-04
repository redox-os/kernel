    //  Populates misc arguments, sets up the stack, clears all other registers.

setup_kstart_context:
    adr  x0, args.kernel_base               // Physical address of kernel base
    str  x11, [x0]

    adr  x0, args.kernel_size               // Size of kernel image
    str  x12, [x0]

    adr  x0, args.stack_base                // Virtual address of kernel stack base
    ldr  x1, =KERNEL_OFFSET
    add  x1, x1, x12
    str  x1, [x0]

    adr  x0, args.stack_size                // Size of kernel stack
    mov  x1, #(EARLY_KSTACK_SIZE)
    str  x1, [x0]

    adr  x0, args.env_base                  // Virtual address of environment base
    adr  x1, env_region_marker
    ldr  x1, [x1]
    str  x1, [x0]

    adr  x0, args.env_size                  // Size of environment (populated later in kstart)
    ldr  x1, =PAGE_SIZE
    str  x1, [x0]

    adr  x0, args.dtb_base                  // Physical address of DTB Image's base
    str  x19, [x0]

    adr  x0, args.dtb_size                  // Size of DTB image
    mov  w1, w21
    str  w1, [x0]

    add  x1, x15, x12                       // Initialize the stack pointer, everything is 2MB aligned
    add  x1, x1, x14                        // sp = (kbase.vaddr + ksize + stksize) - sizeof(word)
    sub  x1, x1, #16
    mov  sp, x1

    adr  x0, tmp_zero                       // Store a zero at tmp_zero
    str  xzr, [x0]                          // Note: x0 points to addr_marker so we use it below as-is

    ldp  x2, x3, [x0, #0]!                  // Zero x1:x31
    ldp  x4, x5, [x0, #0]!
    ldp  x6, x7, [x0, #0]!
    ldp  x8, x9, [x0, #0]!
    ldp  x10, x11, [x0, #0]!
    ldp  x12, x13, [x0, #0]!
    ldp  x14, x15, [x0, #0]!
    ldp  x16, x17, [x0, #0]!
    ldp  x18, x19, [x0, #0]!
    ldp  x20, x21, [x0, #0]!
    ldp  x22, x23, [x0, #0]!
    ldp  x24, x25, [x0, #0]!
    ldp  x26, x27, [x0, #0]!
    ldp  x28, x29, [x0, #0]!

    ldr  x0, =args.kernel_base              // x0 = Start of argument block
    mov  x1, #0

    ret

mmu_on_trampoline:
    adr     x0, mmu_on_marker               // x0: paddr of mmu_on_marker
    ldr     x0, [x0]                        // x0: vaddr of mmu_on
    br      x0                              // MMU now On. Jump to mmu_on using it's vaddr

    // Statically allocated space to hold misc arguments for kstart.

    .align 3
args.kernel_base:
    .space 8
args.kernel_size:
    .space 8
args.stack_base:
    .space 8
args.stack_size:
    .space 8
args.env_base:
    .space 8
args.env_size:
    .space 8
args.dtb_base:
    .space 8
args.dtb_size:
    .space 8

    //  Misc scratch memory used by this file

env_region_marker:
    .quad env_region
mmu_on_marker:
    .quad mmu_on
tmp_zero:
    .quad tmp_zero
