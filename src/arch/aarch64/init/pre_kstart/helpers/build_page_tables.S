    //  Creates the following MMU mappings:
    //
    //  1. Identity mapping for the kernel (VA == PA) to be able to switch on the MMU
    //  2. Mapping for the kernel with high VAs from KERNEL_OFFSET onwards
    //  3. Mapping for the kernel stack
    //  4. Mapping for the DTB Image
    //  5. Optional Mapping for a diagnostic UART

create_page_tables:
    mov     x22, x30
    adr     x0, addr_marker                 // x0: Physical address of addr_marker
    ldr     x1, [x0]                        // x1: Virtual address of addr_marker
    ldr     x2, =KERNEL_OFFSET              // x2: Virtual address of kernel base
    sub     x3, x1, x2                      // x3: 'Distance' of addr_marker from kernel base
    sub     x0, x0, x3                      // x0: Physical address of kernel base
    mov     x11,x0                          // x11: Stash away the Physical address of the kernel image base

    ldr     x1, =KERNEL_OFFSET              // x1: Virtual address of kernel start addr
    ldr     x2, =__end                      // x2: Virtual address of kernel end addr
    sub     x12, x2, x1                     // x12: Size of the kernel image
    add     x12, x12, #(0x200000)           // x12: Align to 2MB (Add 2MB, then clear low bits if any)
    and     x3, x12, #0xffffffffffe00000
    cmp     x12, #0x200, lsl #12
    csel    x12, x3, x12, hi
    add     x13, x1, x12                    // x13: Stack top vaddr (kbase.vaddr + ksize)
    mov     x14, #(EARLY_KSTACK_SIZE)       // x14: Stack size
    ldr     x15, =KERNEL_OFFSET             // x15: Kernel base vaddr

    //  From this point on, the following registers are not to be modified for convenience:
    //  x11: PA of kernel image base
    //  x12: Kernel image size (2MB aligned)
    //  x13: VA of stack top
    //  x14: Stack size
    //  x15: VA of kernel Base

    //  Zero out all the tables
zero_tables:
    adr     x0, identkmap_l0_ptable
    mov     x1, #(PAGE_SIZE)
    mov     x2, #(NUM_TABLES)            // There are normally 12 tables to clear (2 L0, 5 L1, 5 L2, 1 env)
    mul     x1, x1, x2
    lsr     x1, x1, #3
    mov     x2, xzr
zero_loop:
    str     xzr, [x0, x2]
    add     x2, x2, #8
    cmp     x1, x2
    b.ne    zero_loop

    //  Identity map the kernel
    mov     x0, x11                         // x0: Paddr of kernel image base
    mov     x1, x11                         // x1: Paddr of kernel image base
    mov     x2, x12                         // x2: Kernel image size
    mov     x3, #(NORMAL_UNCACHED_MEM)      // x3: Attributes to apply
    adr     x4, identkmap_l0_ptable         // x5: Ptr to L0 table for identity mapping the kernel
    adr     x5, identkmap_l1_ptable         // x6: Ptr to L1 table for identity mapping the kernel
    adr     x6, identkmap_l2_ptable         // x7: Ptr to L2 table for identity mapping the kernel
    bl      build_map

    //  Map the kernel
    ldr     x0, =KERNEL_OFFSET              // x0: Vaddr of kernel base
    mov     x1, x11                         // x1: Paddr of kernel base
    mov     x2, x12                         // x2: Kernel image size
    mov     x3, #(NORMAL_CACHED_MEM)        // x3: Attributes to apply
    adr     x4, kernmap_l0_ptable           // x5: Ptr to L0 table for mapping the kernel
    adr     x5, kernmap_l1_ptable           // x6: Ptr to L1 table for mapping the kernel
    adr     x6, kernmap_l2_ptable           // x7: Ptr to L2 table for mapping the kernel
    bl      build_map

    //  Map the kernel stack
    ldr     x0, =KERNEL_OFFSET              // x0: Vaddr of kernel stack top
    add     x0, x0, x12
    sub     x1, x11, x14                    // x1: Paddr of kernel stack top (kbase.paddr - kstack size)
    mov     x2, #(EARLY_KSTACK_SIZE)        // x2: Size of kernel stack
    mov     x3, #(NORMAL_CACHED_MEM)        // x3: Attributes to apply
    adr     x4, kernmap_l0_ptable           // x5: Ptr to the kernel L0 table
    adr     x5, kstack_l1_ptable            // x6: Ptr to L1 table for mapping the kernel stack
    adr     x6, kstack_l2_ptable            // x7: Ptr to L2 table for mapping the kernel stack
    bl      build_map

    // Map first GIGABYTE at PHYS_OFFSET
    mov     x1, #0                          // x1: Physical address
    adr     x6, physmap_1gb_l2_ptable       // x7: Ptr to L2 table
    bl      build_physmap

    // Map second GIGABYTE at PHYS_OFFSET + GIGABYTE
    mov     x1, #(GIGABYTE)                 // x1: Physical address
    adr     x6, physmap_2gb_l2_ptable       // x7: Ptr to L2 table
    bl      build_physmap

    // Map third GIGABYTE at PHYS_OFFSET + 2*GIGABYTE
    mov     x1, #(2*GIGABYTE)               // x1: Physical address
    adr     x6, physmap_3gb_l2_ptable       // x7: Ptr to L2 table
    bl      build_physmap

    // Map fourth GIGABYTE at PHYS_OFFSET + 3*GIGABYTE
    mov     x1, #(3*GIGABYTE)               // x1: Physical address
    adr     x6, physmap_4gb_l2_ptable       // x7: Ptr to L2 table
    bl      build_physmap

    //  Set up recursive paging for TTBR1

    adr     x0, kernmap_l0_ptable
    add     x1, x0, #(511 * 8)
    orr     x0, x0, #((DESC_TYPE_TABLE << DESC_TYPE_BIT) | (DESC_VALID << DESC_VALID_BIT))
    orr     x0, x0, #(ACCESS_FLAG_BIT)
    str     x0, [x1]

    //  Set up recursive paging for TTBR0

    adr     x0, identkmap_l0_ptable
    add     x1, x0, #(511 * 8)
    orr     x0, x0, #((DESC_TYPE_TABLE << DESC_TYPE_BIT) | (DESC_VALID << DESC_VALID_BIT))
    orr     x0, x0, #(ACCESS_FLAG_BIT)
    str     x0, [x1]

    mov     x30, x22

    ret

// Add a physmap entry
//   x1: physical address, a multiple of GIGABYTE
//   x6: address of l2 page table
build_physmap:
    ldr     x0, =DEVMAP_VBASE               // x0: Virtual address
    add     x0, x0, x1
    mov     x2, #(GIGABYTE - 1)             // x2: Size (minus one to work around errors)
    mov     x3, #(DEVICE_MEM)               // x3: Attributes to apply
    adr     x4, kernmap_l0_ptable           // x5: Ptr to L0 table
    adr     x5, physmap_l1_ptable           // x6: Ptr to L1 table
    b       build_map

    //  Generic routine to build mappings. Requires the following inputs:
    //
    //  x0:  Vaddr to map to Paddr
    //  x1:  Paddr to map Vaddr to
    //  x2:  Length (in bytes) of region to map
    //  x3:  Region attributes
    //  x4:  Paddr of L0 table to use for mapping
    //  x5:  Paddr of L1 table to use for mapping
    //  x6:  Paddr of L2 table to use for mapping
    //
    //  To keep things simple everything is mapped using 2MB blocks. This implies that the length
    //  is explicitly aligned to 2MB to prevent any translation aliases. Since block translations
    //  at L2 cover 2MB blocks, that suits us nicely so everything uses 2MB L2 blocks. Wasteful
    //  perhaps but at this stage it's convenient and in any case will get ripped out and
    //  reprogrammed in kstart.

build_map:
    lsr     x8, x0, #39                     // First group of 9 bits of VA
    and     x8, x8, #0x1ff
    lsl     x8, x8, #3                      // x8: Index into L0 table
    ldr     x9, [x4, x8]
    cbnz    x9, l1_idx_prefilled

    mov     x9, x5                          // Get L1 base
    bfm     w9, wzr, #0, #11
    orr     x9, x9, #((DESC_TYPE_TABLE << DESC_TYPE_BIT) | (DESC_VALID << DESC_VALID_BIT))
    orr     x9, x9, #(ACCESS_FLAG_BIT)
    str     x9, [x4, x8]                    // L0[Index]: L1

l1_idx_prefilled:
    lsr     x8, x0, #30                     // Second group of 9 bits of VA
    and     x8, x8, #0x1ff
    lsl     x8, x8, #3                      // x8: Index into L1 table
    ldr     x9, [x5, x8]
    cbnz    x9, l2_idx_prefilled

build_map_l2:
    mov     x9, x6                          // Get L2 base
    bfm     w9, wzr, #0, #11
    orr     x9, x9, #((DESC_TYPE_TABLE << DESC_TYPE_BIT) | (DESC_VALID << DESC_VALID_BIT))
    orr     x9, x9, #(ACCESS_FLAG_BIT)
    lsl     x4, x3, #2
    orr     x9, x9, x4
    str     x9, [x5, x8]                    // L1[Index]: Base of L2 table

l2_idx_prefilled:
    lsr     x2, x2, #21                     // Number of 2MB blocks needed */
    add     x2, x2, #1                      //TODO: remove this and remove workarounds

    lsr     x8, x0, #21                     // Third group of 9 bits of VA
    and     x8, x8, #0x1ff
    lsl     x8, x8, #3                      // x8: Index into L2 table
    ldr     x9, [x6, x8]
    cbnz    x9, build_map_error

build_map_l2_loop:
    mov     x9, x1
    bfm     w9, wzr, #0, #11
    orr     x9, x9, #((DESC_TYPE_BLOCK << DESC_TYPE_BIT) | (DESC_VALID << DESC_VALID_BIT))
    orr     x9, x9, #(ACCESS_FLAG_BIT)
    lsl     x4, x3, #2
    orr     x9, x9, x4
    ldr     x10, [x6, x8]
    mov     x7, #(DESC_VALID << DESC_VALID_BIT)
    and     x10, x10, x7
    cmp     x10, x7
    b.eq    build_map_error
    str     x9, [x6, x8]                    // L2[Index]: PA of 2MB region to map to

    mov     x9, #1
    add     x1, x1, x9, lsl #21
    add     x8, x8, #8
    sub     x2, x2, #1
    cbnz    x2, build_map_l2_loop

    ret

build_map_error:
    wfi
    b       build_map_error

    //  Statically allocated tables consumed by build_map.

    .align 12
identkmap_l0_ptable:
    .space PAGE_SIZE
identkmap_l1_ptable:
    .space PAGE_SIZE
identkmap_l2_ptable:
    .space PAGE_SIZE
kernmap_l0_ptable:
    .space PAGE_SIZE
kernmap_l1_ptable:
    .space PAGE_SIZE
kernmap_l2_ptable:
    .space PAGE_SIZE
kstack_l1_ptable:
    .space PAGE_SIZE
kstack_l2_ptable:
    .space PAGE_SIZE
physmap_l1_ptable:
    .space PAGE_SIZE
physmap_1gb_l2_ptable:
    .space PAGE_SIZE
physmap_2gb_l2_ptable:
    .space PAGE_SIZE
physmap_3gb_l2_ptable:
    .space PAGE_SIZE
physmap_4gb_l2_ptable:
    .space PAGE_SIZE
env_region:
    .space PAGE_SIZE

    //  Misc scratch memory used by this file

addr_marker:
    .quad addr_marker
