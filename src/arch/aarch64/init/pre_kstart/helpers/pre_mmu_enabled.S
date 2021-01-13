    //  Stashes DTB size for use later
    //  Sets up the exception vectors
early_setup:
    mov     x19, x0                         // Store paddr of DTB in x19
    ldr     w21, [x0, #4]                   // x0[4] has the DTB size in Big Endian Format
    rev     w21, w21                        // Swizzle to little endian

    msr     contextidr_el1, xzr             // Set contextID reg
    dsb     sy

    ldr     x0, =exception_vector_base
    msr     vbar_el1, x0

    ret

disable_mmu:
    mrs     x0, sctlr_el1
    bic     x0, x0, SCTLR_M
    msr     sctlr_el1, x0
    isb

    ret


    //  Programs the TTBR registers, MAIR registers, TCR and SCTLR registers.
enable_mmu:
    dsb     sy

    adr     x0, identkmap_l0_ptable         // Setup TTBRx_EL1
    msr     ttbr0_el1, x0                   // ttbr0_el1: Lower vaddrs
    adr     x1, kernmap_l0_ptable
    msr     ttbr1_el1, x1                   // ttbr1_el1: Higher vaddrs
    isb

    tlbi    vmalle1is                       // Invalidate the TLB

    ldr     x2, mair                        // Setup MAIR
    msr     mair_el1, x2

    ldr     x2, tcr                         // Setup TCR ()ID_AA64MMFR0_EL1)
    mrs     x3, id_aa64mmfr0_el1
    bfi     x2, x3, #32, #3
    msr     tcr_el1, x2
    isb

    ldr     x2, sctlr_set_bits              // Setup SCTLR
    ldr     x3, sctlr_clr_bits
    mrs     x1, sctlr_el1
    bic     x1, x1, x3
    orr     x1, x1, x2
    msr     sctlr_el1, x1
    isb
    mrs     x1, sctlr_el1

    ret

    //  Magic config runes (Too much detail to enumerate here: grep the ARM ARM for details)
    .align 3
mair:
    .quad   0xff4400                        // MAIR: Arrange for Device, Normal Non-Cache, Normal Write-Back access types
tcr:
    .quad   0x1085100510                    // Setup TCR: (TxSZ, ASID_16, TG1_4K, Cache Attrs, SMP Attrs)
sctlr_set_bits:
    .quad   0x3485d13d                      // Set SCTLR bits: (LSMAOE, nTLSMD, UCI, SPAN, nTWW, nTWI, UCT, DZE, I, SED, SA0, SA, C, M, CP15BEN)
sctlr_clr_bits:
    .quad   0x32802c2                       // Clear SCTLR bits: (EE, EOE, IESB, WXN, UMA, ITD, THEE, A)
