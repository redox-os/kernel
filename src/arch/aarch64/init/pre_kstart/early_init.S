// Early initialisation for AArch64 systems.
//
// This code is responsible for taking over control of the boot CPU from
// the bootloader and setting up enough of the CPU so Rust code can take
// over (in kstart).
//
// Readers are recommended to refer to the Arm Architecture Reference Manual
// when studying this code. The latest version of the Arm Arm can be found at:
//
// https://developer.arm.com/products/architecture/cpu-architecture/a-profile/docs
//
// The code is structured such that different phases/functionality are
// in separate files included by this central one.
//
// This is hopefully easier to grok and study than one gigantic file.
//
// The emphasis is on clarity and not optimisation. Clarity is hard without
// a decent understanding of the Arm architecture.
//
// Optimisation is not too much of a concern given that this is boot code.
// That said, future revisions will aim to optimise.

#include "helpers/consts.h"

#include "helpers/pre_mmu_enabled.S"
#include "helpers/build_page_tables.S"
#include "helpers/post_mmu_enabled.S"
#include "helpers/vectors.S"

//  Entry point for the boot CPU. We assume that x0 contains the physical address of a DTB image
//  passed in by the bootloader.
//
//  Note that the kernel linker script arranges for this code to lie at the start of the kernel
//  image.

    .text
    .align 2
    .pushsection ".early_init.text", "ax"
    .globl early_init
early_init:
    bl      early_setup
    bl      disable_mmu
    bl      create_page_tables
    bl      enable_mmu
    b       mmu_on_trampoline               // With the mmu now on, this returns below to
                                            // mmu_on using Virtual Addressing

mmu_on:
    bl      setup_kstart_context            // Setup environment for kstart
    b       kstart                          // Let the show begin! :)
    .popsection
