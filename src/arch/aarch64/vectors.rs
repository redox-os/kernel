core::arch::global_asm!(
    "
    //  Exception vector stubs
    //
    //  Unhandled exceptions spin in a wfi loop for the moment
    //  This can be macro-ified

.globl exception_vector_base

    .align 11
exception_vector_base:

    // Synchronous
    .align 7
__vec_00:
    b       synchronous_exception_at_el1_with_sp0
    b       __vec_00

    // IRQ
    .align 7
__vec_01:
    b       irq_at_el1
    b       __vec_01

    // FIQ
    .align 7
__vec_02:
    b       unhandled_exception
    b       __vec_02

    // SError
    .align 7
__vec_03:
    b       unhandled_exception
    b       __vec_03

    // Synchronous
    .align 7
__vec_04:
    b       synchronous_exception_at_el1_with_spx
    b       __vec_04

    // IRQ
    .align 7
__vec_05:
    b       irq_at_el1
    b       __vec_05

    // FIQ
    .align 7
__vec_06:
    b       unhandled_exception
    b       __vec_06

    // SError
    .align 7
__vec_07:
    b       unhandled_exception
    b       __vec_07

    // Synchronous
    .align 7
__vec_08:
    b       synchronous_exception_at_el0
    b       __vec_08

    // IRQ
    .align 7
__vec_09:
    b       irq_at_el0
    b       __vec_09

    // FIQ
    .align 7
__vec_10:
    b       unhandled_exception
    b       __vec_10

    // SError
    .align 7
__vec_11:
    b       unhandled_exception
    b       __vec_11

    // Synchronous
    .align 7
__vec_12:
    b       unhandled_exception
    b       __vec_12

    // IRQ
    .align 7
__vec_13:
    b       unhandled_exception
    b       __vec_13

    // FIQ
    .align 7
__vec_14:
    b       unhandled_exception
    b       __vec_14

    // SError
    .align 7
__vec_15:
    b       unhandled_exception
    b       __vec_15
    
    .align 7
exception_vector_end:
"
);
