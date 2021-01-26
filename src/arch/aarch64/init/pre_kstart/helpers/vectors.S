    //  Exception vector stubs
    //
    //  The hex values in x18 are to aid debugging
    //  Unhandled exceptions spin in a wfi loop for the moment
    //  This can be macro-ified

    .align 11
exception_vector_base:

    // Synchronous
    .align 7
__vec_00:
    mov     x18, #0xb0b0
    b       synchronous_exception_at_el1_with_sp0
    b       __vec_00

    // IRQ
    .align 7
__vec_01:
    mov     x18, #0xb0b1
    b       irq_at_el1
    b       __vec_01

    // FIQ
    .align 7
__vec_02:
    mov     x18, #0xb0b2
    b       unhandled_exception
    b       __vec_02

    // SError
    .align 7
__vec_03:
    mov     x18, #0xb0b3
    b       unhandled_exception
    b       __vec_03

    // Synchronous
    .align 7
__vec_04:
    mov     x18, #0xb0b4
    b       synchronous_exception_at_el1_with_spx
    b       __vec_04

    // IRQ
    .align 7
__vec_05:
    mov     x18, #0xb0b5
    b       irq_at_el1
    b       __vec_05

    // FIQ
    .align 7
__vec_06:
    mov     x18, #0xb0b6
    b       unhandled_exception
    b       __vec_06

    // SError
    .align 7
__vec_07:
    mov     x18, #0xb0b7
    b       unhandled_exception
    b       __vec_07

    // Synchronous
    .align 7
__vec_08:
    mov     x18, #0xb0b8
    b       synchronous_exception_at_el0
    b       __vec_08

    // IRQ
    .align 7
__vec_09:
    mov     x18, #0xb0b9
    b       irq_at_el0
    b       __vec_09

    // FIQ
    .align 7
__vec_10:
    mov     x18, #0xb0ba
    b       unhandled_exception
    b       __vec_10

    // SError
    .align 7
__vec_11:
    mov     x18, #0xb0bb
    b       unhandled_exception
    b       __vec_11

    // Synchronous
    .align 7
__vec_12:
    mov     x18, #0xb0bc
    b       unhandled_exception
    b       __vec_12

    // IRQ
    .align 7
__vec_13:
    mov     x18, #0xb0bd
    b       unhandled_exception
    b       __vec_13

    // FIQ
    .align 7
__vec_14:
    mov     x18, #0xb0be
    b       unhandled_exception
    b       __vec_14

    // SError
    .align 7
__vec_15:
    mov     x18, #0xb0bf
    b       unhandled_exception
    b       __vec_15
    
    .align 7
exception_vector_end:
