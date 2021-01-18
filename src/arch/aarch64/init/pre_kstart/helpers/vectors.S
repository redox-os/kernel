    //  Exception vector stubs
    //
    //  The hex values in x18 are to aid debugging
    //  Unhandled exceptions spin in a wfi loop for the moment
    //  This can be macro-ified

    .align 11
exception_vector_base:

    .align 7
__vec_00:
    mov     x18, #0xb0b0
    b       do_exception_synchronous
    b       __vec_00

    .align 7
__vec_01:
    mov     x18, #0xb0b1
    b       do_exception_irq
    b       __vec_01

    .align 7
__vec_02:
    mov     x18, #0xb0b2
    b       do_exception_unhandled
    b       __vec_02

    .align 7
__vec_03:
    mov     x18, #0xb0b3
    b       do_exception_unhandled
    b       __vec_03

    .align 7
__vec_04:
    mov     x18, #0xb0b4
    b       do_exception_synchronous
    b       __vec_04

    .align 7
__vec_05:
    mov     x18, #0xb0b5
    b       do_exception_irq
    b       __vec_05

    .align 7
__vec_06:
    mov     x18, #0xb0b6
    b       do_exception_unhandled
    b       __vec_06

    .align 7
__vec_07:
    mov     x18, #0xb0b7
    b       do_exception_unhandled
    b       __vec_07

    .align 7
__vec_08:
    mov     x18, #0xb0b8
    b       do_exception_synchronous
    b       __vec_08

    .align 7
__vec_09:
    mov     x18, #0xb0b9
    b       do_exception_irq
    b       __vec_09

    .align 7
__vec_10:
    mov     x18, #0xb0ba
    b       do_exception_unhandled
    b       __vec_10

    .align 7
__vec_11:
    mov     x18, #0xb0bb
    b       do_exception_unhandled
    b       __vec_11

    .align 7
__vec_12:
    mov     x18, #0xb0bc
    b       do_exception_unhandled
    b       __vec_12

    .align 7
__vec_13:
    mov     x18, #0xb0bd
    b       do_exception_unhandled
    b       __vec_13

    .align 7
__vec_14:
    mov     x18, #0xb0be
    b       do_exception_unhandled
    b       __vec_14

    .align 7
exception_vector_end:
