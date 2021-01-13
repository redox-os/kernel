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
    wfi
    b __vec_00

    .align 7
__vec_01:
    mov     x18, #0xb0b1
    wfi
    b __vec_01

    .align 7
__vec_02:
    mov     x18, #0xb0b2
    wfi
    b __vec_02

    .align 7
__vec_03:
    mov     x18, #0xb0b3
    wfi
    b __vec_03

    .align 7
__vec_04:
    b       do_report_exception
    wfi
    b __vec_04

    .align 7
__vec_05:
    b       do_irq                              // First level interrupt handler
    wfi
    b __vec_05

    .align 7
__vec_06:
    mov     x18, #0xb0b6
    wfi
    b __vec_06

    .align 7
__vec_07:
    mov     x18, #0xb0b7
    wfi
    b __vec_07

    .align 7
__vec_08:
    b       do_syscall                          // Syscall handler
    wfi
    b __vec_08

    .align 7
__vec_09:
    b       do_irq                              // First level interrupt handler
    wfi
    b __vec_09

    .align 7
__vec_10:
    mov     x18, #0xb0bb
    wfi
    b __vec_10

    .align 7
__vec_11:
    mov     x18, #0xb0bc
    wfi
    b __vec_11

    .align 7
__vec_12:
    mov     x18, #0xb0bd
    wfi
    b __vec_12

    .align 7
__vec_13:
    mov     x18, #0xb0be
    wfi
    b __vec_13

    .align 7
__vec_14:
    mov     x18, #0xb0bf
    wfi
    b __vec_14

    .align 7
exception_vector_end:
