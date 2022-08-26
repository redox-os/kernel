; trampoline for bringing up APs
; compiled with nasm by build.rs, and included in src/acpi/madt.rs

ORG 0x8000
SECTION .text
USE16

trampoline:
    jmp short startup_ap
    times 8 - ($ - trampoline) nop
    .ready: dq 0
    .cpu_id: dq 0
    .page_table: dq 0
    .stack_start: dq 0
    .stack_end: dq 0
    .code: dq 0

startup_ap:
    cli

    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax

    ; initialize stack to invalid value
    mov sp, 0

    ; cr3 holds pointer to PML4
    mov edi, [trampoline.page_table]
    mov cr3, edi

    ; enable FPU
    mov eax, cr0
    and al, 11110011b ; Clear task switched (3) and emulation (2)
    or al, 00100010b ; Set numeric error (5) monitor co-processor (1)
    mov cr0, eax

    ; 9: FXSAVE/FXRSTOR
    ; 7: Page Global
    ; 4: Page Size Extension
    mov eax, cr4
    or eax, 1 << 9 | 1 << 7 | 1 << 4
    mov cr4, eax

    ; initialize floating point registers
    fninit

    ; load protected mode GDT
    lgdt [gdtr]

    ;enabling paging and protection simultaneously
    mov ebx, cr0
    ; 31: Paging
    ; 16: write protect kernel
    ; 0: Protected Mode
    or ebx, 1 << 31 | 1 << 16 | 1
    mov cr0, ebx

    ; far jump to enable Protected Mode and load CS with 32 bit segment
    jmp gdt.kernel_code:protected_mode_ap

USE32
protected_mode_ap:
    mov eax, gdt.kernel_data
    mov ds, eax
    mov es, eax
    mov fs, eax
    mov gs, eax
    mov ss, eax

    mov eax, [trampoline.stack_end]
    lea esp, [eax - 256]

    mov eax, trampoline.cpu_id
    push eax

    mov eax, [trampoline.code]
    mov dword [trampoline.ready], 1
    call eax
.halt:
    cli
    hlt
    jmp .halt

struc GDTEntry
    .limitl resw 1
    .basel resw 1
    .basem resb 1
    .attribute resb 1
    .flags__limith resb 1
    .baseh resb 1
endstruc

attrib:
    .present              equ 1 << 7
    .ring1                equ 1 << 5
    .ring2                equ 1 << 6
    .ring3                equ 1 << 5 | 1 << 6
    .user                 equ 1 << 4
;user
    .code                 equ 1 << 3
;   code
    .conforming           equ 1 << 2
    .readable             equ 1 << 1
;   data
    .expand_down          equ 1 << 2
    .writable             equ 1 << 1
    .accessed             equ 1 << 0
;system
;   legacy
    .tssAvailabe16        equ 0x1
    .ldt                  equ 0x2
    .tssBusy16            equ 0x3
    .call16               equ 0x4
    .task                 equ 0x5
    .interrupt16          equ 0x6
    .trap16               equ 0x7
    .tssAvailabe32        equ 0x9
    .tssBusy32            equ 0xB
    .call32               equ 0xC
    .interrupt32          equ 0xE
    .trap32               equ 0xF
;   long mode
    .ldt32                equ 0x2
    .tssAvailabe64        equ 0x9
    .tssBusy64            equ 0xB
    .call64               equ 0xC
    .interrupt64          equ 0xE
    .trap64               equ 0xF

flags:
    .granularity equ 1 << 7
    .available equ 1 << 4
;user
    .default_operand_size equ 1 << 6
;   code
    .long_mode equ 1 << 5
;   data
    .reserved equ 1 << 5

gdtr:
    dw gdt.end + 1  ; size
    dq gdt          ; offset

gdt:
.null equ $ - gdt
    dq 0

.kernel_code equ $ - gdt
istruc GDTEntry
    at GDTEntry.limitl, dw 0xFFFF
    at GDTEntry.basel, dw 0
    at GDTEntry.basem, db 0
    at GDTEntry.attribute, db attrib.present | attrib.user | attrib.code | attrib.readable
    at GDTEntry.flags__limith, db 0xF | flags.granularity | flags.default_operand_size
    at GDTEntry.baseh, db 0
iend

.kernel_data equ $ - gdt
istruc GDTEntry
    at GDTEntry.limitl, dw 0xFFFF
    at GDTEntry.basel, dw 0
    at GDTEntry.basem, db 0
    at GDTEntry.attribute, db attrib.present | attrib.user | attrib.writable
    at GDTEntry.flags__limith, db 0xF | flags.granularity | flags.default_operand_size
    at GDTEntry.baseh, db 0
iend

.end equ $ - gdt
