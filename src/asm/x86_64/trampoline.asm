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

    ;cr3 holds pointer to PML4
    mov edi, [trampoline.page_table]
    mov cr3, edi

    ; Enable FPU
    mov eax, cr0
    and al, 11110011b ; Clear task switched (3) and emulation (2)
    or al, 00100010b ; Set numeric error (5) monitor co-processor (1)
    mov cr0, eax

    ; 18: Enable OSXSAVE
    ; 10: Unmasked SSE exceptions
    ; 9: FXSAVE/FXRSTOR
    ; 7: Page Global
    ; 5: Page Address Extension
    ; 4: Page Size Extension
    mov eax, cr4
    or eax, 1 << 18 | 1 << 10 | 1 << 9 | 1 << 7 | 1 << 5 | 1 << 4
    mov cr4, eax

    ; initialize floating point registers
    fninit

    ; load protected mode GDT
    lgdt [gdtr]

    mov ecx, 0xC0000080               ; Read from the EFER MSR.
    rdmsr
    or eax, 1 << 11 | 1 << 8          ; Set the Long-Mode-Enable and NXE bit.
    wrmsr

    ;enabling paging and protection simultaneously
    mov ebx, cr0
    ; 31: Paging
    ; 16: write protect kernel
    ; 0: Protected Mode
    or ebx, 1 << 31 | 1 << 16 | 1
    mov cr0, ebx

    ; far jump to enable Long Mode and load CS with 64 bit segment
    jmp gdt.kernel_code:long_mode_ap

USE64
long_mode_ap:
    mov rax, gdt.kernel_data
    mov ds, rax
    mov es, rax
    mov fs, rax
    mov gs, rax
    mov ss, rax

    mov rcx, [trampoline.stack_end]
    lea rsp, [rcx - 256]

    mov rdi, trampoline.cpu_id

    mov rax, [trampoline.code]
    mov qword [trampoline.ready], 1
    jmp rax

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
    at GDTEntry.limitl, dw 0
    at GDTEntry.basel, dw 0
    at GDTEntry.basem, db 0
    at GDTEntry.attribute, db attrib.present | attrib.user | attrib.code
    at GDTEntry.flags__limith, db flags.long_mode
    at GDTEntry.baseh, db 0
iend

.kernel_data equ $ - gdt
istruc GDTEntry
    at GDTEntry.limitl, dw 0
    at GDTEntry.basel, dw 0
    at GDTEntry.basem, db 0
; AMD System Programming Manual states that the writeable bit is ignored in long mode, but ss can not be set to this descriptor without it
    at GDTEntry.attribute, db attrib.present | attrib.user | attrib.writable
    at GDTEntry.flags__limith, db 0
    at GDTEntry.baseh, db 0
iend

.end equ $ - gdt
