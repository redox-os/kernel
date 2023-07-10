ENTRY(kstart)
OUTPUT_FORMAT(elf32-i386)

KERNEL_OFFSET = 0xC0000000;

SECTIONS {
    . = KERNEL_OFFSET;

    . += SIZEOF_HEADERS;

    .text ALIGN(4K) : AT(ADDR(.text) - KERNEL_OFFSET) {
        __text_start = .;
        *(.text*)
        __usercopy_start = .;
        *(.usercopy-fns)
        __usercopy_end = .;
    }

    .rodata ALIGN(4K) : AT(ADDR(.rodata) - KERNEL_OFFSET) {
        __text_end = .;
        __rodata_start = .;
        *(.rodata*)
    }

    .data ALIGN(4K) : AT(ADDR(.data) - KERNEL_OFFSET) {
        __rodata_end = .;
        __data_start = .;
        *(.data*)
        . = ALIGN(4K);
        __data_end = .;
        __bss_start = .;
        *(.bss*)
        . = ALIGN(4K);
    }

    .tdata ALIGN(4K) : AT(ADDR(.tdata) - KERNEL_OFFSET) {
        __bss_end = .;
        __tdata_start = .;
        *(.tdata*)
        . = ALIGN(4K);
        __tdata_end = .;
        __tbss_start = .;
        *(.tbss*)
        . += 8;
        . = ALIGN(4K);
        __tbss_end = .;
    }

    __end = .;

    /DISCARD/ : {
        *(.comment*)
        *(.eh_frame*)
        *(.gcc_except_table*)
        *(.note*)
        *(.rel.eh_frame*)
    }
}
