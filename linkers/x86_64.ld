ENTRY(kstart)
OUTPUT_FORMAT(elf64-x86-64)

KERNEL_OFFSET = 0xFFFFFFFF80000000;

SECTIONS {
    . = KERNEL_OFFSET;

    . += SIZEOF_HEADERS;

    /* Force the zero page to be part of a segment by creating a
     * dummy section in the zero page.
     * Limine will map the segment with the lowest vaddr value at
     * 0xFFFFFFFF80000000 even if the segment has a higher vaddr.
     * As such without the zero page being part of a segment, the
     * kernel would be loaded at an offset from the expected
     * location. As the redox kernel is not currently relocatable,
     * this would result in a crash. A similar issue likely exists
     * with multiboot/multiboot2 and the paddr of the segment.
     */
    .dummy : AT(ADDR(.dummy) - KERNEL_OFFSET) {}

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
        __altcode_start = .;
        KEEP(*(.altcode*))
        __altcode_end = .;
        . = ALIGN(8);
        __altrelocs_start = .;
        KEEP(*(.altrelocs*))
        __altrelocs_end = .;
        __altfeatures_start = .;
        KEEP(*(.altfeatures*))
        __altfeatures_end = .;
    }

    .data ALIGN(4K) : AT(ADDR(.data) - KERNEL_OFFSET) {
        __rodata_end = .;
        __data_start = .;
        *(.data*)
        . = ALIGN(4K);
        __data_end = .;
        __bss_start = .;
        *(.bss*)
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
