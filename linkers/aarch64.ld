ENTRY(early_init)
OUTPUT_FORMAT("elf64-littleaarch64", "elf64-littleaarch64", "elf64-littleaarch64")

KERNEL_OFFSET = 0xFFFFFF0000000000;

SECTIONS {
    . = KERNEL_OFFSET;

    . += SIZEOF_HEADERS;
    . = ALIGN(4096);

    .text : AT(ADDR(.text) - KERNEL_OFFSET) {
        __text_start = .;
	*(.early_init.text*)
	. = ALIGN(4096);
        *(.text*)
	. = ALIGN(4096);
        __text_end = .;
    }

	.rodata : AT(ADDR(.rodata) - KERNEL_OFFSET) {
        __rodata_start = .;
        *(.rodata*)
	. = ALIGN(4096);
        __rodata_end = .;
    }

    .data : AT(ADDR(.data) - KERNEL_OFFSET) {
        __data_start = .;
        *(.data*)
	. = ALIGN(4096);
        __data_end = .;
        __bss_start = .;
        *(.bss*)
	. = ALIGN(4096);
        __bss_end = .;
    }

    .tdata : AT(ADDR(.tdata) - KERNEL_OFFSET) {
        __tdata_start = .;
        *(.tdata*)
	. = ALIGN(4096);
        __tdata_end = .;
        __tbss_start = .;
        *(.tbss*)
        . += 8;
	. = ALIGN(4096);
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
