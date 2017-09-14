/// This function is where the kernel sets up IRQ handlers
/// It is increcibly unsafe, and should be minimal in nature
/// It must create the IDT with the correct entries, those entries are
/// defined in other files inside of the `arch` module

use core::sync::atomic::{AtomicBool, ATOMIC_BOOL_INIT, AtomicUsize, ATOMIC_USIZE_INIT, Ordering};

use acpi;
use allocator;
use device;
use gdt;
use idt;
use interrupt;
use memory;
use paging::{self, entry, Page, VirtualAddress};
use paging::mapper::MapperFlushAll;

/// Test of zero values in BSS.
static BSS_TEST_ZERO: usize = 0;
/// Test of non-zero values in data.
static DATA_TEST_NONZERO: usize = 0xFFFFFFFFFFFFFFFF;
/// Test of zero values in thread BSS
#[thread_local]
static mut TBSS_TEST_ZERO: usize = 0;
/// Test of non-zero values in thread data.
#[thread_local]
static mut TDATA_TEST_NONZERO: usize = 0xFFFFFFFFFFFFFFFF;

pub static KERNEL_BASE: AtomicUsize = ATOMIC_USIZE_INIT;
pub static KERNEL_SIZE: AtomicUsize = ATOMIC_USIZE_INIT;
pub static CPU_COUNT: AtomicUsize = ATOMIC_USIZE_INIT;
pub static AP_READY: AtomicBool = ATOMIC_BOOL_INIT;
static BSP_READY: AtomicBool = ATOMIC_BOOL_INIT;

extern {
    /// Kernel main function
    fn kmain(cpus: usize) -> !;
    /// Kernel main for APs
    fn kmain_ap(id: usize) -> !;
}

/// The entry to Rust, all things must be initialized
#[no_mangle]
pub unsafe extern fn kstart(kernel_base: usize, kernel_size: usize, stack_base: usize, stack_size: usize) -> ! {
    {
        // BSS should already be zero
        {
            assert_eq!(BSS_TEST_ZERO, 0);
            assert_eq!(DATA_TEST_NONZERO, 0xFFFFFFFFFFFFFFFF);
        }

        KERNEL_BASE.store(kernel_base, Ordering::SeqCst);
        KERNEL_SIZE.store(kernel_size, Ordering::SeqCst);

        println!("Kernel: {:X}:{:X}", kernel_base, kernel_base + kernel_size);
        println!("Stack: {:X}:{:X}", stack_base, stack_base + stack_size);

        // Initialize memory management
        memory::init(0, kernel_base + ((kernel_size + 4095)/4096) * 4096);

        // Initialize paging
        let (mut active_table, tcb_offset) = paging::init(0, kernel_base, kernel_base + kernel_size, stack_base, stack_base + stack_size);

        // Set up GDT
        gdt::init(tcb_offset, stack_base + stack_size);

        // Set up IDT
        idt::init();

        // Test tdata and tbss
        {
            assert_eq!(TBSS_TEST_ZERO, 0);
            TBSS_TEST_ZERO += 1;
            assert_eq!(TBSS_TEST_ZERO, 1);
            assert_eq!(TDATA_TEST_NONZERO, 0xFFFFFFFFFFFFFFFF);
            TDATA_TEST_NONZERO -= 1;
            assert_eq!(TDATA_TEST_NONZERO, 0xFFFFFFFFFFFFFFFE);
        }

        // Reset AP variables
        CPU_COUNT.store(1, Ordering::SeqCst);
        AP_READY.store(false, Ordering::SeqCst);
        BSP_READY.store(false, Ordering::SeqCst);

        // Setup kernel heap
        {
            let mut flush_all = MapperFlushAll::new();

            // Map heap pages
            let heap_start_page = Page::containing_address(VirtualAddress::new(::KERNEL_HEAP_OFFSET));
            let heap_end_page = Page::containing_address(VirtualAddress::new(::KERNEL_HEAP_OFFSET + ::KERNEL_HEAP_SIZE-1));
            for page in Page::range_inclusive(heap_start_page, heap_end_page) {
                let result = active_table.map(page, entry::PRESENT | entry::GLOBAL | entry::WRITABLE | entry::NO_EXECUTE);
                flush_all.consume(result);
            }

            flush_all.flush(&mut active_table);

            // Init the allocator
            allocator::init(::KERNEL_HEAP_OFFSET, ::KERNEL_HEAP_SIZE);
        }

        // Initialize devices
        device::init(&mut active_table);

        // Read ACPI tables, starts APs
        acpi::init(&mut active_table);

        // Initialize all of the non-core devices not otherwise needed to complete initialization
        device::init_noncore();

        // Initialize memory functions after core has loaded
        memory::init_noncore();

        BSP_READY.store(true, Ordering::SeqCst);
    }

    kmain(CPU_COUNT.load(Ordering::SeqCst));
}

/// Entry to rust for an AP
pub unsafe extern fn kstart_ap(cpu_id: usize, bsp_table: usize, stack_start: usize, stack_end: usize) -> ! {
    {
        assert_eq!(BSS_TEST_ZERO, 0);
        assert_eq!(DATA_TEST_NONZERO, 0xFFFFFFFFFFFFFFFF);

        // Initialize paging
        let tcb_offset = paging::init_ap(cpu_id, bsp_table, stack_start, stack_end);

        // Set up GDT for AP
        gdt::init(tcb_offset, stack_end);

        // Set up IDT for AP
        idt::init();

        // Test tdata and tbss
        {
            assert_eq!(TBSS_TEST_ZERO, 0);
            TBSS_TEST_ZERO += 1;
            assert_eq!(TBSS_TEST_ZERO, 1);
            assert_eq!(TDATA_TEST_NONZERO, 0xFFFFFFFFFFFFFFFF);
            TDATA_TEST_NONZERO -= 1;
            assert_eq!(TDATA_TEST_NONZERO, 0xFFFFFFFFFFFFFFFE);
        }

        // Initialize devices (for AP)
        device::init_ap();

        AP_READY.store(true, Ordering::SeqCst);
    }

    while ! BSP_READY.load(Ordering::SeqCst) {
        interrupt::pause();
    }

    kmain_ap(cpu_id);
}

pub unsafe fn usermode(ip: usize, sp: usize, arg: usize) -> ! {
    // Go to usermode
    asm!("mov ds, r10d
        mov es, r10d
        mov fs, r11d
        mov gs, r10d
        push r10
        push r12
        push r13
        push r14
        push r15
        iretq"
        : // No output because it never returns
        :   "{r10}"(gdt::GDT_USER_DATA << 3 | 3), // Data segment
            "{r11}"(gdt::GDT_USER_TLS << 3 | 3), // TLS segment
            "{r12}"(sp), // Stack pointer
            "{r13}"(0 << 12 | 1 << 9), // Flags - Set IOPL and interrupt enable flag
            "{r14}"(gdt::GDT_USER_CODE << 3 | 3), // Code segment
            "{r15}"(ip) // IP
            "{rdi}"(arg) // Argument
        : // No clobers because it never returns
        : "intel", "volatile");
    unreachable!();
}
