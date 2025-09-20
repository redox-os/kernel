//! This function is where the kernel sets up IRQ handlers
//! It is increcibly unsafe, and should be minimal in nature
//! It must create the IDT with the correct entries, those entries are
//! defined in other files inside of the `arch` module
use core::{
    cell::SyncUnsafeCell,
    hint,
    sync::atomic::{AtomicBool, Ordering},
};

#[cfg(feature = "acpi")]
use crate::acpi;

use crate::{
    allocator,
    cpu_set::LogicalCpuId,
    device,
    devices::graphical_debug,
    gdt, idt, interrupt,
    paging::{self, PhysicalAddress, RmmA, RmmArch, TableKind},
    startup::KernelArgs,
};

/// Test of zero values in BSS.
static BSS_TEST_ZERO: SyncUnsafeCell<usize> = SyncUnsafeCell::new(0);
/// Test of non-zero values in data.
static DATA_TEST_NONZERO: SyncUnsafeCell<usize> = SyncUnsafeCell::new(usize::max_value());

pub static AP_READY: AtomicBool = AtomicBool::new(false);
static BSP_READY: AtomicBool = AtomicBool::new(false);

/// The entry to Rust, all things must be initialized
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kstart(args_ptr: *const KernelArgs) -> ! {
    unsafe {
        let bootstrap = {
            let args = args_ptr.read();

            // BSS should already be zero
            {
                assert_eq!(BSS_TEST_ZERO.get().read(), 0);
                assert_eq!(DATA_TEST_NONZERO.get().read(), usize::max_value());
            }

            // Set up serial debug
            device::serial::init();

            // Set up graphical debug
            graphical_debug::init(args.env());

            info!("Redox OS starting...");
            args.print();

            // Set up GDT
            gdt::init_bsp(args.stack_base as usize + args.stack_size as usize);

            // Set up IDT
            idt::init_bsp();

            // Initialize RMM
            #[cfg(target_arch = "x86")]
            crate::startup::memory::init(&args, Some(0x100000), Some(0x40000000));
            #[cfg(target_arch = "x86_64")]
            crate::startup::memory::init(&args, Some(0x100000), None);

            // Initialize paging
            paging::init();

            #[cfg(target_arch = "x86_64")]
            crate::alternative::early_init(true);

            // Set up syscall instruction
            interrupt::syscall::init();

            // Reset AP variables
            AP_READY.store(false, Ordering::SeqCst);
            BSP_READY.store(false, Ordering::SeqCst);

            // Setup kernel heap
            allocator::init();

            #[cfg(all(target_arch = "x86_64", feature = "profiling"))]
            crate::profiling::init();

            // Activate memory logging
            crate::log::init();

            // Initialize miscellaneous processor features
            #[cfg(target_arch = "x86_64")]
            crate::misc::init(LogicalCpuId::BSP);

            // Initialize devices
            device::init();

            // Read ACPI tables, starts APs
            #[cfg(feature = "acpi")]
            {
                acpi::init(args.acpi_rsdp());
                device::init_after_acpi();
            }

            // Initialize all of the non-core devices not otherwise needed to complete initialization
            device::init_noncore();

            BSP_READY.store(true, Ordering::SeqCst);

            args.bootstrap()
        };

        crate::kmain(bootstrap);
    }
}

pub struct KernelArgsAp {
    pub cpu_id: LogicalCpuId,
    pub page_table: usize,
    pub pcr_ptr: *mut gdt::ProcessorControlRegion,
    pub idt_ptr: *mut idt::Idt,
}

/// Entry to rust for an AP
pub unsafe extern "C" fn kstart_ap(args_ptr: *const KernelArgsAp) -> ! {
    unsafe {
        let cpu_id = {
            let args = &*args_ptr;
            assert_eq!(BSS_TEST_ZERO.get().read(), 0);
            assert_eq!(DATA_TEST_NONZERO.get().read(), usize::max_value());

            // Set up GDT
            gdt::install_pcr(args.pcr_ptr);

            // Set up IDT
            idt::install_idt(args.idt_ptr);

            // Initialize paging
            RmmA::set_table(TableKind::Kernel, PhysicalAddress::new(args.page_table));
            paging::init();

            #[cfg(all(target_arch = "x86_64", feature = "profiling"))]
            crate::profiling::init();

            #[cfg(target_arch = "x86_64")]
            crate::alternative::early_init(false);

            // Set up syscall instruction
            interrupt::syscall::init();

            // Initialize miscellaneous processor features
            #[cfg(target_arch = "x86_64")]
            crate::misc::init(args.cpu_id);

            // Initialize devices (for AP)
            device::init_ap();

            AP_READY.store(true, Ordering::SeqCst);

            args.cpu_id
        };

        while !BSP_READY.load(Ordering::SeqCst) {
            hint::spin_loop();
        }

        crate::kmain_ap(cpu_id);
    }
}
