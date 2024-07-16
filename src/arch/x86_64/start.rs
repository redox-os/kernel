/// This function is where the kernel sets up IRQ handlers
/// It is increcibly unsafe, and should be minimal in nature
/// It must create the IDT with the correct entries, those entries are
/// defined in other files inside of the `arch` module
use core::slice;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use log::info;

#[cfg(feature = "acpi")]
use crate::acpi;

#[cfg(feature = "graphical_debug")]
use crate::devices::graphical_debug;
use crate::{
    allocator,
    cpu_set::LogicalCpuId,
    device, gdt, idt, interrupt, misc,
    paging::{self, PhysicalAddress, RmmA, RmmArch, TableKind},
    startup::memory::{register_bootloader_areas, register_memory_region, BootloaderMemoryKind},
};

/// Test of zero values in BSS.
static mut BSS_TEST_ZERO: usize = 0;
/// Test of non-zero values in data.
static mut DATA_TEST_NONZERO: usize = usize::max_value();

pub static KERNEL_BASE: AtomicUsize = AtomicUsize::new(0);
pub static KERNEL_SIZE: AtomicUsize = AtomicUsize::new(0);

// TODO: This probably shouldn't be an atomic. Only the BSP starts APs.
pub static CPU_COUNT: AtomicU32 = AtomicU32::new(0);

pub static AP_READY: AtomicBool = AtomicBool::new(false);
static BSP_READY: AtomicBool = AtomicBool::new(false);

#[repr(C, packed(8))]
pub struct KernelArgs {
    kernel_base: u64,
    kernel_size: u64,
    stack_base: u64,
    stack_size: u64,
    env_base: u64,
    env_size: u64,

    /// The base pointer to the saved RSDP.
    ///
    /// This field can be NULL, and if so, the system has not booted with UEFI or in some other way
    /// retrieved the RSDPs. The kernel or a userspace driver will thus try searching the BIOS
    /// memory instead. On UEFI systems, searching is not guaranteed to actually work though.
    acpi_rsdp_base: u64,
    /// The size of the RSDP region.
    acpi_rsdp_size: u64,

    areas_base: u64,
    areas_size: u64,

    /// The physical base 64-bit pointer to the contiguous bootstrap/initfs.
    bootstrap_base: u64,
    /// Size of contiguous bootstrap/initfs physical region, not necessarily page aligned.
    bootstrap_size: u64,
}

/// The entry to Rust, all things must be initialized
#[no_mangle]
pub unsafe extern "C" fn kstart(args_ptr: *const KernelArgs) -> ! {
    let bootstrap = {
        let args = args_ptr.read();

        // BSS should already be zero
        {
            assert_eq!(BSS_TEST_ZERO, 0);
            assert_eq!(DATA_TEST_NONZERO, usize::max_value());
        }

        KERNEL_BASE.store(args.kernel_base as usize, Ordering::SeqCst);
        KERNEL_SIZE.store(args.kernel_size as usize, Ordering::SeqCst);

        // Convert env to slice
        let env = slice::from_raw_parts(
            (args.env_base as usize + crate::PHYS_OFFSET) as *const u8,
            args.env_size as usize,
        );

        // Set up graphical debug
        #[cfg(feature = "graphical_debug")]
        graphical_debug::init(env);

        #[cfg(feature = "system76_ec_debug")]
        device::system76_ec::init();

        // Initialize logger
        crate::log::init_logger(|r| {
            use core::fmt::Write;
            let _ = writeln!(
                super::debug::Writer::new(),
                "{}:{} -- {}",
                r.target(),
                r.level(),
                r.args()
            );
        });

        info!("Redox OS starting...");
        info!(
            "Kernel: {:X}:{:X}",
            { args.kernel_base },
            { args.kernel_base } + { args.kernel_size }
        );
        info!(
            "Stack: {:X}:{:X}",
            { args.stack_base },
            { args.stack_base } + { args.stack_size }
        );
        info!(
            "Env: {:X}:{:X}",
            { args.env_base },
            { args.env_base } + { args.env_size }
        );
        info!(
            "RSDP: {:X}:{:X}",
            { args.acpi_rsdp_base },
            { args.acpi_rsdp_base } + { args.acpi_rsdp_size }
        );
        info!(
            "Areas: {:X}:{:X}",
            { args.areas_base },
            { args.areas_base } + { args.areas_size }
        );
        info!(
            "Bootstrap: {:X}:{:X}",
            { args.bootstrap_base },
            { args.bootstrap_base } + { args.bootstrap_size }
        );

        // Set up GDT before paging
        gdt::init();

        // Set up IDT before paging
        idt::init();

        // Initialize RMM
        register_bootloader_areas(args.areas_base as usize, args.areas_size as usize);
        register_memory_region(
            args.kernel_base as usize,
            args.kernel_size as usize,
            BootloaderMemoryKind::Kernel,
        );
        register_memory_region(
            args.stack_base as usize,
            args.stack_size as usize,
            BootloaderMemoryKind::IdentityMap,
        );
        register_memory_region(
            args.env_base as usize,
            args.env_size as usize,
            BootloaderMemoryKind::IdentityMap,
        );
        register_memory_region(
            args.acpi_rsdp_base as usize,
            args.acpi_rsdp_size as usize,
            BootloaderMemoryKind::IdentityMap,
        );
        register_memory_region(
            args.bootstrap_base as usize,
            args.bootstrap_size as usize,
            BootloaderMemoryKind::IdentityMap,
        );
        crate::startup::memory::init(Some(0x100000), None);

        // Initialize PAT
        paging::init();

        // Set up GDT after paging with TLS
        gdt::init_paging(
            args.stack_base as usize + args.stack_size as usize,
            LogicalCpuId::BSP,
        );

        // Set up IDT
        idt::init_paging_bsp();

        crate::alternative::early_init(true);

        // Set up syscall instruction
        interrupt::syscall::init();

        // Reset AP variables
        CPU_COUNT.store(1, Ordering::SeqCst);
        AP_READY.store(false, Ordering::SeqCst);
        BSP_READY.store(false, Ordering::SeqCst);

        // Setup kernel heap
        allocator::init();

        #[cfg(feature = "profiling")]
        crate::profiling::init();

        // Set up double buffer for graphical debug now that heap is available
        #[cfg(feature = "graphical_debug")]
        graphical_debug::init_heap();

        idt::init_paging_post_heap(LogicalCpuId::BSP);

        // Activate memory logging
        crate::log::init();

        // Initialize miscellaneous processor features
        misc::init(LogicalCpuId::BSP);

        // Initialize devices
        device::init();

        // Read ACPI tables, starts APs
        #[cfg(feature = "acpi")]
        {
            acpi::init(if args.acpi_rsdp_base != 0 {
                Some((args.acpi_rsdp_base as usize + crate::PHYS_OFFSET) as *const u8)
            } else {
                None
            });
            device::init_after_acpi();
        }

        // Initialize all of the non-core devices not otherwise needed to complete initialization
        device::init_noncore();

        BSP_READY.store(true, Ordering::SeqCst);

        crate::Bootstrap {
            base: crate::memory::Frame::containing(crate::paging::PhysicalAddress::new(
                args.bootstrap_base as usize,
            )),
            page_count: (args.bootstrap_size as usize) / crate::memory::PAGE_SIZE,
            env,
        }
    };

    crate::kmain(CPU_COUNT.load(Ordering::SeqCst), bootstrap);
}

#[repr(C, packed)]
pub struct KernelArgsAp {
    // TODO: u32?
    cpu_id: u64,

    page_table: u64,
    stack_start: u64,
    stack_end: u64,
}

/// Entry to rust for an AP
pub unsafe extern "C" fn kstart_ap(args_ptr: *const KernelArgsAp) -> ! {
    let cpu_id = {
        let args = &*args_ptr;
        let cpu_id = LogicalCpuId::new(args.cpu_id as u32);
        let bsp_table = args.page_table as usize;
        let _stack_start = args.stack_start as usize;
        let stack_end = args.stack_end as usize;

        assert_eq!(BSS_TEST_ZERO, 0);
        assert_eq!(DATA_TEST_NONZERO, usize::max_value());

        // Set up GDT before paging
        gdt::init();

        // Set up IDT before paging
        idt::init();

        // Initialize paging
        RmmA::set_table(TableKind::Kernel, PhysicalAddress::new(bsp_table));
        paging::init();

        // Set up GDT with TLS
        gdt::init_paging(stack_end, cpu_id);

        #[cfg(feature = "profiling")]
        crate::profiling::init();

        // Set up IDT for AP
        idt::init_paging_post_heap(cpu_id);

        crate::alternative::early_init(false);

        // Set up syscall instruction
        interrupt::syscall::init();

        // Initialize miscellaneous processor features
        misc::init(cpu_id);

        // Initialize devices (for AP)
        device::init_ap();

        AP_READY.store(true, Ordering::SeqCst);

        cpu_id
    };

    while !BSP_READY.load(Ordering::SeqCst) {
        interrupt::pause();
    }

    crate::kmain_ap(cpu_id);
}
