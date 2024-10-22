use core::{
    arch::asm,
    slice,
    sync::atomic::{AtomicU32, AtomicUsize, Ordering},
};
use fdt::Fdt;
use log::info;

use crate::{
    allocator,
    memory::Frame,
    paging::{PhysicalAddress, PAGE_SIZE},
};

use crate::{
    arch::{device::serial::init_early, interrupt, paging},
    device,
    startup::memory::{register_bootloader_areas, register_memory_region, BootloaderMemoryKind},
};

#[cfg(feature = "graphical_debug")]
use crate::devices::graphical_debug;
use crate::dtb::register_dev_memory_ranges;

/// Test of zero values in BSS.
static mut BSS_TEST_ZERO: usize = 0;
/// Test of non-zero values in data.
static mut DATA_TEST_NONZERO: usize = 0xFFFF_FFFF_FFFF_FFFF;

pub static KERNEL_BASE: AtomicUsize = AtomicUsize::new(0);
pub static KERNEL_SIZE: AtomicUsize = AtomicUsize::new(0);
pub static CPU_COUNT: AtomicU32 = AtomicU32::new(0);
pub static BOOT_HART_ID: AtomicUsize = AtomicUsize::new(0);

#[repr(packed)]
pub struct KernelArgs {
    kernel_base: usize,
    kernel_size: usize,
    stack_base: usize,
    stack_size: usize,
    env_base: usize,
    env_size: usize,
    acpi_base: usize,
    acpi_size: usize,
    areas_base: usize,
    areas_size: usize,

    /// The physical base 64-bit pointer to the contiguous bootstrap/initfs.
    bootstrap_base: usize,
    /// Size of contiguous bootstrap/initfs physical region, not necessarily page aligned.
    bootstrap_size: usize,
}

fn get_boot_hart_id(env: &[u8]) -> Option<usize> {
    for line in core::str::from_utf8(env).unwrap_or("").lines() {
        let mut parts = line.splitn(2, '=');
        let name = parts.next().unwrap_or("");
        let value = parts.next().unwrap_or("");

        if name == "BOOT_HART_ID" {
            return usize::from_str_radix(value, 16).ok();
        }
    }
    None
}

/// The entry to Rust, all things must be initialized
#[no_mangle]
pub unsafe extern "C" fn kstart(args_ptr: *const KernelArgs) -> ! {
    asm!(
        "mv tp, x0", // reset percpu until it is initialized
        "csrw sscratch, tp",
        "sd x0, -16(fp)", // and stop frame walker here
        "sd x0, -8(fp)",
    );

    let bootstrap = {
        let args = &*args_ptr;

        // BSS should already be zero
        {
            assert_eq!(BSS_TEST_ZERO, 0);
            assert_eq!(DATA_TEST_NONZERO, 0xFFFF_FFFF_FFFF_FFFF);
        }

        KERNEL_BASE.store(args.kernel_base, Ordering::SeqCst);
        KERNEL_SIZE.store(args.kernel_size, Ordering::SeqCst);

        let env = slice::from_raw_parts(
            (crate::PHYS_OFFSET + args.env_base) as *const u8,
            args.env_size,
        );

        let dtb_data = if args.acpi_base != 0 {
            Some((crate::PHYS_OFFSET + args.acpi_base, args.acpi_size))
        } else {
            None
        };
        let dtb = dtb_data
            .map(|(base, size)| unsafe { slice::from_raw_parts(base as *const u8, size) })
            .and_then(|data| Fdt::new(data).ok());

        #[cfg(feature = "graphical_debug")]
        graphical_debug::init(env);

        #[cfg(feature = "serial_debug")]
        if let Some(dtb) = &dtb {
            init_early(dtb);
        }

        // Initialize logger
        crate::log::init_logger(|r| {
            use core::fmt::Write;
            let _ = write!(
                crate::debug::Writer::new(),
                "{}:{} -- {}\n",
                r.target(),
                r.level(),
                r.args()
            );
        });
        ::log::set_max_level(::log::LevelFilter::Debug);

        info!("Redox OS starting...");
        info!(
            "Kernel: {:X}:{:X}",
            { args.kernel_base },
            args.kernel_base + args.kernel_size
        );
        info!(
            "Stack: {:X}:{:X}",
            { args.stack_base },
            args.stack_base + args.stack_size
        );
        info!(
            "Env: {:X}:{:X}",
            { args.env_base },
            args.env_base + args.env_size
        );
        info!(
            "RSDPs: {:X}:{:X}",
            { args.acpi_size },
            args.acpi_size + args.acpi_size
        );
        info!(
            "Areas: {:X}:{:X}",
            { args.areas_base },
            args.areas_base + args.areas_size
        );
        info!(
            "Bootstrap: {:X}:{:X}",
            { args.bootstrap_base },
            args.bootstrap_base + args.bootstrap_size
        );

        if let Some(dtb) = &dtb {
            device::dump_fdt(&dtb);
        }

        interrupt::init();

        let bootstrap = crate::Bootstrap {
            base: Frame::containing(PhysicalAddress::new(args.bootstrap_base)),
            page_count: args.bootstrap_size / PAGE_SIZE,
            env,
        };

        // Initialize RMM
        register_bootloader_areas(args.areas_base, args.areas_size);
        if let Some(dt) = &dtb {
            register_dev_memory_ranges(dt);
        }

        register_memory_region(
            args.kernel_base,
            args.kernel_size,
            BootloaderMemoryKind::Kernel,
        );
        register_memory_region(
            args.stack_base,
            args.stack_size,
            BootloaderMemoryKind::IdentityMap,
        );
        register_memory_region(
            args.env_base,
            args.env_size,
            BootloaderMemoryKind::IdentityMap,
        );
        register_memory_region(
            args.acpi_base,
            args.acpi_size,
            BootloaderMemoryKind::IdentityMap,
        );
        register_memory_region(
            args.bootstrap_base,
            args.bootstrap_size,
            BootloaderMemoryKind::IdentityMap,
        );

        crate::startup::memory::init(None, None);

        let boot_hart_id = get_boot_hart_id(env).expect("Didn't get boot HART id from bootloader");
        info!("Booting on HART {}", boot_hart_id);
        BOOT_HART_ID.store(boot_hart_id, Ordering::Relaxed);

        paging::init();

        crate::misc::init(crate::cpu_set::LogicalCpuId::new(0));

        CPU_COUNT.store(1, Ordering::SeqCst);

        // Setup kernel heap
        allocator::init();

        // Activate memory logging
        crate::log::init();

        crate::dtb::init(dtb_data);

        // Initialize devices
        device::init();

        // Initialize all of the non-core devices not otherwise needed to complete initialization
        device::init_noncore();

        // FIXME bringup AP HARTs

        bootstrap
    };

    crate::kmain(CPU_COUNT.load(Ordering::SeqCst), bootstrap);
}
