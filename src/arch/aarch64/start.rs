/// This function is where the kernel sets up IRQ handlers
/// It is increcibly unsafe, and should be minimal in nature
/// It must create the IDT with the correct entries, those entries are
/// defined in other files inside of the `arch` module
use core::slice;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

#[cfg(feature = "graphical_debug")]
use crate::devices::graphical_debug;

use fdt::Fdt;
use log::info;

use crate::{
    allocator, device, dtb,
    dtb::register_dev_memory_ranges,
    paging,
    startup::memory::{register_bootloader_areas, register_memory_region, BootloaderMemoryKind},
};

/// Test of zero values in BSS.
static mut BSS_TEST_ZERO: usize = 0;
/// Test of non-zero values in data.
static mut DATA_TEST_NONZERO: usize = 0xFFFF_FFFF_FFFF_FFFF;

pub static KERNEL_BASE: AtomicUsize = AtomicUsize::new(0);
pub static KERNEL_SIZE: AtomicUsize = AtomicUsize::new(0);
pub static CPU_COUNT: AtomicU32 = AtomicU32::new(0);
pub static AP_READY: AtomicBool = AtomicBool::new(false);
static BSP_READY: AtomicBool = AtomicBool::new(false);

#[derive(Debug)]
#[repr(C, packed(8))]
pub struct KernelArgs {
    kernel_base: usize,
    kernel_size: usize,
    stack_base: usize,
    stack_size: usize,
    env_base: usize,
    env_size: usize,
    hwdesc_base: usize,
    hwdesc_size: usize,
    areas_base: usize,
    areas_size: usize,

    /// The physical base 64-bit pointer to the contiguous bootstrap/initfs.
    bootstrap_base: usize,
    /// Size of contiguous bootstrap/initfs physical region, not necessarily page aligned.
    bootstrap_size: usize,
}

/// The entry to Rust, all things must be initialized
#[no_mangle]
pub unsafe extern "C" fn kstart(args_ptr: *const KernelArgs) -> ! {
    let bootstrap = {
        let args = args_ptr.read();

        // BSS should already be zero
        {
            assert_eq!(BSS_TEST_ZERO, 0);
            assert_eq!(DATA_TEST_NONZERO, 0xFFFF_FFFF_FFFF_FFFF);
        }

        KERNEL_BASE.store(args.kernel_base, Ordering::SeqCst);
        KERNEL_SIZE.store(args.kernel_size, Ordering::SeqCst);

        // Convert env to slice
        let env = slice::from_raw_parts(
            (crate::PHYS_OFFSET + args.env_base) as *const u8,
            args.env_size,
        );

        // Set up graphical debug
        #[cfg(feature = "graphical_debug")]
        graphical_debug::init(env);

        // Get hardware descriptor data
        //TODO: use env {DTB,RSDT}_{BASE,SIZE}?
        let hwdesc_data = if args.hwdesc_base != 0 {
            Some(unsafe {
                slice::from_raw_parts(
                    (crate::PHYS_OFFSET + args.hwdesc_base) as *const u8,
                    args.hwdesc_size,
                )
            })
        } else {
            None
        };

        let dtb_res = hwdesc_data
            .ok_or(fdt::FdtError::BadPtr)
            .and_then(|data| Fdt::new(data));

        let rsdp_opt = hwdesc_data.and_then(|data| {
            if data.starts_with(b"RSD PTR ") {
                Some(data.as_ptr())
            } else {
                None
            }
        });

        // Try to find serial port prior to logging
        if let Ok(dtb) = &dtb_res {
            device::serial::init_early(dtb);
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
        log::set_max_level(::log::LevelFilter::Debug);

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
            "HWDESC: {:X}:{:X}",
            { args.hwdesc_base },
            args.hwdesc_base + args.hwdesc_size
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

        // Setup interrupt handlers
        core::arch::asm!(
            "
            ldr {tmp}, =exception_vector_base
            msr vbar_el1, {tmp}
            ",
            tmp = out(reg) _,
        );

        // Initialize RMM
        register_bootloader_areas(args.areas_base, args.areas_size);
        if let Ok(dtb) = &dtb_res {
            register_dev_memory_ranges(dtb);
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
            args.hwdesc_base,
            args.hwdesc_size,
            BootloaderMemoryKind::IdentityMap,
        );
        register_memory_region(
            args.bootstrap_base,
            args.bootstrap_size,
            BootloaderMemoryKind::IdentityMap,
        );
        crate::startup::memory::init(None, None);

        // Initialize paging
        paging::init();

        crate::misc::init(crate::cpu_set::LogicalCpuId::new(0));

        // Reset AP variables
        CPU_COUNT.store(1, Ordering::SeqCst);
        AP_READY.store(false, Ordering::SeqCst);
        BSP_READY.store(false, Ordering::SeqCst);

        // Setup kernel heap
        allocator::init();

        // Set up double buffer for graphical debug now that heap is available
        #[cfg(feature = "graphical_debug")]
        graphical_debug::init_heap();

        // Activate memory logging
        crate::log::init();

        // Initialize devices
        match dtb_res {
            Ok(dtb) => {
                dtb::init(hwdesc_data.map(|slice| (slice.as_ptr() as usize, slice.len())));
                device::init_devicetree(&dtb);
            }
            Err(err) => {
                dtb::init(None);
                log::warn!("failed to parse DTB: {}", err);

                #[cfg(feature = "acpi")]
                {
                    crate::acpi::init(rsdp_opt);
                }
            }
        }

        BSP_READY.store(true, Ordering::SeqCst);

        crate::Bootstrap {
            base: crate::memory::Frame::containing(crate::paging::PhysicalAddress::new(
                args.bootstrap_base,
            )),
            page_count: args.bootstrap_size / crate::memory::PAGE_SIZE,
            env,
        }
    };

    crate::kmain(CPU_COUNT.load(Ordering::SeqCst), bootstrap);
}

#[repr(C, packed)]
#[allow(unused)]
pub struct KernelArgsAp {
    cpu_id: u64,
    page_table: u64,
    stack_start: u64,
    stack_end: u64,
}

/// Entry to rust for an AP
#[allow(unused)]
pub unsafe extern "C" fn kstart_ap(_args_ptr: *const KernelArgsAp) -> ! {
    loop {}
}
