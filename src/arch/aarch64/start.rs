//! This function is where the kernel sets up IRQ handlers
//! It is increcibly unsafe, and should be minimal in nature
//! It must create the IDT with the correct entries, those entries are
//! defined in other files inside of the `arch` module
use core::{
    slice,
    sync::atomic::{AtomicBool, Ordering},
};

use fdt::Fdt;

use crate::{
    allocator, arch::interrupt, device, devices::graphical_debug, dtb, paging, startup::KernelArgs,
};

/// Test of zero values in BSS.
static mut BSS_TEST_ZERO: usize = 0;
/// Test of non-zero values in data.
static mut DATA_TEST_NONZERO: usize = 0xFFFF_FFFF_FFFF_FFFF;

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
                assert_eq!(BSS_TEST_ZERO, 0);
                assert_eq!(DATA_TEST_NONZERO, 0xFFFF_FFFF_FFFF_FFFF);
            }

            // Set up graphical debug
            graphical_debug::init(args.env());

            // Get hardware descriptor data
            //TODO: use env {DTB,RSDT}_{BASE,SIZE}?
            let hwdesc_data = if args.hwdesc_base != 0 {
                Some(unsafe {
                    slice::from_raw_parts(
                        (crate::PHYS_OFFSET + args.hwdesc_base as usize) as *const u8,
                        args.hwdesc_size as usize,
                    )
                })
            } else {
                None
            };

            let dtb_res = hwdesc_data
                .ok_or(fdt::FdtError::BadPtr)
                .and_then(|data| Fdt::new(data));

            // Try to find serial port prior to logging
            if let Ok(dtb) = &dtb_res {
                device::serial::init_early(dtb);
            }

            info!("Redox OS starting...");
            args.print();

            interrupt::init();

            // Initialize RMM
            crate::startup::memory::init(&args, None, None);

            // Initialize paging
            paging::init();

            crate::misc::init(crate::cpu_set::LogicalCpuId::new(0));

            // Reset AP variables
            AP_READY.store(false, Ordering::SeqCst);
            BSP_READY.store(false, Ordering::SeqCst);

            // Setup kernel heap
            allocator::init();

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
                    warn!("failed to parse DTB: {}", err);

                    #[cfg(feature = "acpi")]
                    {
                        crate::acpi::init(args.acpi_rsdp());
                    }
                }
            }

            BSP_READY.store(true, Ordering::SeqCst);

            args.bootstrap()
        };

        crate::kmain(bootstrap);
    }
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
