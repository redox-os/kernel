use core::{
    arch::asm,
    slice,
    sync::atomic::{AtomicUsize, Ordering},
};
use fdt::Fdt;

use crate::{
    allocator,
    memory::Frame,
    paging::{PhysicalAddress, PAGE_SIZE},
};

use crate::{
    arch::{device::serial::init_early, interrupt, paging},
    device,
    devices::graphical_debug,
    startup::KernelArgs,
};

/// Test of zero values in BSS.
static mut BSS_TEST_ZERO: usize = 0;
/// Test of non-zero values in data.
static mut DATA_TEST_NONZERO: usize = 0xFFFF_FFFF_FFFF_FFFF;

pub static BOOT_HART_ID: AtomicUsize = AtomicUsize::new(0);

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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kstart(args_ptr: *const KernelArgs) -> ! {
    unsafe {
        asm!(
            "mv tp, x0", // reset percpu until it is initialized
            "csrw sscratch, tp",
            "sd x0, -16(fp)", // and stop frame walker here
            "sd x0, -8(fp)",
        );

        let bootstrap = {
            let args = args_ptr.read();

            // BSS should already be zero
            {
                assert_eq!(BSS_TEST_ZERO, 0);
                assert_eq!(DATA_TEST_NONZERO, 0xFFFF_FFFF_FFFF_FFFF);
            }

            let dtb_data = if args.hwdesc_base != 0 {
                Some((
                    crate::PHYS_OFFSET + args.hwdesc_base as usize,
                    args.hwdesc_size as usize,
                ))
            } else {
                None
            };
            let dtb = args.dtb();

            graphical_debug::init(args.env());

            if let Some(dtb) = &dtb {
                init_early(dtb);
            }

            info!("Redox OS starting...");
            args.print();

            if let Some(dtb) = &dtb {
                device::dump_fdt(&dtb);
            }

            interrupt::init();

            // Initialize RMM
            crate::startup::memory::init(&args, None, None);

            let boot_hart_id =
                get_boot_hart_id(args.env()).expect("Didn't get boot HART id from bootloader");
            info!("Booting on HART {}", boot_hart_id);
            BOOT_HART_ID.store(boot_hart_id, Ordering::Relaxed);

            paging::init();

            crate::misc::init(crate::cpu_set::LogicalCpuId::new(0));

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

            args.bootstrap()
        };

        crate::kmain(bootstrap);
    }
}
