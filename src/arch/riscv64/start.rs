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
    dtb::register_dev_memory_ranges,
    startup::{
        memory::{register_bootloader_areas, register_memory_region, BootloaderMemoryKind},
        KernelArgs,
    },
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
            let args = &*args_ptr;

            // BSS should already be zero
            {
                assert_eq!(BSS_TEST_ZERO, 0);
                assert_eq!(DATA_TEST_NONZERO, 0xFFFF_FFFF_FFFF_FFFF);
            }

            let env = slice::from_raw_parts(
                (crate::PHYS_OFFSET + args.env_base as usize) as *const u8,
                args.env_size as usize,
            );

            let dtb_data = if args.hwdesc_base != 0 {
                Some((
                    crate::PHYS_OFFSET + args.hwdesc_base as usize,
                    args.hwdesc_size as usize,
                ))
            } else {
                None
            };
            let dtb = dtb_data
                .map(|(base, size)| unsafe { slice::from_raw_parts(base as *const u8, size) })
                .and_then(|data| Fdt::new(data).ok());

            graphical_debug::init(env);

            if let Some(dtb) = &dtb {
                init_early(dtb);
            }

            info!("Redox OS starting...");
            args.print();

            if let Some(dtb) = &dtb {
                device::dump_fdt(&dtb);
            }

            interrupt::init();

            let bootstrap = crate::Bootstrap {
                base: Frame::containing(PhysicalAddress::new(args.bootstrap_base as usize)),
                page_count: args.bootstrap_size as usize / PAGE_SIZE,
                env,
            };

            // Initialize RMM
            register_bootloader_areas(args.areas_base as usize, args.areas_size as usize);
            if let Some(dt) = &dtb {
                register_dev_memory_ranges(dt);
            }

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
                args.hwdesc_base as usize,
                args.hwdesc_size as usize,
                BootloaderMemoryKind::IdentityMap,
            );
            register_memory_region(
                args.bootstrap_base as usize,
                args.bootstrap_size as usize,
                BootloaderMemoryKind::IdentityMap,
            );

            crate::startup::memory::init(None, None);

            let boot_hart_id =
                get_boot_hart_id(env).expect("Didn't get boot HART id from bootloader");
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

            bootstrap
        };

        crate::kmain(bootstrap);
    }
}
