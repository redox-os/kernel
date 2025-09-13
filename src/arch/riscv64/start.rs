use core::{
    arch::{asm, global_asm},
    cell::SyncUnsafeCell,
    sync::atomic::{AtomicUsize, Ordering},
};

use crate::{
    allocator,
    memory::Frame,
    paging::{PhysicalAddress, PAGE_SIZE},
};

use crate::{
    arch::{device::serial::init_early, interrupt, paging},
    device,
    devices::graphical_debug,
    interrupt::exception_handler,
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

#[repr(C, align(16))]
struct StackAlign<T>(T);

static STACK: SyncUnsafeCell<StackAlign<[u8; 128 * 1024]>> =
    SyncUnsafeCell::new(StackAlign([0; 128 * 1024]));

global_asm!("
    .globl kstart
    kstart:
        mv gp, x0 // ensure gp relative accesses crash
        mv tp, x0 // reset percpu until it is initialized
        csrw sscratch, tp

        // BSS should already be zero
        ld t0, {bss_test_zero}
        bnez t0, .Lkstart_crash
        ld t0, {data_test_nonzero}
        beqz t0, .Lkstart_crash

    .Lpcrel_hi0:
        auipc   sp, %pcrel_hi({stack}+{stack_size}-16)
        addi    sp, sp, %pcrel_lo(.Lpcrel_hi0)

        la t0, {exception_handler} // WARL=0 - direct mode combined handler
        csrw stvec, t0

        li ra, 0
        j {start}

    .Lkstart_crash:
        jr x0
    ",
    bss_test_zero = sym BSS_TEST_ZERO,
    data_test_nonzero = sym DATA_TEST_NONZERO,
    exception_handler = sym exception_handler,
    stack = sym STACK,
    stack_size = const size_of_val(&STACK),
    start = sym start,
);

/// The entry to Rust, all things must be initialized
unsafe extern "C" fn start(args_ptr: *const KernelArgs) -> ! {
    unsafe {
        let bootstrap = {
            let args = args_ptr.read();

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
