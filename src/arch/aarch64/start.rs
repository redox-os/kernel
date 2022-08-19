/// This function is where the kernel sets up IRQ handlers
/// It is increcibly unsafe, and should be minimal in nature
/// It must create the IDT with the correct entries, those entries are
/// defined in other files inside of the `arch` module

use core::slice;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::memory::{Frame};
use crate::paging::{Page, PAGE_SIZE, PhysicalAddress, VirtualAddress};

use crate::allocator;
use crate::device;
#[cfg(feature = "graphical_debug")]
use crate::devices::graphical_debug;
use crate::init::device_tree;
use crate::interrupt;
use crate::log::{self, info};
use crate::paging::{self, KernelMapper};

/// Test of zero values in BSS.
static BSS_TEST_ZERO: usize = 0;
/// Test of non-zero values in data.
static DATA_TEST_NONZERO: usize = 0xFFFF_FFFF_FFFF_FFFF;
/// Test of zero values in thread BSS
#[thread_local]
static mut TBSS_TEST_ZERO: usize = 0;
/// Test of non-zero values in thread data.
#[thread_local]
static mut TDATA_TEST_NONZERO: usize = 0xFFFF_FFFF_FFFF_FFFF;

pub static KERNEL_BASE: AtomicUsize = AtomicUsize::new(0);
pub static KERNEL_SIZE: AtomicUsize = AtomicUsize::new(0);
pub static CPU_COUNT: AtomicUsize = AtomicUsize::new(0);
pub static AP_READY: AtomicBool = AtomicBool::new(false);
static BSP_READY: AtomicBool = AtomicBool::new(false);

#[repr(packed)]
pub struct KernelArgs {
    kernel_base: usize,
    kernel_size: usize,
    stack_base: usize,
    stack_size: usize,
    env_base: usize,
    env_size: usize,
    dtb_base: usize,
    dtb_size: usize,
    areas_base: usize,
    areas_size: usize,

    /// The physical base 64-bit pointer to the contiguous bootstrap/initfs.
    bootstrap_base: usize,
    /// Size of contiguous bootstrap/initfs physical region, not necessarily page aligned.
    bootstrap_size: usize,
    /// Entry point the kernel will jump to.
    bootstrap_entry: usize,
}

/// The entry to Rust, all things must be initialized
#[no_mangle]
pub unsafe extern fn kstart(args_ptr: *const KernelArgs) -> ! {
    let bootstrap = {
        let args = &*args_ptr;

        let kernel_base = args.kernel_base as usize;
        let kernel_size = args.kernel_size as usize;
        let stack_base = args.stack_base as usize;
        let stack_size = args.stack_size as usize;
        let env_base = args.env_base as usize;
        let env_size = args.env_size as usize;
        let dtb_base = args.dtb_base as usize;
        let dtb_size = args.dtb_size as usize;

        // BSS should already be zero
        {
            assert_eq!(BSS_TEST_ZERO, 0);
            assert_eq!(DATA_TEST_NONZERO, 0xFFFF_FFFF_FFFF_FFFF);
        }

        KERNEL_BASE.store(kernel_base, Ordering::SeqCst);
        KERNEL_SIZE.store(kernel_size, Ordering::SeqCst);

        // Try to find serial port prior to logging
        device::serial::init_early(crate::KERNEL_DEVMAP_OFFSET + dtb_base, dtb_size);

        // Convert env to slice
        let env = slice::from_raw_parts((args.env_base + crate::PHYS_OFFSET) as *const u8, args.env_size);

        // Set up graphical debug
        #[cfg(feature = "graphical_debug")]
        graphical_debug::init(env);

        // Initialize logger
        log::init_logger(|r| {
            use core::fmt::Write;
            let _ = write!(
                crate::debug::Writer::new(),
                "{}:{} -- {}\n",
                r.target(),
                r.level(),
                r.args()
            );
        });

        info!("Redox OS starting...");
        info!("Kernel: {:X}:{:X}", args.kernel_base, args.kernel_base + args.kernel_size);
        info!("Stack: {:X}:{:X}", args.stack_base, args.stack_base + args.stack_size);
        info!("Env: {:X}:{:X}", args.env_base, args.env_base + args.env_size);
        info!("RSDPs: {:X}:{:X}", args.dtb_base, args.dtb_base + args.dtb_size);
        info!("Areas: {:X}:{:X}", args.areas_base, args.areas_base + args.areas_size);
        info!("Bootstrap: {:X}:{:X}", args.bootstrap_base, args.bootstrap_base + args.bootstrap_size);
        info!("Bootstrap entry point: {:X}", args.bootstrap_entry);

        println!("FILL MEMORY MAP START");
        device_tree::fill_memory_map(crate::KERNEL_DEVMAP_OFFSET + dtb_base, dtb_size);
        println!("FILL MEMORY MAP COMPLETE");

        println!("FILL ENV DATA START");
        let env_size = device_tree::fill_env_data(crate::KERNEL_DEVMAP_OFFSET + dtb_base, dtb_size, env_base);
        println!("FILL ENV DATA COMPLETE");

        // Initialize RMM
        println!("RMM INIT START");
        crate::arch::rmm::init(
            args.kernel_base, args.kernel_size,
            args.stack_base, args.stack_size,
            args.env_base, args.env_size,
            args.dtb_base, args.dtb_size,
            args.areas_base, args.areas_size,
            args.bootstrap_base, args.bootstrap_size,
        );
        println!("RMM INIT COMPLETE");

        // Initialize paging
        println!("PAGING INIT START");
        let tcb_offset = paging::init(0);
        println!("PAGING INIT COMPLETE");

        // Test tdata and tbss
        {
            assert_eq!(TBSS_TEST_ZERO, 0);
            TBSS_TEST_ZERO += 1;
            assert_eq!(TBSS_TEST_ZERO, 1);
            assert_eq!(TDATA_TEST_NONZERO, 0xFFFF_FFFF_FFFF_FFFF);
            TDATA_TEST_NONZERO -= 1;
            assert_eq!(TDATA_TEST_NONZERO, 0xFFFF_FFFF_FFFF_FFFE);
        }

        // Reset AP variables
        CPU_COUNT.store(1, Ordering::SeqCst);
        AP_READY.store(false, Ordering::SeqCst);
        BSP_READY.store(false, Ordering::SeqCst);

        // Setup kernel heap
        println!("ALLOCATOR INIT START");
        allocator::init();
        println!("ALLOCATOR INIT COMPLETE");

        // Activate memory logging
        println!("LOG INIT START");
        log::init();
        println!("LOG INIT COMPLETE");

        // Initialize devices
        println!("DEVICE INIT START");
        device::init();
        println!("DEVICE INIT COMPLETE");

        // Initialize all of the non-core devices not otherwise needed to complete initialization
        println!("DEVICE INIT NONCORE START");
        device::init_noncore();
        println!("DEVICE INIT NONCORE COMPLETE");

        BSP_READY.store(true, Ordering::SeqCst);

        crate::Bootstrap {
            base: crate::memory::Frame::containing_address(crate::paging::PhysicalAddress::new(args.bootstrap_base)),
            page_count: args.bootstrap_size / crate::memory::PAGE_SIZE,
            entry: args.bootstrap_entry,
            env,
        }
    };

    println!("KMAIN");
    crate::kmain(CPU_COUNT.load(Ordering::SeqCst), bootstrap);
}

#[repr(packed)]
pub struct KernelArgsAp {
    cpu_id: u64,
    page_table: u64,
    stack_start: u64,
    stack_end: u64,
}

/// Entry to rust for an AP
pub unsafe extern fn kstart_ap(args_ptr: *const KernelArgsAp) -> ! {
    loop{}
}

#[naked]
pub unsafe fn usermode(ip: usize, sp: usize, arg: usize, _singlestep: usize) -> ! {
    core::arch::asm!(
        "
        udf #0
        ",
        options(noreturn)
    );
    /*TODO: update to asm
    let cpu_id: usize = 0;
    let spsr: u32 = 0;

    llvm_asm!("msr   spsr_el1, $0" : : "r"(spsr) : : "volatile");
    llvm_asm!("msr   elr_el1, $0" : : "r"(ip) : : "volatile");
    llvm_asm!("msr   sp_el0, $0" : : "r"(sp) : : "volatile");

    llvm_asm!("mov   x0, $0" : : "r"(arg) : : "volatile");
    llvm_asm!("eret" : : : : "volatile");

    unreachable!();
    */
}
