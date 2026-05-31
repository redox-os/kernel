use core::{
    arch::{asm, naked_asm},
    cell::SyncUnsafeCell,
    hint,
    sync::atomic::{AtomicUsize, Ordering},
};

use crate::{
    allocator::{self},
    arch::{
        self,
        device::{self},
        interrupt::exception_handler,
        ipi, paging,
    },
    devices::graphical_debug,
    dtb::serial::{self},
    kernel_executable_offsets::KERNEL_OFFSET,
    memory::{allocate_p2frame, deallocate_p2frame},
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

// FIXME use extern "custom"
#[unsafe(naked)]
#[unsafe(no_mangle)]
extern "C" fn kstart() {
    naked_asm!("
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
}

/// The entry to Rust, all things must be initialized
unsafe extern "C" fn start(args_ptr: *const KernelArgs) -> ! {
    unsafe {
        let bootstrap = {
            let args = args_ptr.read();

            let fdt = args.dtb().expect("Failed to parse devicetree!");

            graphical_debug::init(args.env());
            serial::init_early(&fdt);

            info!("Redox OS starting...");
            args.print();

            device::dump_fdt(&fdt);

            // Initialize RMM
            crate::startup::memory::init(&args, None, None);
            paging::init();

            let boot_hart_id =
                get_boot_hart_id(args.env()).expect("Didn't get boot HART id from bootloader");
            info!("Booting on HART {}", boot_hart_id);
            BOOT_HART_ID.store(boot_hart_id, Ordering::Relaxed);

            crate::arch::misc::init(crate::cpu_set::LogicalCpuId::new(0), boot_hart_id);

            // Setup kernel heap
            allocator::init();

            // Activate memory logging
            crate::log::init();

            crate::dtb::init(Some((
                fdt.raw_data().as_ptr() as usize,
                fdt.raw_data().len(),
            )));

            // Initialize devices
            device::init(&fdt);

            // Initialize all of the non-core devices not otherwise needed to complete initialization
            device::init_noncore(&fdt);

            bring_up_aps(&fdt, args.kernel_base, boot_hart_id);

            args.bootstrap()
        };

        crate::startup::kmain(bootstrap);
    }
}

static AP_SIGNAL: AtomicUsize = AtomicUsize::new(0);

/// Starts the secondary harts
unsafe fn bring_up_aps(fdt: &fdt::Fdt, kernel_base: u64, boot_hart_id: usize) {
    use fdt::node::NodeProperty;
    use rmm::Arch;

    // for replicating the VA setup on the APs
    let satp_bits;
    unsafe {
        asm!("csrr {0}, satp", out(reg) satp_bits);
    }

    for cpu in fdt.cpus() {
        let hart_id = cpu.ids().first();
        if hart_id == boot_hart_id {
            continue;
        }
        if !cpu
            .property("riscv,isa")
            .and_then(NodeProperty::as_str)
            .is_some_and(|isa| isa.starts_with("rv64imafdc"))
        {
            info!("skipping ap hart {}: isa not compatible", hart_id);
            continue;
        }

        unsafe {
            let ap_stack_frame = allocate_p2frame(4).expect("failed to allocate AP stack");
            let ap_stack = arch::CurrentRmmArch::phys_to_virt(ap_stack_frame.base()).data();
            AP_SIGNAL.store(ap_stack, Ordering::SeqCst);
            let start_addr_phys =
                (kstart_ap_raw as *const () as usize - KERNEL_OFFSET()) + kernel_base as usize;

            info!("starting ap hart {}", hart_id);
            if let Err(e) = sbi_rt::hart_start(hart_id, start_addr_phys, satp_bits).into_result() {
                println!("failed to start ap hart: {:?}", e);
                deallocate_p2frame(ap_stack_frame, 4);
                continue;
            }

            while AP_SIGNAL.load(Ordering::Relaxed) == ap_stack {
                hint::spin_loop();
            }
            info!("ap hart {} started!", hart_id);
        }
    }
}

#[unsafe(naked)]
#[unsafe(no_mangle)]
/// Entry point for APs
///
/// Sets up virtual addressing before jumping to the next stage, since
/// (unlike the bootloader with the main hart) SBI starts the AP in Bare mode.
///
/// The Satp bits of the boot hart are passed in the opaque value of the hart_start SBI call.
extern "C" fn kstart_ap_raw() {
    naked_asm!("
        .balign 4

        la t0, {kstart_ap} // WARL=0 - direct mode combined handler
        csrw stvec, t0 // advanced exception gymnastics to avoid having to ident map

        csrw satp, a1
        sfence.vma

        jr t0 // just in case
        ",
        kstart_ap = sym kstart_ap
    );
}

#[unsafe(naked)]
extern "C" fn kstart_ap() {
    naked_asm!("
        .balign 4

        mv gp, x0 // ensure gp relative accesses crash
        mv tp, x0 // reset percpu until it is initialized
        csrw sscratch, tp

        ld sp, {signal}
        li t0, {stack_size} -16
        add sp, sp, t0

        la t0, {exception_handler} // WARL=0 - direct mode combined handler
        csrw stvec, t0

        li ra, 0
        j {start_ap}
    ",
        signal = sym AP_SIGNAL,
        stack_size = const size_of_val(&STACK),
        exception_handler = sym exception_handler,
        start_ap = sym start_ap,
    );
}
/// The entry to Rust on the APs, all things must be initialized
unsafe extern "C" fn start_ap(hart_id: usize) -> ! {
    AP_SIGNAL.store(hart_id, Ordering::Relaxed);
    let cpu_id = unsafe {
        let cpu_id = crate::cpu_set::LogicalCpuId::next();

        crate::arch::misc::init(cpu_id, hart_id);

        crate::profiling::init();

        ipi::init(hart_id);
        device::irqchip::hlic::init();
        crate::arch::device::irqchip::init_clint_ap(hart_id);

        cpu_id
    };

    crate::startup::kmain_ap(cpu_id);
}
