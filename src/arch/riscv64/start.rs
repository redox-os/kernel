use core::{
    arch::{asm, naked_asm},
    cell::SyncUnsafeCell,
    sync::atomic::{AtomicUsize, Ordering},
};

use crate::{
    allocator::{self},
    arch::{
        device::{self},
        interrupt::exception_handler,
        paging,
    },
    devices::graphical_debug,
    dtb::serial::init_early,
    kernel_executable_offsets::KERNEL_OFFSET,
    percpu::PercpuBlock,
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

            let dtb_data = if args.hwdesc_base != 0 {
                Some((
                    crate::PHYS_OFFSET | args.hwdesc_base as usize,
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
                device::dump_fdt(dtb);
            }

            // Initialize RMM
            crate::startup::memory::init(&args, None, None);

            let boot_hart_id =
                get_boot_hart_id(args.env()).expect("Didn't get boot HART id from bootloader");
            info!("Booting on HART {}", boot_hart_id);
            BOOT_HART_ID.store(boot_hart_id, Ordering::Relaxed);

            paging::init();

            crate::arch::misc::init(crate::cpu_set::LogicalCpuId::new(0), boot_hart_id);

            // Setup kernel heap
            allocator::init();

            // Activate memory logging
            crate::log::init();

            crate::dtb::init(dtb_data);

            // Initialize devices
            device::init();

            // Initialize all of the non-core devices not otherwise needed to complete initialization
            device::init_noncore();

            if let Some(dtb) = &dtb {
                bring_up_aps(dtb, args.kernel_base as usize);
            }

            args.bootstrap()
        };

        crate::startup::kmain(bootstrap);
    }
}

static AP_SIGNAL: AtomicUsize = AtomicUsize::new(0);

unsafe fn bring_up_aps(fdt: &fdt::Fdt, kernel_base: usize) {
    use core::alloc::{GlobalAlloc, Layout};
    use fdt::node::NodeProperty;

    let boot_hart_id = BOOT_HART_ID.load(Ordering::Relaxed);
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
            let satp_bits;
            asm!("csrr {0}, satp", out(reg) satp_bits);

            let ap_stack = crate::ALLOCATOR.alloc_zeroed(Layout::for_value(&STACK));
            AP_SIGNAL.store(ap_stack.expose_provenance(), Ordering::SeqCst);
            let start_addr_phys = (kstart_ap_phys as usize - KERNEL_OFFSET()) + kernel_base;
            info!("starting ap hart {}", hart_id);
            if let Err(e) = sbi_rt::hart_start(hart_id, start_addr_phys, satp_bits).into_result() {
                println!("failed to start ap hart: {:?}", e);
                crate::ALLOCATOR.dealloc(ap_stack, Layout::for_value(&STACK));
                continue;
            }

            while AP_SIGNAL.load(Ordering::Relaxed) == ap_stack as usize {}
            info!("ap hart {} started!", hart_id);
        }
    }
}

#[unsafe(naked)]
#[unsafe(no_mangle)]
extern "C" fn kstart_ap_phys() {
    naked_asm!("
        la t0, {kstart_ap} // WARL=0 - direct mode combined handler
        csrw stvec, t0

        csrw satp, a1 // advanced exception gymnastics to avoid having to ident map
        sfence.vma

        jr t0 // just in case
        ",
        kstart_ap = sym kstart_ap
    );
}

#[unsafe(naked)]
#[unsafe(no_mangle)]
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

unsafe extern "C" fn start_ap(hart_id: usize) -> ! {
    AP_SIGNAL.store(hart_id, Ordering::Relaxed);
    let cpu_id = unsafe {
        // Initialize paging
        paging::init();

        crate::profiling::init();

        let cpu_id = crate::cpu_set::LogicalCpuId::next();

        crate::arch::misc::init(cpu_id, hart_id);
        ipi::init(hart_id);

        device::irqchip::hlic::init();

        crate::arch::device::irqchip::init_clint_ap(hart_id);

        cpu_id
    };

    crate::startup::kmain_ap(cpu_id);
}
