/// This function is where the kernel sets up IRQ handlers
/// It is increcibly unsafe, and should be minimal in nature
/// It must create the IDT with the correct entries, those entries are
/// defined in other files inside of the `arch` module
use core::slice;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

#[cfg(feature = "acpi")]
use crate::acpi;
#[cfg(feature = "graphical_debug")]
use crate::devices::graphical_debug;
use crate::{
    allocator,
    arch::{flags::*, pti},
    device, gdt, idt, interrupt,
    log::{self, info},
    memory,
    paging::{self, KernelMapper, PhysicalAddress, RmmA, RmmArch, TableKind},
    cpu_set::LogicalCpuId,
};

/// Test of zero values in BSS.
static BSS_TEST_ZERO: usize = 0;
/// Test of non-zero values in data.
static DATA_TEST_NONZERO: usize = usize::max_value();

pub static KERNEL_BASE: AtomicUsize = AtomicUsize::new(0);
pub static KERNEL_SIZE: AtomicUsize = AtomicUsize::new(0);

// TODO: This probably shouldn't be an atomic. Only the BSP starts APs.
pub static CPU_COUNT: AtomicU32 = AtomicU32::new(0);

pub static AP_READY: AtomicBool = AtomicBool::new(false);
static BSP_READY: AtomicBool = AtomicBool::new(false);

#[repr(packed)]
pub struct KernelArgs {
    kernel_base: u64,
    kernel_size: u64,
    stack_base: u64,
    stack_size: u64,
    env_base: u64,
    env_size: u64,

    /// The base 64-bit pointer to an array of saved RSDPs. It's up to the kernel (and possibly
    /// userspace), to decide which RSDP to use. The buffer will be a linked list containing a
    /// 32-bit relative (to this field) next, and the actual struct afterwards.
    ///
    /// This field can be NULL, and if so, the system has not booted with UEFI or in some other way
    /// retrieved the RSDPs. The kernel or a userspace driver will thus try searching the BIOS
    /// memory instead. On UEFI systems, BIOS-like searching is not guaranteed to actually work though.
    acpi_rsdps_base: u64,
    /// The size of the RSDPs region.
    acpi_rsdps_size: u64,

    areas_base: u64,
    areas_size: u64,

    /// The physical base 64-bit pointer to the contiguous bootstrap/initfs.
    bootstrap_base: u64,
    /// Size of contiguous bootstrap/initfs physical region, not necessarily page aligned.
    bootstrap_size: u64,
    /// Entry point the kernel will jump to.
    bootstrap_entry: u64,
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
        log::init_logger(|r| {
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
            "RSDPs: {:X}:{:X}",
            { args.acpi_rsdps_base },
            { args.acpi_rsdps_base } + { args.acpi_rsdps_size }
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
        info!("Bootstrap entry point: {:X}", { args.bootstrap_entry });

        // Set up GDT before paging
        gdt::init();

        // Set up IDT before paging
        idt::init();

        // Initialize RMM
        crate::arch::rmm::init(
            args.kernel_base as usize,
            args.kernel_size as usize,
            args.stack_base as usize,
            args.stack_size as usize,
            args.env_base as usize,
            args.env_size as usize,
            args.acpi_rsdps_base as usize,
            args.acpi_rsdps_size as usize,
            args.areas_base as usize,
            args.areas_size as usize,
            args.bootstrap_base as usize,
            args.bootstrap_size as usize,
        );
        // Initialize paging
        paging::init();

        // Set up GDT after paging with TLS
        gdt::init_paging(
            args.stack_base as usize + args.stack_size as usize,
            LogicalCpuId::BSP,
        );

        // Set up IDT
        idt::init_paging_bsp();

        // Set up syscall instruction
        interrupt::syscall::init();

        // Reset AP variables
        CPU_COUNT.store(1, Ordering::SeqCst);
        AP_READY.store(false, Ordering::SeqCst);
        BSP_READY.store(false, Ordering::SeqCst);

        // Setup kernel heap
        allocator::init();

        // Set up double buffer for grpahical debug now that heap is available
        #[cfg(feature = "graphical_debug")]
        graphical_debug::init_heap();

        idt::init_paging_post_heap(LogicalCpuId::BSP);

        // Activate memory logging
        log::init();

        // Initialize devices
        device::init();

        // Read ACPI tables, starts APs
        #[cfg(feature = "acpi")]
        {
            acpi::init(if args.acpi_rsdps_base != 0 && args.acpi_rsdps_size > 0 {
                Some((
                    (args.acpi_rsdps_base as usize + crate::PHYS_OFFSET) as u64,
                    args.acpi_rsdps_size as u64,
                ))
            } else {
                None
            });
            device::init_after_acpi();
        }

        // Initialize all of the non-core devices not otherwise needed to complete initialization
        device::init_noncore();

        // Initialize data structures used to track pages.
        memory::init_mm();

        // Stop graphical debug
        #[cfg(feature = "graphical_debug")]
        graphical_debug::fini();

        BSP_READY.store(true, Ordering::SeqCst);

        crate::Bootstrap {
            base: crate::memory::Frame::containing_address(crate::paging::PhysicalAddress::new(
                args.bootstrap_base as usize,
            )),
            page_count: (args.bootstrap_size as usize) / crate::memory::PAGE_SIZE,
            entry: args.bootstrap_entry as usize,
            env,
        }
    };

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

        // Set up IDT for AP
        idt::init_paging_post_heap(cpu_id);

        // Set up syscall instruction
        interrupt::syscall::init();

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

#[cfg(not(feature = "pit"))]
macro_rules! inner_pit_unmap(
    () => {
        "
            // unused: {pti_unmap}
        "
    }
);
#[cfg(feature = "pit")]
macro_rules! inner_pit_unmap(
    () => {
        "
            push rdi
            push rsi
            push rdx
            push rcx
            sub rsp, 8

            call {pti_unmap}

            add rsp, 8
            pop rcx
            pop rdx
            pop rsi
            pop rdi
        "
    }
);

#[naked]
// TODO: AbiCompatBool
pub unsafe extern "C" fn usermode(_ip: usize, _sp: usize, _arg: usize, _is_singlestep: usize) -> ! {
    // edi, esi, edx, ecx
    core::arch::asm!(
        concat!("
            // Pop arguments into registers
            pop eax // return address, ignored
            pop edi // ip
            pop esi // sp
            pop edx // arg
            pop ecx // is_singlestep

            // Set up eflags
            shl ecx, {shift_singlestep}
            or ecx, {flag_interrupts}

            // Set data selectors
            mov eax, {user_data_seg_selector}
            mov ds, eax
            mov es, eax
            mov eax, {user_fs_seg_selector}
            mov fs, eax
            mov eax, {user_gs_seg_selector}
            mov gs, eax

            // Set up iret stack
            mov eax, {user_data_seg_selector}
            push eax // stack selector
            push esi // stack address
            push ecx // eflags
            mov eax, {user_code_seg_selector}
            push eax // code selector
            push edi // code address

            // Clear general purpose registers
            xor eax, eax
            xor ebx, ebx
            xor ecx, ecx
            xor edx, edx
            xor edi, edi
            xor esi, esi
            xor ebp, ebp

            // Clear FPU registers
            fninit

            // Go to usermode
            iretd
            "),

        flag_interrupts = const(FLAG_INTERRUPTS),
        shift_singlestep = const(SHIFT_SINGLESTEP),
        user_data_seg_selector = const(gdt::GDT_USER_DATA << 3 | 3),
        user_code_seg_selector = const(gdt::GDT_USER_CODE << 3 | 3),
        user_fs_seg_selector = const(gdt::GDT_USER_FS << 3 | 3),
        user_gs_seg_selector = const(gdt::GDT_USER_GS << 3 | 3),

        options(noreturn),
    );
}
