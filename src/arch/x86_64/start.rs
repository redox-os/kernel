/// This function is where the kernel sets up IRQ handlers
/// It is increcibly unsafe, and should be minimal in nature
/// It must create the IDT with the correct entries, those entries are
/// defined in other files inside of the `arch` module

use core::slice;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::allocator;
#[cfg(feature = "acpi")]
use crate::acpi;
#[cfg(feature = "graphical_debug")]
use crate::arch::x86_64::graphical_debug;
use crate::arch::x86_64::pti;
use crate::arch::x86_64::flags::*;
use crate::device;
use crate::gdt;
use crate::idt;
use crate::interrupt;
use crate::log::{self, info};
use crate::paging;

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

    /// The physical base 64-bit pointer to the contiguous initfs.
    initfs_base: u64,
    initfs_size: u64,
}

/// The entry to Rust, all things must be initialized
#[no_mangle]
pub unsafe extern fn kstart(args_ptr: *const KernelArgs) -> ! {
    let env = {
        let args = &*args_ptr;

        let kernel_base = args.kernel_base as usize;
        let kernel_size = args.kernel_size as usize;
        let stack_base = args.stack_base as usize;
        let stack_size = args.stack_size as usize;
        let env_base = args.env_base as usize;
        let env_size = args.env_size as usize;
        let acpi_rsdps_base = args.acpi_rsdps_base;
        let acpi_rsdps_size = args.acpi_rsdps_size;
        let areas_base = args.areas_base as usize;
        let areas_size = args.areas_size as usize;
        let initfs_base = args.initfs_base as usize;
        let initfs_size = args.initfs_size as usize;

        // BSS should already be zero
        {
            assert_eq!(BSS_TEST_ZERO, 0);
            assert_eq!(DATA_TEST_NONZERO, 0xFFFF_FFFF_FFFF_FFFF);
        }

        KERNEL_BASE.store(kernel_base, Ordering::SeqCst);
        KERNEL_SIZE.store(kernel_size, Ordering::SeqCst);

        // Convert env to slice
        let env = slice::from_raw_parts((env_base + crate::PHYS_OFFSET) as *const u8, env_size);
        let initfs = slice::from_raw_parts((initfs_base + crate::PHYS_OFFSET) as *const u8, initfs_size);

        // Set up graphical debug
        #[cfg(feature = "graphical_debug")]
        graphical_debug::init(env);

        #[cfg(feature = "system76_ec_debug")]
        device::system76_ec::init();

        // Initialize logger
        log::init_logger(|r| {
            use core::fmt::Write;
            let _ = write!(
                crate::arch::x86_64::debug::Writer::new(),
                "{}:{} -- {}\n",
                r.target(),
                r.level(),
                r.args()
            );
        });

        info!("Redox OS starting...");
        info!("Kernel: {:X}:{:X}", kernel_base, kernel_base + kernel_size);
        info!("Stack: {:X}:{:X}", stack_base, stack_base + stack_size);
        info!("Env: {:X}:{:X}", env_base, env_base + env_size);
        info!("RSDPs: {:X}:{:X}", acpi_rsdps_base, acpi_rsdps_base + acpi_rsdps_size);
        info!("Areas: {:X}:{:X}", areas_base, areas_base + areas_size);
        info!("Initfs: {:X}:{:X}", initfs_base, initfs_base + initfs_size);

        // Set up GDT before paging
        gdt::init();

        // Set up IDT before paging
        idt::init();

        // Initialize RMM
        crate::arch::rmm::init(
            kernel_base, kernel_size,
            stack_base, stack_size,
            env_base, env_size,
            acpi_rsdps_base as usize, acpi_rsdps_size as usize,
            areas_base, areas_size,
            initfs_base, initfs_size,
        );

        // Initialize paging
        let (mut active_table, tcb_offset) = paging::init(0);

        // Set up GDT after paging with TLS
        gdt::init_paging(0, tcb_offset, stack_base + stack_size);

        // Set up IDT
        idt::init_paging_bsp();

        // Set up syscall instruction
        interrupt::syscall::init();

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
        allocator::init(&mut active_table);

        // Set up double buffer for grpahical debug now that heap is available
        #[cfg(feature = "graphical_debug")]
        graphical_debug::init_heap();

        idt::init_paging_post_heap(true, 0);

        // Activate memory logging
        log::init();

        // Initialize devices
        device::init(&mut active_table);

        // Read ACPI tables, starts APs
        #[cfg(feature = "acpi")]
        {
            acpi::init(&mut active_table, if acpi_rsdps_base != 0 && acpi_rsdps_size > 0 {
                Some((acpi_rsdps_base + crate::PHYS_OFFSET as u64, acpi_rsdps_size))
            } else {
                None
            });
            device::init_after_acpi(&mut active_table);
        }

        // Initialize all of the non-core devices not otherwise needed to complete initialization
        device::init_noncore();

        crate::scheme::initfs::init(initfs);

        // Stop graphical debug
        #[cfg(feature = "graphical_debug")]
        graphical_debug::fini();

        BSP_READY.store(true, Ordering::SeqCst);

        env
    };

    crate::kmain(CPU_COUNT.load(Ordering::SeqCst), env);
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
    let cpu_id = {
        let args = &*args_ptr;
        let cpu_id = args.cpu_id as usize;
        let bsp_table = args.page_table as usize;
        let _stack_start = args.stack_start as usize;
        let stack_end = args.stack_end as usize;

        assert_eq!(BSS_TEST_ZERO, 0);
        assert_eq!(DATA_TEST_NONZERO, 0xFFFF_FFFF_FFFF_FFFF);

        // Set up GDT before paging
        gdt::init();

        // Set up IDT before paging
        idt::init();

        // Initialize paging
        let tcb_offset = paging::init_ap(cpu_id, bsp_table);

        // Set up GDT with TLS
        gdt::init_paging(cpu_id as u32, tcb_offset, stack_end);

        // Set up IDT for AP
        idt::init_paging_post_heap(false, cpu_id);

        // Set up syscall instruction
        interrupt::syscall::init();

        // Test tdata and tbss
        {
            assert_eq!(TBSS_TEST_ZERO, 0);
            TBSS_TEST_ZERO += 1;
            assert_eq!(TBSS_TEST_ZERO, 1);
            assert_eq!(TDATA_TEST_NONZERO, 0xFFFF_FFFF_FFFF_FFFF);
            TDATA_TEST_NONZERO -= 1;
            assert_eq!(TDATA_TEST_NONZERO, 0xFFFF_FFFF_FFFF_FFFE);
        }

        // Initialize devices (for AP)
        device::init_ap();

        AP_READY.store(true, Ordering::SeqCst);

        cpu_id
    };

    while ! BSP_READY.load(Ordering::SeqCst) {
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

#[cfg(not(feature = "x86_fsgsbase"))]
macro_rules! save_fsgsbase(
    () => {
        "
            mov ecx, {MSR_FSBASE}
            rdmsr
            shl rdx, 32
            or rdx, rax
            mov r14, rdx

            mov ecx, {MSR_GSBASE}
            rdmsr
            shl rdx, 32
            or rdx, rax
            mov r13, rdx
        "
    }
);
#[cfg(feature = "x86_fsgsbase")]
macro_rules! save_fsgsbase(
    () => {
        "
        // placeholder: {MSR_FSBASE} {MSR_GSBASE}
        rdfsbase r14
        rdgsbase r13
        "
    }
);

#[cfg(feature = "x86_fsgsbase")]
macro_rules! restore_fsgsbase(
    () => {
        "
        wrfsbase r14
        wrgsbase r13
        "
    }
);

#[cfg(not(feature = "x86_fsgsbase"))]
macro_rules! restore_fsgsbase(
    () => {
        "
        mov ecx, {MSR_FSBASE}
        mov rdx, r14
        mov eax, edx
        shr rdx, 32
        wrmsr

        mov ecx, {MSR_GSBASE}
        mov rdx, r13
        mov eax, edx
        shr rdx, 32
        wrmsr
        "
    }
);

#[naked]
// TODO: AbiCompatBool
pub unsafe extern "C" fn usermode(_ip: usize, _sp: usize, _arg: usize, _is_singlestep: usize) -> ! {
    // rdi, rsi, rdx, rcx
    core::arch::asm!(
        concat!("
            shl rcx, {shift_singlestep}
            or rcx, {flag_interrupts}

            ", inner_pit_unmap!(), "

            // Save rdx for later
            mov r12, rdx

            // Target RFLAGS
            mov r11, rcx

            // Go to usermode
            swapgs

            ", save_fsgsbase!(), "

            mov r15, {user_data_seg_selector}
            mov ds, r15d
            mov es, r15d
            mov fs, r15d
            mov gs, r15d
            ",

            // SS and CS will later be set via sysretq.

            restore_fsgsbase!(), "

            // Target instruction pointer
            mov rcx, rdi
            // Target stack pointer
            mov rsp, rsi
            // Target argument
            mov rdi, r12

            xor rax, rax
            xor rbx, rbx
            // Don't zero rcx; it's used for `ip`.
            xor rdx, rdx
            // Don't zero rdi; it's used for `arg`.
            xor rsi, rsi
            xor rbp, rbp
            // Don't zero rsp, obviously.
            xor r8, r8
            xor r9, r9
            xor r10, r10
            // Don't zero r11; it's used for `rflags`.
            xor r12, r12
            xor r13, r13
            xor r14, r14
            xor r15, r15

            fninit
            ",
            // NOTE: Regarding the sysretq vulnerability, this is safe as we cannot modify RCX,
            // even though the caller can give us the wrong address. But, it's marked unsafe, so
            // the caller is responsible for this! (And, the likelihood of rcx being changed in the
            // middle here, is minimal, unless the attacker already has partial control of kernel
            // memory.)
            "
            sysretq
            "),

        flag_interrupts = const(FLAG_INTERRUPTS),
        shift_singlestep = const(SHIFT_SINGLESTEP),
        pti_unmap = sym pti::unmap,
        user_data_seg_selector = const(gdt::GDT_USER_DATA << 3 | 3),

        MSR_FSBASE = const(x86::msr::IA32_FS_BASE),
        MSR_GSBASE = const(x86::msr::IA32_GS_BASE),

        options(noreturn),
    );
}
