//! This function is where the kernel sets up IRQ handlers
//! It is incredibly unsafe, and should be minimal in nature
//! It must create the IDT with the correct entries, those entries are
//! defined in other files inside of the `arch` module
use core::{
    arch::global_asm,
    cell::SyncUnsafeCell,
    hint,
    mem::offset_of,
    sync::atomic::{AtomicBool, Ordering},
};

#[cfg(feature = "acpi")]
use crate::acpi;

use crate::{
    allocator, cpu_set::LogicalCpuId, device, devices::graphical_debug, gdt, idt, interrupt,
    paging, startup::KernelArgs,
};

/// Test of zero values in BSS.
static BSS_TEST_ZERO: SyncUnsafeCell<usize> = SyncUnsafeCell::new(0);
/// Test of non-zero values in data.
static DATA_TEST_NONZERO: SyncUnsafeCell<usize> = SyncUnsafeCell::new(usize::MAX);

pub static AP_READY: AtomicBool = AtomicBool::new(false);
static BSP_READY: AtomicBool = AtomicBool::new(false);

#[repr(C, align(16))]
struct StackAlign<T>(T);

static STACK: SyncUnsafeCell<StackAlign<[u8; 128 * 1024]>> =
    SyncUnsafeCell::new(StackAlign([0; 128 * 1024]));

#[cfg(target_arch = "x86")]
global_asm!("
    .globl kstart
    kstart:
        // BSS should already be zero
        cmp dword ptr [{bss_test_zero}], 0
        jne .Lkstart_crash
        cmp dword ptr [{data_test_nonzero}], 0
        je .Lkstart_crash

        mov eax, [esp + 4]
        lea esp, [{stack}+{stack_size}-16]
        mov [esp + 4], eax
        mov [esp + 8], esp

        jmp {start}

    .Lkstart_crash:
        mov eax, 0
        jmp eax
    ",
    bss_test_zero = sym BSS_TEST_ZERO,
    data_test_nonzero = sym DATA_TEST_NONZERO,
    stack = sym STACK,
    stack_size = const size_of_val(&STACK),
    start = sym start,
);

#[cfg(target_arch = "x86_64")]
global_asm!("
    .globl kstart
    kstart:
        // BSS should already be zero
        cmp qword ptr [rip + {bss_test_zero}], 0
        jne .Lkstart_crash
        cmp qword ptr [rip + {data_test_nonzero}], 0
        je .Lkstart_crash

        // Note: The System V ABI requires the stack to be aligned to 16 bytes
        // before the call instruction. As we jump rather than call it has to
        // be offset by 8 bytes. Additionally reserve a bit more space at the
        // end of the stack to ensure that the start function returns to
        // address 0.
        lea rsp, [rip + {stack}+{stack_size}-24]
        mov rsi, rsp

        jmp {start}

    .Lkstart_crash:
        mov rax, 0
        jmp rax
    ",
    bss_test_zero = sym BSS_TEST_ZERO,
    data_test_nonzero = sym DATA_TEST_NONZERO,
    stack = sym STACK,
    stack_size = const size_of_val(&STACK),
    start = sym start,
);

/// The entry to Rust, all things must be initialized
unsafe extern "C" fn start(args_ptr: *const KernelArgs, stack_end: usize) -> ! {
    unsafe {
        let bootstrap = {
            let args = args_ptr.read();

            // Set up serial debug
            device::serial::init();

            // Set up graphical debug
            graphical_debug::init(args.env());

            info!("Redox OS starting...");
            args.print();

            // Set up GDT
            gdt::init_bsp(stack_end);

            // Set up IDT
            idt::init_bsp();

            // Initialize RMM
            #[cfg(target_arch = "x86")]
            crate::startup::memory::init(&args, Some(0x100000), Some(0x40000000));
            #[cfg(target_arch = "x86_64")]
            crate::startup::memory::init(&args, Some(0x100000), None);

            // Initialize paging
            paging::init();

            #[cfg(target_arch = "x86_64")]
            crate::alternative::early_init(true);

            // Set up syscall instruction
            interrupt::syscall::init();

            // Reset AP variables
            AP_READY.store(false, Ordering::SeqCst);
            BSP_READY.store(false, Ordering::SeqCst);

            // Setup kernel heap
            allocator::init();

            crate::profiling::init();

            // Activate memory logging
            crate::log::init();

            // Initialize miscellaneous processor features
            #[cfg(target_arch = "x86_64")]
            crate::misc::init(LogicalCpuId::BSP);

            // Initialize devices
            device::init();

            // Read ACPI tables, starts APs
            #[cfg(feature = "acpi")]
            {
                acpi::init(args.acpi_rsdp());
                device::init_after_acpi();
            }

            // Initialize all of the non-core devices not otherwise needed to complete initialization
            device::init_noncore();

            BSP_READY.store(true, Ordering::SeqCst);

            args.bootstrap()
        };

        crate::kmain(bootstrap);
    }
}

pub struct KernelArgsAp {
    pub stack_end: *mut u8,
    pub cpu_id: LogicalCpuId,
    pub pcr_ptr: *mut gdt::ProcessorControlRegion,
    pub idt_ptr: *mut idt::Idt,
}

// FIXME use extern "custom"
unsafe extern "C" {
    pub fn kstart_ap();
}

#[cfg(target_arch = "x86")]
global_asm!("
    .globl kstart_ap
    kstart_ap:
        mov esp, dword ptr [edi + {args_stack}]
        mov [esp + 4], edi
        mov [esp + 8], esp

        jmp {start_ap}
    ",
    args_stack = const offset_of!(KernelArgsAp, stack_end),
    start_ap = sym start_ap,
);

#[cfg(target_arch = "x86_64")]
global_asm!("
    .globl kstart_ap
    kstart_ap:
        // Note: The System V ABI requires the stack to be aligned to 16 bytes
        // before the call instruction. As we jump rather than call it has to
        // be offset by 8 bytes. Additionally reserve a bit more space at the
        // end of the stack to ensure that the start function returns to
        // address 0.
        mov rax, qword ptr [rdi + {args_stack}]
        lea rsp, [rax - 24]

        jmp {start_ap}
    ",
    args_stack = const offset_of!(KernelArgsAp, stack_end),
    start_ap = sym start_ap,
);

/// Entry to rust for an AP
unsafe extern "C" fn start_ap(args_ptr: *const KernelArgsAp) -> ! {
    unsafe {
        let cpu_id = {
            let args = &*args_ptr;

            // Set up GDT
            gdt::install_pcr(args.pcr_ptr);

            // Set up IDT
            idt::install_idt(args.idt_ptr);

            // Initialize paging
            paging::init();

            crate::profiling::init();

            #[cfg(target_arch = "x86_64")]
            crate::alternative::early_init(false);

            // Set up syscall instruction
            interrupt::syscall::init();

            // Initialize miscellaneous processor features
            #[cfg(target_arch = "x86_64")]
            crate::misc::init(args.cpu_id);

            // Initialize devices (for AP)
            device::init_ap();

            AP_READY.store(true, Ordering::SeqCst);

            args.cpu_id
        };

        while !BSP_READY.load(Ordering::SeqCst) {
            hint::spin_loop();
        }

        crate::kmain_ap(cpu_id);
    }
}
