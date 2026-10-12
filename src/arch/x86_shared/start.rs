//! This function is where the kernel sets up IRQ handlers
//! It is incredibly unsafe, and should be minimal in nature
//! It must create the IDT with the correct entries, those entries are
//! defined in other files inside of the `arch` module
use core::{arch::naked_asm, cell::SyncUnsafeCell, mem::offset_of};

use rmm::PageMapper;

use crate::{
    allocator,
    arch::{device, gdt, idt, interrupt, paging},
    context::context::Kstack,
    cpu_set::LogicalCpuId,
    devices::graphical_debug,
    startup::KernelArgs,
};

use crate::numa;

/// Test of zero values in BSS.
static BSS_TEST_ZERO: SyncUnsafeCell<usize> = SyncUnsafeCell::new(0);
/// Test of non-zero values in data.
static DATA_TEST_NONZERO: SyncUnsafeCell<usize> = SyncUnsafeCell::new(usize::MAX);

#[repr(C, align(16))]
struct StackAlign<T>(T);

// FIXME use extern "custom"
#[unsafe(naked)]
#[unsafe(no_mangle)]
extern "C" fn kstart() {
    naked_asm!(
        #[cfg(target_arch = "x86")]
        "
        // BSS should already be zero
        cmp dword ptr [{bss_test_zero}], 0
        jne .Lkstart_crash
        cmp dword ptr [{data_test_nonzero}], 0
        je .Lkstart_crash

        mov eax, [esp + 4]
        and esp, -16
        sub esp, 16
        mov [esp + 4], eax
        mov [esp + 8], esp

        jmp {start}

    .Lkstart_crash:
        xor eax, eax
        jmp eax
    ",

        #[cfg(target_arch = "x86_64")]
        "
        // BSS should already be zero
        cmp qword ptr [rip + {bss_test_zero}], 0
        jne .Lkstart_crash
        cmp qword ptr [rip + {data_test_nonzero}], 0
        je .Lkstart_crash

        // Note: The System V ABI requires the stack to be aligned to 16 bytes
        // before the call instruction.
        and rsp, -16
        mov rsi, rsp

        call {start}
        ud2

    .Lkstart_crash:
        xor rax, rax
        jmp rax
    ",

        bss_test_zero = sym BSS_TEST_ZERO,
        data_test_nonzero = sym DATA_TEST_NONZERO,
        start = sym start,
    );
}

/// The entry to Rust, all things must be initialized
unsafe extern "C" fn start(args_ptr: *const KernelArgs, stack_end: usize) -> ! {
    unsafe {
        let args = args_ptr.read();

        // Set up serial debug
        device::serial::init();

        // Set up graphical debug
        graphical_debug::init(args.env());

        info!("Redox OS starting...");
        args.print();

        // Set up GDT
        gdt::init_bsp(stack_end);

        // Set up IDT, except its IST
        idt::init_bsp_before_mem();

        // Initialize RMM
        #[cfg(target_arch = "x86")]
        let mut bump_allocator =
            crate::startup::memory::init(&args, Some(0x100000), Some(0x40000000));
        #[cfg(target_arch = "x86_64")]
        let mut bump_allocator = crate::startup::memory::init(&args, Some(0x100000), None);

        // Initialize misc features for paging
        paging::init();

        let mut mapper = PageMapper::current(rmm::TableKind::Kernel, bump_allocator);
        if cfg!(feature = "acpi") {
            crate::acpi::init_before_mem(args.acpi_rsdp(), &mut mapper);
        }

        numa::init(mapper.allocator_mut());

        crate::memory::init_mm(mapper.allocator_mut());

        // Set up the IDT's IST
        idt::init_bsp_after_mem();

        let mut kstack_slot = None;
        let kmain_kstack_top = kstack_slot
            .insert(Kstack::new().expect("failed to allocate main kstack"))
            .initial_top();

        #[cfg(target_arch = "x86_64")]
        core::arch::asm!("
            mov rsp, rax
            call {continue_after_stack}
            ud2
        ",
            in("rax") kmain_kstack_top,
            in("rdi") (&args),
            in("rsi") (&mut kstack_slot),
            continue_after_stack=sym continue_after_kmain_stack_raw,
            options(noreturn),
        );
        #[cfg(target_arch = "x86")]
        core::arch::asm!("
            mov esp, eax
            call {continue_after_stack}
            ud2
        ",
            in("eax") kmain_kstack_top,
            in("ecx") (&args),
            in("edx") (&mut kstack_slot),
            continue_after_stack=sym continue_after_kmain_stack_raw,
            options(noreturn),
        );
    }
}
#[cfg(target_arch = "x86_64")]
extern "sysv64" fn continue_after_kmain_stack_raw(
    args: &KernelArgs,
    kstack_slot: &mut Option<Kstack>,
) -> ! {
    continue_after_kmain_stack(args, kstack_slot)
}
#[cfg(target_arch = "x86")]
extern "fastcall" fn continue_after_kmain_stack_raw(
    args: &KernelArgs,
    kstack_slot: &mut Option<Kstack>,
) -> ! {
    continue_after_kmain_stack(args, kstack_slot)
}
#[inline(always)]
fn continue_after_kmain_stack(args: &KernelArgs, kstack_slot: &mut Option<Kstack>) -> ! {
    info!("Now on kmain stack");
    unsafe {
        let bootstrap = {
            #[cfg(target_arch = "x86_64")]
            crate::arch::alternative::early_init(true);

            // Set up syscall instruction
            interrupt::syscall::init();

            // Setup kernel heap
            allocator::init();

            // Activate memory logging
            crate::log::init();

            // Initialize miscellaneous processor features
            #[cfg(target_arch = "x86_64")]
            crate::arch::misc::init(LogicalCpuId::BSP);

            // Initialize devices
            device::init();

            #[cfg(all(target_arch = "x86_64", feature = "numa"))]
            numa::init_arch();

            // Read ACPI tables, starts APs
            if cfg!(feature = "acpi") {
                crate::acpi::init_after_mem();
                device::init_after_acpi();
            }
            crate::profiling::init();

            // Initialize all of the non-core devices not otherwise needed to complete initialization
            device::init_noncore();

            args.bootstrap()
        };

        let kstack = kstack_slot.take().expect("kstack_slot must be Some");

        crate::startup::kmain(bootstrap, kstack);
    }
}

pub struct KernelArgsAp {
    pub stack_end: *mut u8,
    pub kstack: Option<Kstack>,
    pub cpu_id: LogicalCpuId,
    pub pcr_ptr: *mut gdt::ProcessorControlRegion,
    pub idt_ptr: *mut idt::Idt,
}

// FIXME use extern "custom"
#[unsafe(naked)]
pub extern "C" fn kstart_ap() {
    naked_asm!(
        #[cfg(target_arch = "x86")]
        "
        mov esp, dword ptr [edi + {args_stack}]
        mov [esp + 4], edi
        mov [esp + 8], esp

        jmp {start_ap}
    ",

        #[cfg(target_arch = "x86_64")]
        "
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
}

/// Entry to rust for an AP
unsafe extern "C" fn start_ap(args_ptr: *mut KernelArgsAp) -> ! {
    unsafe {
        let cpu_id = {
            let args = &*args_ptr;

            // Set up GDT
            gdt::install_pcr(args.pcr_ptr);

            // Set up IDT
            idt::install_idt(args.idt_ptr, args.cpu_id);

            // Initialize paging
            paging::init();

            crate::profiling::init();

            #[cfg(target_arch = "x86_64")]
            crate::arch::alternative::early_init(false);

            // Set up syscall instruction
            interrupt::syscall::init();

            // Initialize miscellaneous processor features
            #[cfg(target_arch = "x86_64")]
            crate::arch::misc::init(args.cpu_id);

            // Initialize devices (for AP)
            device::init_ap();

            args.cpu_id
        };
        let kstack = (*args_ptr)
            .kstack
            .take()
            .expect("AP kmain stack must be Some");

        crate::startup::kmain_ap(cpu_id, kstack);
    }
}
