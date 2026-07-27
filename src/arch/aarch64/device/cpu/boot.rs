use alloc::vec::Vec;
use core::{
    arch::{asm, global_asm},
    mem::{offset_of, size_of},
    ptr,
    sync::atomic::{AtomicU32, Ordering},
};
use spin::Once;

use crate::{
    context::context::Kstack,
    cpu_set::LogicalCpuId,
    memory::{
        PageFlags, PageMapper, PhysicalAddress, RaiiFrame, RmmA, RmmArch, TableKind,
        TheFrameAllocator, VirtualAddress, PAGE_SIZE,
    },
};

use super::{
    registers::control_regs,
    topology::{CpuDescription, EnableMethod, MPIDR_HWID_MASK},
};

const BOOT_MAGIC: u64 = 0x5245_444f_5841_5031; // "REDOXAP1"
const STATE_PREPARED: u32 = 0;
const STATE_STARTING: u32 = 1;
const STATE_LOCAL_READY: u32 = 2;
const STATE_READY: u32 = 3;
const STATE_ONLINE: u32 = 4;
const STATE_FAILED: u32 = 5;
const STATE_ABORTED: u32 = 6;
const STATE_BAD_ENTRY_EL: u32 = 7;
const STATE_ARGS_INVALID: u32 = 8;
const STATE_PERCPU_INVALID: u32 = 9;
const BOOT_TIMEOUT_SECONDS: u64 = 2;
const TCR_SH0_SHIFT: u32 = 12;
const TCR_SH1_SHIFT: u32 = 28;
const TCR_SH_MASK: u64 = 0b11;
const TCR_INNER_SHAREABLE: u64 = 0b11;

fn tcr_walks_are_inner_shareable(tcr: u64) -> bool {
    (tcr >> TCR_SH0_SHIFT) & TCR_SH_MASK == TCR_INNER_SHAREABLE
        && (tcr >> TCR_SH1_SHIFT) & TCR_SH_MASK == TCR_INNER_SHAREABLE
}

#[repr(C, align(64))]
struct BootArgs {
    magic: u64,
    logical_id: u64,
    mpidr: u64,
    stack_phys_top: u64,
    stack_virt_top: u64,
    percpu_virt: u64,
    ttbr0: u64,
    ttbr1: u64,
    tcr: u64,
    mair: u64,
    sctlr: u64,
    vbar: u64,
    cpacr: u64,
    entry_virt: u64,
    args_virt: u64,
    state: AtomicU32,
}

// PSCI enters the target PE at a physical address with the stage-1 MMU and
// caches disabled, and passes context_id in x0. This trampoline establishes
// the kernel translation regime and only then enters Rust at a virtual
// address. Cache invalidation and coherency-domain management belong to the
// PSCI implementation and are deliberately not duplicated here.
global_asm!(
    r#"
    .section .text.ap_trampoline, "ax"
    .balign 64
    .global __aarch64_ap_trampoline_start
__aarch64_ap_trampoline_start:
    msr daifset, #0xf
    mov x19, x0

    mrs x12, CurrentEL
    cmp x12, #0x8
    b.eq .Lap_from_el2
    cmp x12, #0x4
    b.eq .Lap_at_el1
    mov w14, #{state_bad_entry_el}
    str w14, [x19, #{state}]
    dsb sy
    sev
    b .Lap_park

.Lap_from_el2:
    // PSCI may select EL2 as the first Non-secure Exception level. Initialize
    // EL1 to a known MMU-off state before dropping to the EL1h kernel.
    mov x12, #0x0800
    movk x12, #0x3050, lsl #16
    msr sctlr_el1, x12
    isb

    ldr x1, [x19, #{stack_phys_top}]
    msr sp_el1, x1
    mov x12, #0x80000000
    msr hcr_el2, x12
    mrs x12, cnthctl_el2
    orr x12, x12, #3
    msr cnthctl_el2, x12
    msr cntvoff_el2, xzr
    mov x12, #0x33ff
    msr cptr_el2, x12
    msr hstr_el2, xzr
    msr mdcr_el2, xzr
    adr x12, .Lap_at_el1
    msr elr_el2, x12
    mov x12, #0x3c5
    msr spsr_el2, x12
    isb
    eret

.Lap_at_el1:
    // x19 is the physical BootArgs address supplied as PSCI context_id.
    // Consume every value needed below before enabling address translation.
    ldr x2, [x19, #{stack_virt_top}]
    ldr x3, [x19, #{percpu_virt}]
    ldr x4, [x19, #{ttbr0}]
    ldr x5, [x19, #{ttbr1}]
    ldr x6, [x19, #{tcr}]
    ldr x7, [x19, #{mair}]
    ldr x8, [x19, #{sctlr}]
    ldr x9, [x19, #{vbar}]
    ldr x10, [x19, #{cpacr}]
    ldr x11, [x19, #{entry_virt}]
    ldr x12, [x19, #{args_virt}]

    msr mair_el1, x7
    msr tcr_el1, x6
    msr ttbr0_el1, x4
    msr ttbr1_el1, x5
    dsb sy
    isb
    tlbi vmalle1
    dsb sy
    isb
    msr sctlr_el1, x8
    isb

    mov sp, x2
    msr tpidr_el1, x3
    msr tpidr_el0, xzr
    msr tpidrro_el0, xzr
    msr vbar_el1, x9
    msr cpacr_el1, x10
    isb
    mov x0, x12
    mov x29, xzr
    mov x30, xzr
    br x11

.Lap_park:
    wfe
    b .Lap_park

    .global __aarch64_ap_trampoline_end
__aarch64_ap_trampoline_end:
    .previous
"#,
    stack_phys_top = const offset_of!(BootArgs, stack_phys_top),
    stack_virt_top = const offset_of!(BootArgs, stack_virt_top),
    percpu_virt = const offset_of!(BootArgs, percpu_virt),
    ttbr0 = const offset_of!(BootArgs, ttbr0),
    ttbr1 = const offset_of!(BootArgs, ttbr1),
    tcr = const offset_of!(BootArgs, tcr),
    mair = const offset_of!(BootArgs, mair),
    sctlr = const offset_of!(BootArgs, sctlr),
    vbar = const offset_of!(BootArgs, vbar),
    cpacr = const offset_of!(BootArgs, cpacr),
    entry_virt = const offset_of!(BootArgs, entry_virt),
    args_virt = const offset_of!(BootArgs, args_virt),
    state = const offset_of!(BootArgs, state),
    state_bad_entry_el = const STATE_BAD_ENTRY_EL,
);

unsafe extern "C" {
    static __aarch64_ap_trampoline_start: u8;
    static __aarch64_ap_trampoline_end: u8;
}

struct PreparedBootSlot {
    logical_id: LogicalCpuId,
    mpidr: u64,
    stack: Kstack,
    percpu: RaiiFrame,
    args: RaiiFrame,
}

impl PreparedBootSlot {
    fn args(&self) -> &BootArgs {
        let virt = RmmA::phys_to_virt(self.args.get().base()).data();
        unsafe { &*(virt as *const BootArgs) }
    }

    fn gic_target_mask(&self) -> u8 {
        let virt = RmmA::phys_to_virt(self.percpu.get().base()).data();
        unsafe { &*(virt as *const crate::percpu::PercpuBlock) }
            .misc_arch_info
            .gic_target_mask
            .load(Ordering::Acquire)
    }
}

struct BootResources {
    slots: Vec<PreparedBootSlot>,
    trampoline: RaiiFrame,
    idmap_root: PhysicalAddress,
}

static BOOT_RESOURCES: Once<BootResources> = Once::new();

fn cache_line_size() -> usize {
    let ctr: u64;
    unsafe { asm!("mrs {}, ctr_el0", out(reg) ctr, options(nomem, nostack)) };
    4usize << ((ctr >> 16) & 0xf)
}

fn clean_data_to_poc(base: usize, len: usize) {
    let line = cache_line_size();
    let mut address = base & !(line - 1);
    let end = base.saturating_add(len);
    while address < end {
        unsafe { asm!("dc cvac, {}", in(reg) address, options(nostack)) };
        address += line;
    }
    unsafe { asm!("dsb sy", options(nostack)) };
}

fn synchronize_instructions(base: usize, len: usize) {
    clean_data_to_poc(base, len);
    unsafe { asm!("ic ialluis", "dsb ish", "isb", options(nostack)) };
}

fn clean_idmap_tables(root: PhysicalAddress, address: usize) -> Option<()> {
    const TABLE_ADDRESS_MASK: usize = 0x0000_00ff_ffff_f000;
    const LEVEL_SHIFTS: [usize; 4] = [39, 30, 21, 12];

    let mut table_phys = root.data();
    for (level, shift) in LEVEL_SHIFTS.into_iter().enumerate() {
        let table_virt = RmmA::phys_to_virt(PhysicalAddress::new(table_phys)).data();
        clean_data_to_poc(table_virt, PAGE_SIZE);
        if level == LEVEL_SHIFTS.len() - 1 {
            return Some(());
        }

        let index = (address >> shift) & 0x1ff;
        let entry =
            unsafe { ptr::read_volatile((table_virt + index * size_of::<u64>()) as *const u64) };
        if entry & 1 == 0 {
            return None;
        }
        table_phys = entry as usize & TABLE_ADDRESS_MASK;
    }
    None
}

fn prepare_trampoline() -> Option<(RaiiFrame, PhysicalAddress)> {
    let trampoline = RaiiFrame::allocate().ok()?;
    let trampoline_phys = trampoline.get().base();
    if trampoline_phys.data() >= crate::arch::consts::USER_END_OFFSET {
        warn!("CPU trampoline lies outside the TTBR0 address range");
        return None;
    }

    let source_start = ptr::addr_of!(__aarch64_ap_trampoline_start) as usize;
    let source_end = ptr::addr_of!(__aarch64_ap_trampoline_end) as usize;
    let source_len = source_end.checked_sub(source_start)?;
    if source_len == 0 || source_len > PAGE_SIZE {
        warn!("CPU trampoline has invalid size {}", source_len);
        return None;
    }

    let trampoline_virt = RmmA::phys_to_virt(trampoline_phys).data();
    unsafe {
        ptr::copy_nonoverlapping(
            source_start as *const u8,
            trampoline_virt as *mut u8,
            source_len,
        );
    }
    synchronize_instructions(trampoline_virt, source_len);

    let mut mapper = unsafe { PageMapper::create(TableKind::User, TheFrameAllocator) }?;
    let flush = unsafe {
        mapper.map_phys(
            VirtualAddress::new(trampoline_phys.data()),
            trampoline_phys,
            PageFlags::new().execute(true),
        )
    }?;
    unsafe { flush.ignore() };
    let root = mapper.table().phys();
    clean_idmap_tables(root, trampoline_phys.data())?;
    unsafe { asm!("dsb sy", options(nostack)) };
    Some((trampoline, root))
}

pub(super) fn prepare(topology: &[CpuDescription]) {
    // Page-table walks have their own cacheability/shareability attributes in
    // TCR_EL1. PTE.SH makes the mapped data shareable, but cannot make stale
    // page-table entries coherent between walkers. The boot path currently
    // inherits TCR from the bootloader, so fail closed for SMP unless both
    // TTBR0 and TTBR1 walks are explicitly Inner Shareable.
    let tcr = unsafe { control_regs::tcr_el1() };
    if !tcr_walks_are_inner_shareable(tcr) {
        error!(
            "CPU boot resources unavailable: TCR_EL1 does not make TTBR0/TTBR1 walks inner-shareable ({:#x})",
            tcr
        );
        return;
    }
    info!(
        "BSP translation-table walks are inner-shareable: TCR_EL1={:#x}",
        tcr
    );

    if let Some(cpu) = topology
        .iter()
        .find(|cpu| !cpu.boot_cpu && cpu.enable_method != EnableMethod::Psci)
    {
        warn!(
            "CPU boot resources unavailable: secondary MPIDR={:#x} is not PSCI-enabled",
            cpu.mpidr
        );
        return;
    }

    let secondary_count = topology
        .iter()
        .filter(|cpu| !cpu.boot_cpu && cpu.enable_method == EnableMethod::Psci)
        .count();
    if secondary_count == 0 {
        info!("CPU boot resources: no PSCI secondary CPUs");
        return;
    }

    let Some((trampoline, idmap_root)) = prepare_trampoline() else {
        warn!("CPU boot resources unavailable: cannot prepare physical trampoline");
        return;
    };

    let mut slots = Vec::new();
    if slots.try_reserve_exact(secondary_count).is_err() {
        warn!(
            "CPU boot resources unavailable: cannot reserve {} slots",
            secondary_count
        );
        return;
    }

    let ttbr1 = RmmA::table(TableKind::Kernel).data() as u64;
    let mair = unsafe { control_regs::mair_el1() };
    let sctlr = unsafe { control_regs::sctlr_el1() };
    let vbar = unsafe { control_regs::vbar_el1() };
    let cpacr = unsafe { control_regs::cpacr_el1() };

    for (logical_id, cpu) in topology.iter().enumerate() {
        if cpu.boot_cpu || cpu.enable_method != EnableMethod::Psci {
            continue;
        }

        let logical_id = LogicalCpuId::new(
            u32::try_from(logical_id).expect("validated CPU topology exceeds logical ID range"),
        );
        let stack = match Kstack::new() {
            Ok(stack) => stack,
            Err(error) => {
                warn!(
                    "CPU boot resources unavailable for logical {} MPIDR={:#x}: stack: {:?}",
                    logical_id, cpu.mpidr, error
                );
                return;
            }
        };
        let percpu = match crate::arch::misc::prepare(logical_id) {
            Ok(percpu) => percpu,
            Err(error) => {
                warn!(
                    "CPU boot resources unavailable for logical {} MPIDR={:#x}: percpu: {:?}",
                    logical_id, cpu.mpidr, error
                );
                return;
            }
        };
        let args = match RaiiFrame::allocate() {
            Ok(args) => args,
            Err(error) => {
                warn!(
                    "CPU boot resources unavailable for logical {} MPIDR={:#x}: args: {:?}",
                    logical_id, cpu.mpidr, error
                );
                return;
            }
        };

        let stack_phys_top = stack.initial_top_phys();
        let stack_virt_top = RmmA::phys_to_virt(PhysicalAddress::new(stack_phys_top)).data();
        let percpu_virt = RmmA::phys_to_virt(percpu.get().base()).data();
        let args_virt = RmmA::phys_to_virt(args.get().base()).data();
        unsafe {
            (args_virt as *mut BootArgs).write(BootArgs {
                magic: BOOT_MAGIC,
                logical_id: u64::from(logical_id.get()),
                mpidr: cpu.mpidr,
                stack_phys_top: stack_phys_top as u64,
                stack_virt_top: stack_virt_top as u64,
                percpu_virt: percpu_virt as u64,
                ttbr0: idmap_root.data() as u64,
                ttbr1,
                tcr,
                mair,
                sctlr,
                vbar,
                cpacr,
                entry_virt: secondary_start as *const () as usize as u64,
                args_virt: args_virt as u64,
                state: AtomicU32::new(STATE_PREPARED),
            });
        }
        clean_data_to_poc(args_virt, size_of::<BootArgs>());

        slots.push(PreparedBootSlot {
            logical_id,
            mpidr: cpu.mpidr,
            stack,
            percpu,
            args,
        });
    }

    let resources = BOOT_RESOURCES.call_once(|| BootResources {
        slots,
        trampoline,
        idmap_root,
    });
    info!(
        "CPU boot resources: {} PSCI slots ready, trampoline={:#x}, idmap={:#x}",
        resources.slots.len(),
        resources.trampoline.get().base().data(),
        resources.idmap_root.data()
    );
    for slot in &resources.slots {
        let stack_top = slot.stack.initial_top_phys();
        debug!(
            "CPU boot slot logical {}: MPIDR={:#x} stack_phys={:#x}..{:#x} percpu_phys={:#x} args_phys={:#x}",
            slot.logical_id,
            slot.mpidr,
            stack_top - slot.stack.len(),
            stack_top,
            slot.percpu.get().base().data(),
            slot.args.get().base().data()
        );
    }
}

pub(super) fn start_secondaries() {
    if !cfg!(feature = "multi_core") {
        info!("CPU activation disabled by kernel configuration");
        return;
    }
    let Some(resources) = BOOT_RESOURCES.get() else {
        return;
    };
    let Some(gic_capacity) = crate::arch::device::irqchip::cpu_capacity() else {
        error!("CPU activation unavailable: no supported local interrupt controller");
        return;
    };
    if resources.slots.len() + 1 > gic_capacity {
        error!(
            "CPU activation unavailable: topology requires {} CPUs but GICv2 exposes {} interfaces",
            resources.slots.len() + 1,
            gic_capacity
        );
        return;
    }
    if crate::arch::device::irqchip::current_cpu_target_mask().is_none() {
        error!("CPU activation unavailable: BSP has no directed-SGI target mask");
        return;
    }
    if !crate::arch::device::generic_timer::ready() {
        error!("CPU activation unavailable: architected timer is not initialized");
        return;
    }

    let entry_phys = resources.trampoline.get().base().data();
    let frequency = u64::from(unsafe { control_regs::cntfrq_el0() });
    if frequency == 0 {
        error!("CPU activation unavailable: architected timer frequency is zero");
        return;
    }
    let timeout_ticks = frequency.saturating_mul(BOOT_TIMEOUT_SECONDS);
    let mut online = 1u32;

    for slot in &resources.slots {
        let args = slot.args();
        args.state.store(STATE_STARTING, Ordering::Release);
        clean_data_to_poc(args as *const BootArgs as usize, size_of::<BootArgs>());

        info!(
            "CPU logical {}: PSCI CPU_ON MPIDR={:#x}",
            slot.logical_id, slot.mpidr
        );
        if let Err(error) =
            crate::arch::device::psci::cpu_on(slot.mpidr, entry_phys, slot.args.get().base().data())
        {
            args.state.store(STATE_FAILED, Ordering::Release);
            error!(
                "CPU logical {}: PSCI CPU_ON failed: {:?}",
                slot.logical_id, error
            );
            break;
        }

        let started = unsafe { control_regs::cntvct_el0() };
        let mut self_test_sgi_sent = false;
        loop {
            match args.state.load(Ordering::Acquire) {
                STATE_READY => break,
                STATE_LOCAL_READY if !self_test_sgi_sent => {
                    let target_mask = slot.gic_target_mask();
                    if let Err(error) = crate::arch::device::irqchip::send_sgi(
                        crate::arch::ipi::IpiKind::Wakeup as u8,
                        Some(target_mask),
                    ) {
                        args.state.store(STATE_ABORTED, Ordering::Release);
                        unsafe { asm!("sev", options(nostack)) };
                        error!(
                            "CPU logical {}: local SGI self-test could not start: {:?}",
                            slot.logical_id, error
                        );
                        return;
                    }
                    self_test_sgi_sent = true;
                }
                STATE_FAILED | STATE_ABORTED => {
                    error!(
                        "CPU logical {}: secondary initialization failed",
                        slot.logical_id
                    );
                    return;
                }
                STATE_BAD_ENTRY_EL => {
                    error!(
                        "CPU logical {}: unsupported exception level",
                        slot.logical_id
                    );
                    return;
                }
                STATE_ARGS_INVALID => {
                    error!(
                        "CPU logical {}: boot arguments invalid after trampoline",
                        slot.logical_id
                    );
                    return;
                }
                STATE_PERCPU_INVALID => {
                    error!(
                        "CPU logical {}: per-CPU pointer invalid after trampoline",
                        slot.logical_id
                    );
                    return;
                }
                _ => {}
            }
            if unsafe { control_regs::cntvct_el0() }.wrapping_sub(started) >= timeout_ticks {
                if args
                    .state
                    .compare_exchange(
                        STATE_STARTING,
                        STATE_ABORTED,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_err()
                    && args.state.load(Ordering::Acquire) == STATE_READY
                {
                    break;
                }
                unsafe { asm!("sev", options(nostack)) };
                error!("CPU logical {}: boot handshake timed out", slot.logical_id);
                return;
            }
            core::hint::spin_loop();
        }

        if !crate::publish_cpu(slot.logical_id) {
            args.state.store(STATE_ABORTED, Ordering::Release);
            unsafe { asm!("sev", options(nostack)) };
            error!(
                "CPU logical {}: refused non-contiguous online publication",
                slot.logical_id
            );
            return;
        }
        args.state.store(STATE_ONLINE, Ordering::Release);
        unsafe { asm!("sev", options(nostack)) };
        online += 1;
        info!("CPU logical {}: online", slot.logical_id);
    }

    info!("CPU activation complete: {} CPUs online", online);
}

unsafe extern "C" fn secondary_start(args_ptr: *const BootArgs) -> ! {
    let Some(args) = (unsafe { args_ptr.as_ref() }) else {
        park();
    };
    let logical_id = match u32::try_from(args.logical_id) {
        Ok(id) => LogicalCpuId::new(id),
        Err(_) => park(),
    };
    let mpidr = unsafe { control_regs::mpidr() } & MPIDR_HWID_MASK;
    if args.magic != BOOT_MAGIC
        || args.args_virt != args_ptr as u64
        || args.mpidr != mpidr
        || args.state.load(Ordering::Acquire) != STATE_STARTING
    {
        args.state.store(STATE_ARGS_INVALID, Ordering::Release);
        unsafe { asm!("sev", options(nostack)) };
        park();
    }

    if crate::percpu::PercpuBlock::current().cpu_id != logical_id {
        args.state.store(STATE_PERCPU_INVALID, Ordering::Release);
        unsafe { asm!("sev", options(nostack)) };
        park();
    }
    unsafe {
        crate::arch::misc::install_address(
            args.percpu_virt as usize as *mut crate::percpu::PercpuBlock,
        );
    }
    if let Err(error) = crate::arch::device::irqchip::init_ap() {
        error!(
            "CPU logical {}: local GIC init failed: {:?}",
            logical_id, error
        );
        args.state.store(STATE_FAILED, Ordering::Release);
        unsafe { asm!("sev", options(nostack)) };
        park();
    }
    if let Err(error) = crate::arch::device::generic_timer::init_ap() {
        error!(
            "CPU logical {}: local timer init failed: {:?}",
            logical_id, error
        );
        args.state.store(STATE_FAILED, Ordering::Release);
        unsafe { asm!("sev", options(nostack)) };
        park();
    }
    unsafe {
        // start_secondaries runs after the BSP has initialized EMPTY_CR3.
        // Remove the trampoline-only identity map before advertising READY.
        RmmA::set_table(TableKind::User, crate::context::empty_cr3());
    }

    if args
        .state
        .compare_exchange(
            STATE_STARTING,
            STATE_LOCAL_READY,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        park();
    }
    unsafe { asm!("sev", options(nostack)) };

    let frequency = u64::from(unsafe { control_regs::cntfrq_el0() });
    let started = unsafe { control_regs::cntvct_el0() };
    let timeout_ticks = frequency.saturating_mul(BOOT_TIMEOUT_SECONDS);
    let mut saw_sgi = false;
    let mut saw_timer = false;
    while !saw_sgi || !saw_timer {
        let (raw_iar, hwirq, _) = crate::arch::device::irqchip::acknowledge_root();
        if hwirq < 1020 {
            if hwirq == crate::arch::ipi::IpiKind::Wakeup as u32 {
                crate::arch::device::irqchip::end_root(raw_iar);
                saw_sgi = true;
            } else if crate::arch::device::generic_timer::complete_ap_self_test(hwirq, raw_iar) {
                saw_timer = true;
            } else {
                crate::arch::device::irqchip::end_root(raw_iar);
                error!(
                    "CPU logical {}: unexpected local IRQ {} during boot self-test",
                    logical_id, hwirq
                );
                args.state.store(STATE_FAILED, Ordering::Release);
                unsafe { asm!("sev", options(nostack)) };
                park();
            }
        }

        if unsafe { control_regs::cntvct_el0() }.wrapping_sub(started) >= timeout_ticks {
            error!(
                "CPU logical {}: local interrupt self-test timed out (sgi={}, timer={})",
                logical_id, saw_sgi, saw_timer
            );
            args.state.store(STATE_FAILED, Ordering::Release);
            unsafe { asm!("sev", options(nostack)) };
            park();
        }
        core::hint::spin_loop();
    }

    if args
        .state
        .compare_exchange(
            STATE_LOCAL_READY,
            STATE_READY,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        park();
    }
    info!(
        "CPU logical {}: local SGI/timer self-test passed",
        logical_id
    );
    unsafe { asm!("sev", options(nostack)) };

    loop {
        match args.state.load(Ordering::Acquire) {
            STATE_ONLINE => break,
            STATE_ABORTED | STATE_FAILED => park(),
            _ => unsafe { asm!("wfe", options(nostack)) },
        }
    }

    crate::startup::kmain_ap(logical_id)
}

fn park() -> ! {
    loop {
        unsafe { asm!("msr daifset, #0xf", "wfe", options(nostack)) };
    }
}
