use crate::{
    arch::{
        interrupt::InterruptStack,
        paging::{PageMapper, ENTRY_COUNT},
    },
    context::{context::Kstack, memory::Table},
    memory::{KernelMapper, RmmA},
    percpu::PercpuBlock,
    syscall::FloatRegisters,
};
use core::{mem::offset_of, sync::atomic::AtomicBool};
use rmm::{Arch, TableKind, VirtualAddress};
use spin::Once;
use syscall::{error::*, EnvRegisters};

pub static CONTEXT_SWITCH_LOCK: AtomicBool = AtomicBool::new(false);

pub const KFX_ALIGN: usize = 16;

#[derive(Clone, Debug, Default)]
pub struct Context {
    sp: usize,
    ra: usize,
    fp: usize,
    s1: usize,
    s2: usize,
    s3: usize,
    s4: usize,
    s5: usize,
    s6: usize,
    s7: usize,
    s8: usize,
    s9: usize,
    s10: usize,
    s11: usize,
    sstatus: usize,
}

impl Context {
    pub fn new() -> Self {
        Self::default()
    }

    fn set_stack(&mut self, address: usize) {
        self.sp = address;
    }

    fn set_ra(&mut self, address: usize) {
        self.ra = address;
    }

    fn set_s11(&mut self, address: usize) {
        self.s11 = address;
    }

    pub(crate) fn setup_initial_call(
        &mut self,
        stack: &Kstack,
        func: extern "C" fn(),
        userspace_allowed: bool,
    ) {
        let mut stack_top = stack.initial_top();

        const INT_REGS_SIZE: usize = core::mem::size_of::<InterruptStack>();

        if userspace_allowed {
            unsafe {
                // Zero-initialize InterruptStack registers.
                stack_top = stack_top.sub(INT_REGS_SIZE);
                stack_top.write_bytes(0_u8, INT_REGS_SIZE);
                (&mut *stack_top.cast::<InterruptStack>()).init();
            }
        }

        self.set_ra(crate::interrupt::syscall::enter_usermode as usize);
        self.set_s11(func as usize);

        self.set_stack(stack_top as usize);
    }
}

impl super::Context {
    pub fn get_fx_regs(&self) -> FloatRegisters {
        unimplemented!()
    }

    pub fn set_fx_regs(&mut self, mut _new: FloatRegisters) {
        unimplemented!()
    }

    pub fn current_syscall(&self) -> Option<[usize; 6]> {
        if !self.inside_syscall {
            return None;
        }
        let regs = self.regs()?;
        let regs = &regs.registers;
        Some([regs.x17, regs.x10, regs.x11, regs.x12, regs.x13, regs.x14])
    }

    pub(crate) fn write_current_env_regs(&mut self, regs: EnvRegisters) -> Result<()> {
        self.write_env_regs(regs)
    }

    pub(crate) fn write_env_regs(&mut self, regs: EnvRegisters) -> Result<()> {
        if RmmA::virt_is_valid(VirtualAddress::new(regs.tp)) {
            match self.regs_mut() {
                Some(stack) => {
                    stack.registers.x4 = regs.tp;
                    Ok(())
                }
                None => Err(Error::new(ESRCH)),
            }
        } else {
            Err(Error::new(EINVAL))
        }
    }

    pub(crate) fn read_current_env_regs(&self) -> Result<EnvRegisters> {
        self.read_env_regs()
    }

    pub(crate) fn read_env_regs(&self) -> Result<EnvRegisters> {
        match self.regs() {
            Some(stack) => Ok(EnvRegisters {
                tp: stack.registers.x4,
            }),
            None => Err(Error::new(ESRCH)),
        }
    }
}

pub static EMPTY_CR3: Once<rmm::PhysicalAddress> = Once::new();

// SAFETY: EMPTY_CR3 must be initialized.
pub unsafe fn empty_cr3() -> rmm::PhysicalAddress {
    debug_assert!(EMPTY_CR3.poll().is_some());
    *EMPTY_CR3.get_unchecked()
}

/// Switch to the next context by restoring its stack and registers
pub unsafe fn switch_to(prev: &mut super::Context, next: &mut super::Context) {
    // FIXME floating point
    PercpuBlock::current()
        .new_addrsp_tmp
        .set(next.addr_space.clone());

    switch_to_inner(&mut prev.arch, &mut next.arch);
}

#[naked]
unsafe extern "C" fn switch_to_inner(prev: &mut Context, next: &mut Context) {
    core::arch::asm!(r#"
        sd s1, {off_s1}(a0)
        ld s1, {off_s1}(a1)

        sd s2, {off_s2}(a0)
        ld s2, {off_s2}(a1)

        sd s3, {off_s3}(a0)
        ld s3, {off_s3}(a1)

        sd s4, {off_s4}(a0)
        ld s4, {off_s4}(a1)

        sd s5, {off_s5}(a0)
        ld s5, {off_s5}(a1)

        sd s6, {off_s6}(a0)
        ld s6, {off_s6}(a1)

        sd s7, {off_s7}(a0)
        ld s7, {off_s7}(a1)

        sd s8, {off_s8}(a0)
        ld s8, {off_s8}(a1)

        sd s9, {off_s9}(a0)
        ld s9, {off_s9}(a1)

        sd s10, {off_s10}(a0)
        ld s10, {off_s10}(a1)

        sd s11, {off_s11}(a0)
        ld s11, {off_s11}(a1)

        sd s11, {off_s11}(a0)
        ld s11, {off_s11}(a1)

        sd sp, {off_sp}(a0)
        ld sp, {off_sp}(a1)

        sd ra, {off_ra}(a0)
        ld ra, {off_ra}(a1)

        sd fp, {off_fp}(a0)
        ld fp, {off_fp}(a1)

        csrr t0, sstatus
        sd t0, {off_sstatus}(a0)
        ld t0, {off_sstatus}(a1)
        csrw sstatus, t0

        j {switch_hook}
        "#,
    off_s1 = const(offset_of!(Context, s1)),
    off_s2 = const(offset_of!(Context, s2)),
    off_s3 = const(offset_of!(Context, s3)),
    off_s4 = const(offset_of!(Context, s4)),
    off_s5 = const(offset_of!(Context, s5)),
    off_s6 = const(offset_of!(Context, s6)),
    off_s7 = const(offset_of!(Context, s7)),
    off_s8 = const(offset_of!(Context, s8)),
    off_s9 = const(offset_of!(Context, s9)),
    off_s10 = const(offset_of!(Context, s10)),
    off_s11 = const(offset_of!(Context, s11)),
    off_sp = const(offset_of!(Context, sp)),
    off_ra = const(offset_of!(Context, ra)),
    off_fp = const(offset_of!(Context, fp)),
    off_sstatus = const(offset_of!(Context, sstatus)),

    switch_hook = sym crate::context::switch_finish_hook,
    options(noreturn),
    );
}

/// Allocates a new empty utable
pub fn setup_new_utable() -> Result<Table> {
    let utable = unsafe {
        PageMapper::create(TableKind::User, crate::memory::TheFrameAllocator)
            .ok_or(Error::new(ENOMEM))?
    };

    // Copy higher half (kernel) mappings
    unsafe {
        let active_ktable = KernelMapper::lock();
        for pde_no in ENTRY_COUNT / 2..ENTRY_COUNT {
            if let Some(entry) = active_ktable.table().entry(pde_no) {
                utable.table().set_entry(pde_no, entry);
            }
        }
    }

    Ok(Table { utable })
}
