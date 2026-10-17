use core::{arch::asm, ptr::with_exposed_provenance_mut};

use spin::Once;

use crate::{
    arch::device::ArchPercpuMisc,
    cpu_set::LogicalCpuId,
    memory::{RmmA, RmmArch},
    percpu::PercpuBlock,
};

#[repr(C)]
pub struct ArchPercpu {
    // These fields must be kept first and in this order. Assembly in exception.rs depends on it
    pub tmp: usize,
    pub s_sp: usize,

    pub percpu: PercpuBlock,
}

#[cfg(not(test))]
impl PercpuBlock {
    pub fn current() -> &'static Self {
        unsafe {
            let tp: *const ArchPercpu;
            asm!( "mv t0, tp", out("t0") tp );
            let arch_percpu = &*tp;
            &arch_percpu.percpu
        }
    }
    pub fn current_hart() -> usize {
        Self::current().misc_arch_info.hart_id
    }
}

#[cold]
pub unsafe fn init(cpu_id: LogicalCpuId, hart_id: usize) {
    unsafe {
        let must_be_zero = true;
        let frame =
            crate::memory::allocate_frame(must_be_zero).expect("failed to allocate percpu memory");
        let virt: *mut ArchPercpu =
            with_exposed_provenance_mut(RmmA::phys_to_virt(frame.base()).data());

        let arch_per_cpu = ArchPercpu {
            tmp: 0,
            s_sp: 0,
            percpu: PercpuBlock {
                misc_arch_info: ArchPercpuMisc {
                    hart_id,
                    hlic_idx: Once::new(),
                },
                ..PercpuBlock::init(cpu_id)
            },
        };

        virt.write(arch_per_cpu);

        asm!(
            "mv tp, {}",
            "csrw sscratch, tp",
            in(reg) virt as usize
        );
    }
}
