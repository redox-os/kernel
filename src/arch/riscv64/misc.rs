use core::arch::asm;

use crate::{
    cpu_set::LogicalCpuId,
    paging::{RmmA, RmmArch},
    percpu::PercpuBlock,
};

#[repr(C)]
pub struct ArchPercpu {
    // These fields must be kept first and in this order. Assembly in exception.rs depends on it
    pub tmp: usize,
    pub s_sp: usize,

    pub percpu: PercpuBlock,
}

impl PercpuBlock {
    pub fn current() -> &'static Self {
        unsafe {
            let tp: *const ArchPercpu;
            asm!( "mv t0, tp", out("t0") tp );
            let arch_percpu = &*tp;
            &arch_percpu.percpu
        }
    }
}

#[cold]
pub unsafe fn init(cpu_id: LogicalCpuId) {
    let frame = crate::memory::allocate_frame().expect("failed to allocate percpu memory");
    let virt = RmmA::phys_to_virt(frame.base()).data() as *mut ArchPercpu;

    virt.write(ArchPercpu {
        tmp: 0,
        s_sp: 0,
        percpu: PercpuBlock::init(cpu_id),
    });

    asm!(
        "mv tp, {}",
        "csrw sscratch, tp",
        in(reg) virt as usize
    );
}
