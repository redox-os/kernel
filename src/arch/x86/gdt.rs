//! Global descriptor table

use core::convert::TryInto;
use core::mem;
use core::ptr::addr_of_mut;

use x86::bits32::task::TaskStateSegment;
use x86::Ring;
use x86::dtables::{self, DescriptorTablePointer};
use x86::segmentation::{self, Descriptor as SegmentDescriptor, SegmentSelector};
use x86::task;

use crate::paging::{RmmA, RmmArch, PAGE_SIZE};

use super::cpuid::cpuid;

pub const GDT_NULL: usize = 0;
pub const GDT_KERNEL_CODE: usize = 1;
pub const GDT_KERNEL_DATA: usize = 2;
pub const GDT_KERNEL_PERCPU: usize = 3;
pub const GDT_USER_CODE: usize = 4;
pub const GDT_USER_DATA: usize = 5;
pub const GDT_USER_FS: usize = 6;
pub const GDT_USER_GS: usize = 7;
pub const GDT_TSS: usize = 8;

pub const GDT_A_PRESENT: u8 = 1 << 7;
pub const GDT_A_RING_0: u8 = 0 << 5;
pub const GDT_A_RING_1: u8 = 1 << 5;
pub const GDT_A_RING_2: u8 = 2 << 5;
pub const GDT_A_RING_3: u8 = 3 << 5;
pub const GDT_A_SYSTEM: u8 = 1 << 4;
pub const GDT_A_EXECUTABLE: u8 = 1 << 3;
pub const GDT_A_CONFORMING: u8 = 1 << 2;
pub const GDT_A_PRIVILEGE: u8 = 1 << 1;
pub const GDT_A_DIRTY: u8 = 1;

pub const GDT_A_TSS_AVAIL: u8 = 0x9;
pub const GDT_A_TSS_BUSY: u8 = 0xB;

pub const GDT_F_PAGE_SIZE: u8 = 1 << 7;
pub const GDT_F_PROTECTED_MODE: u8 = 1 << 6;
pub const GDT_F_LONG_MODE: u8 = 1 << 5;

static INIT_GDT: [GdtEntry; 3] = [
    // Null
    GdtEntry::new(0, 0, 0, 0),
    // Kernel code
    GdtEntry::new(0, 0xFFFFF, GDT_A_PRESENT | GDT_A_RING_0 | GDT_A_SYSTEM | GDT_A_EXECUTABLE | GDT_A_PRIVILEGE, GDT_F_PAGE_SIZE | GDT_F_PROTECTED_MODE),
    // Kernel data
    GdtEntry::new(0, 0xFFFFF, GDT_A_PRESENT | GDT_A_RING_0 | GDT_A_SYSTEM | GDT_A_PRIVILEGE, GDT_F_PAGE_SIZE | GDT_F_PROTECTED_MODE),
];

const BASE_GDT: [GdtEntry; 9] = [
    // Null
    GdtEntry::new(0, 0, 0, 0),
    // Kernel code
    GdtEntry::new(0, 0xFFFFF, GDT_A_PRESENT | GDT_A_RING_0 | GDT_A_SYSTEM | GDT_A_EXECUTABLE | GDT_A_PRIVILEGE, GDT_F_PAGE_SIZE | GDT_F_PROTECTED_MODE),
    // Kernel data
    GdtEntry::new(0, 0xFFFFF, GDT_A_PRESENT | GDT_A_RING_0 | GDT_A_SYSTEM | GDT_A_PRIVILEGE, GDT_F_PAGE_SIZE | GDT_F_PROTECTED_MODE),
    // Kernel TLS
    GdtEntry::new(0, 0xFFFFF, GDT_A_PRESENT | GDT_A_RING_0 | GDT_A_SYSTEM | GDT_A_PRIVILEGE, GDT_F_PAGE_SIZE | GDT_F_PROTECTED_MODE),
    // User (32-bit) code
    GdtEntry::new(0, 0xFFFFF, GDT_A_PRESENT | GDT_A_RING_3 | GDT_A_SYSTEM | GDT_A_EXECUTABLE | GDT_A_PRIVILEGE, GDT_F_PAGE_SIZE | GDT_F_PROTECTED_MODE),
    // User data
    GdtEntry::new(0, 0xFFFFF, GDT_A_PRESENT | GDT_A_RING_3 | GDT_A_SYSTEM | GDT_A_PRIVILEGE, GDT_F_PAGE_SIZE | GDT_F_PROTECTED_MODE),
    // User FS (for TLS)
    GdtEntry::new(0, 0xFFFFF, GDT_A_PRESENT | GDT_A_RING_3 | GDT_A_SYSTEM | GDT_A_PRIVILEGE, GDT_F_PAGE_SIZE | GDT_F_PROTECTED_MODE),
    // User GS (for TLS)
    GdtEntry::new(0, 0xFFFFF, GDT_A_PRESENT | GDT_A_RING_3 | GDT_A_SYSTEM | GDT_A_PRIVILEGE, GDT_F_PAGE_SIZE | GDT_F_PROTECTED_MODE),
    // TSS
    GdtEntry::new(0, 0, GDT_A_PRESENT | GDT_A_RING_3 | GDT_A_TSS_AVAIL, 0),
];

#[repr(C, align(4096))]
pub struct ProcessorControlRegion {
    pub tcb_end: usize,
    pub user_rsp_tmp: usize,
    pub tss: TssWrapper,
    pub self_ref: usize,
    pub gdt: [GdtEntry; 9],
}

// NOTE: Despite not using #[repr(packed)], we do know that while there may be some padding
// inserted before and after the TSS, the main TSS structure will remain intact.
#[repr(C, align(16))]
pub struct TssWrapper(pub TaskStateSegment);

pub unsafe fn pcr() -> *mut ProcessorControlRegion {
    let mut ret: *mut ProcessorControlRegion;
    core::arch::asm!("mov {}, gs:[{}]", out(reg) ret, const(memoffset::offset_of!(ProcessorControlRegion, self_ref)));
    ret
}

#[cfg(feature = "pti")]
pub unsafe fn set_tss_stack(stack: usize) {
    use super::pti::{PTI_CPU_STACK, PTI_CONTEXT_STACK};
    addr_of_mut!((*pcr()).tss.0.ss0).write((GDT_KERNEL_DATA << 3) as u16);
    addr_of_mut!((*pcr()).tss.0.esp0).write((PTI_CPU_STACK.as_ptr() as usize + PTI_CPU_STACK.len()) as u32);
    PTI_CONTEXT_STACK = stack;
}

#[cfg(not(feature = "pti"))]
pub unsafe fn set_tss_stack(stack: usize) {
    addr_of_mut!((*pcr()).tss.0.ss0).write((GDT_KERNEL_DATA << 3) as u16);
    addr_of_mut!((*pcr()).tss.0.esp0).write(stack as u32);
}

/// Initialize a minimal GDT without configuring percpu.
pub unsafe fn init() {
    // Load the initial GDT, before the kernel remaps itself.
    dtables::lgdt(&DescriptorTablePointer {
        limit: (INIT_GDT.len() * mem::size_of::<GdtEntry>() - 1) as u16,
        base: INIT_GDT.as_ptr() as *const SegmentDescriptor,
    });

    // Load the segment descriptors
    segmentation::load_cs(SegmentSelector::new(GDT_KERNEL_CODE as u16, Ring::Ring0));
    segmentation::load_ds(SegmentSelector::new(GDT_KERNEL_DATA as u16, Ring::Ring0));
    segmentation::load_es(SegmentSelector::new(GDT_KERNEL_DATA as u16, Ring::Ring0));
    segmentation::load_fs(SegmentSelector::new(GDT_KERNEL_DATA as u16, Ring::Ring0));
    segmentation::load_gs(SegmentSelector::new(GDT_KERNEL_DATA as u16, Ring::Ring0));
    segmentation::load_ss(SegmentSelector::new(GDT_KERNEL_DATA as u16, Ring::Ring0));
}

/// Initialize GDT and configure percpu.
pub unsafe fn init_paging(stack_offset: usize) {
    let pcr_frame = crate::memory::allocate_frames(1).expect("failed to allocate PCR frame");
    let pcr = &mut *(RmmA::phys_to_virt(pcr_frame.start_address()).data() as *mut ProcessorControlRegion);

    pcr.self_ref = pcr as *const _ as usize;
    pcr.gdt = BASE_GDT;
    pcr.gdt[GDT_KERNEL_PERCPU].set_offset(pcr as *const _ as u32);

    let gdtr: DescriptorTablePointer<SegmentDescriptor> = DescriptorTablePointer {
        limit: (pcr.gdt.len() * mem::size_of::<GdtEntry>() - 1) as u16,
        base: pcr.gdt.as_ptr() as *const SegmentDescriptor,
    };

    pcr.tcb_end = init_percpu();

    {
        let tss = &pcr.tss.0 as *const _ as usize as u32;

        pcr.gdt[GDT_TSS].set_offset(tss);
        pcr.gdt[GDT_TSS].set_limit(mem::size_of::<TaskStateSegment>() as u32);
    }

    // Load the new GDT, which is correctly located in thread local storage.
    dtables::lgdt(&gdtr);

    // Reload the segment descriptors
    segmentation::load_cs(SegmentSelector::new(GDT_KERNEL_CODE as u16, Ring::Ring0));
    segmentation::load_ds(SegmentSelector::new(GDT_KERNEL_DATA as u16, Ring::Ring0));
    segmentation::load_es(SegmentSelector::new(GDT_KERNEL_DATA as u16, Ring::Ring0));
    segmentation::load_ss(SegmentSelector::new(GDT_KERNEL_DATA as u16, Ring::Ring0));

    // TODO: Use FS for kernel TLS on i686?
    segmentation::load_fs(SegmentSelector::new(GDT_KERNEL_DATA as u16, Ring::Ring0));
    segmentation::load_gs(SegmentSelector::new(GDT_KERNEL_PERCPU as u16, Ring::Ring0));

    // Set the stack pointer to use when coming back from userspace.
    set_tss_stack(stack_offset);

    // Load the task register
    task::load_tr(SegmentSelector::new(GDT_TSS as u16, Ring::Ring0));
}

// TODO: Share code with x86. Maybe even with aarch64?
/// Copy tdata, clear tbss, calculate TCB end pointer
#[cold]
unsafe fn init_percpu() -> usize {
    use crate::kernel_executable_offsets::*;

    let size = __tbss_end() - __tdata_start();
    assert_eq!(size % PAGE_SIZE, 0);

    let tbss_offset = __tbss_start() - __tdata_start();

    let base_frame = crate::memory::allocate_frames(size / PAGE_SIZE).expect("failed to allocate percpu memory");
    let base = RmmA::phys_to_virt(base_frame.start_address());

    let tls_end = base.data() + size;

    core::ptr::copy_nonoverlapping(__tdata_start() as *const u8, base.data() as *mut u8, tbss_offset);
    core::ptr::write_bytes((base.data() + tbss_offset) as *mut u8, 0, size - tbss_offset);

    tls_end
}

#[derive(Copy, Clone, Debug)]
#[repr(packed)]
pub struct GdtEntry {
    pub limitl: u16,
    pub offsetl: u16,
    pub offsetm: u8,
    pub access: u8,
    pub flags_limith: u8,
    pub offseth: u8
}

impl GdtEntry {
    pub const fn new(offset: u32, limit: u32, access: u8, flags: u8) -> Self {
        GdtEntry {
            limitl: limit as u16,
            offsetl: offset as u16,
            offsetm: (offset >> 16) as u8,
            access,
            flags_limith: flags & 0xF0 | ((limit >> 16) as u8) & 0x0F,
            offseth: (offset >> 24) as u8
        }
    }

    pub fn offset(&self) -> u32 {
        (self.offsetl as u32) |
        ((self.offsetm as u32) << 16) |
        ((self.offseth as u32) << 24)
    }

    pub fn set_offset(&mut self, offset: u32) {
        self.offsetl = offset as u16;
        self.offsetm = (offset >> 16) as u8;
        self.offseth = (offset >> 24) as u8;
    }

    pub fn set_limit(&mut self, limit: u32) {
        self.limitl = limit as u16;
        self.flags_limith = self.flags_limith & 0xF0 | ((limit >> 16) as u8) & 0x0F;
    }
}
