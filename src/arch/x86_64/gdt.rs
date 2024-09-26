//! Global descriptor table

use core::{convert::TryInto, mem::size_of};

use crate::{
    cpu_set::LogicalCpuId,
    paging::{RmmA, RmmArch, PAGE_SIZE},
    percpu::PercpuBlock,
};

use x86::{
    bits64::task::TaskStateSegment,
    dtables::{self, DescriptorTablePointer},
    segmentation::{self, Descriptor as SegmentDescriptor, SegmentSelector},
    task, Ring,
};

pub const GDT_NULL: usize = 0;
pub const GDT_KERNEL_CODE: usize = 1;
pub const GDT_KERNEL_DATA: usize = 2;
pub const GDT_USER_CODE32_UNUSED: usize = 3;
pub const GDT_USER_DATA: usize = 4;
pub const GDT_USER_CODE: usize = 5;
pub const GDT_TSS: usize = 6;
pub const GDT_TSS_HIGH: usize = 7;

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

const IOBITMAP_SIZE: u32 = 65536 / 8;

static mut INIT_GDT: [GdtEntry; 3] = [
    // Null
    GdtEntry::new(0, 0, 0, 0),
    // Kernel code
    GdtEntry::new(
        0,
        0,
        GDT_A_PRESENT | GDT_A_RING_0 | GDT_A_SYSTEM | GDT_A_EXECUTABLE | GDT_A_PRIVILEGE,
        GDT_F_LONG_MODE,
    ),
    // Kernel data
    GdtEntry::new(
        0,
        0,
        GDT_A_PRESENT | GDT_A_RING_0 | GDT_A_SYSTEM | GDT_A_PRIVILEGE,
        GDT_F_LONG_MODE,
    ),
];

// Later copied into the actual GDT with various fields set.
const BASE_GDT: [GdtEntry; 8] = [
    // Null
    GdtEntry::new(0, 0, 0, 0),
    // Kernel code
    GdtEntry::new(
        0,
        0,
        GDT_A_PRESENT | GDT_A_RING_0 | GDT_A_SYSTEM | GDT_A_EXECUTABLE | GDT_A_PRIVILEGE,
        GDT_F_LONG_MODE,
    ),
    // Kernel data
    GdtEntry::new(
        0,
        0,
        GDT_A_PRESENT | GDT_A_RING_0 | GDT_A_SYSTEM | GDT_A_PRIVILEGE,
        GDT_F_LONG_MODE,
    ),
    // Dummy 32-bit user code - apparently necessary for SYSRET. We restrict it to ring 0 anyway.
    GdtEntry::new(
        0,
        0,
        GDT_A_PRESENT | GDT_A_RING_0 | GDT_A_SYSTEM | GDT_A_EXECUTABLE | GDT_A_PRIVILEGE,
        GDT_F_PROTECTED_MODE,
    ),
    // User data
    GdtEntry::new(
        0,
        0,
        GDT_A_PRESENT | GDT_A_RING_3 | GDT_A_SYSTEM | GDT_A_PRIVILEGE,
        GDT_F_LONG_MODE,
    ),
    // User (64-bit) code
    GdtEntry::new(
        0,
        0,
        GDT_A_PRESENT | GDT_A_RING_3 | GDT_A_SYSTEM | GDT_A_EXECUTABLE | GDT_A_PRIVILEGE,
        GDT_F_LONG_MODE,
    ),
    // TSS
    GdtEntry::new(0, 0, GDT_A_PRESENT | GDT_A_RING_3 | GDT_A_TSS_AVAIL, 0),
    // TSS must be 16 bytes long, twice the normal size
    GdtEntry::new(0, 0, 0, 0),
];

#[repr(C, align(16))]
struct Align([usize; 2]);

#[repr(C, align(4096))]
pub struct ProcessorControlRegion {
    // TODO: When both KASLR and KPTI are implemented, the PCR may need to be split into two pages,
    // such that "secret" kernel addresses are only stored in the protected half.
    pub self_ref: usize,

    pub user_rsp_tmp: usize,
    // The GDT *must* be stored in the PCR! The paranoid interrupt handler, lacking a reliable way
    // to correctly obtain GSBASE, uses SGDT to calculate the PCR offset.
    pub gdt: [GdtEntry; 8],
    pub percpu: PercpuBlock,
    _rsvd: Align,
    pub tss: TaskStateSegment,

    // These two fields are read by the CPU, but not currently modified by the kernel. Instead, the
    // kernel sets the `iomap_base` field in the TSS, to either point to this bitmap, or outside
    // the TSS, in which case userspace is not granted port IO access.
    pub _iobitmap: [u8; IOBITMAP_SIZE as usize],
    pub _all_ones: u8,
}

const _: () = {
    if core::mem::offset_of!(ProcessorControlRegion, tss) % 16 != 0 {
        panic!("PCR is incorrectly defined, TSS alignment is too small");
    }
    if core::mem::offset_of!(ProcessorControlRegion, gdt) % 8 != 0 {
        panic!("PCR is incorrectly defined, GDT alignment is too small");
    }
};

pub unsafe fn pcr() -> *mut ProcessorControlRegion {
    // Primitive benchmarking of RDFSBASE and RDGSBASE in userspace, appears to indicate that
    // obtaining FSBASE/GSBASE using mov gs:[gs_self_ref] is faster than using the (probably
    // microcoded) instructions.
    let mut ret: *mut ProcessorControlRegion;
    core::arch::asm!("mov {}, gs:[{}]", out(reg) ret, const(core::mem::offset_of!(ProcessorControlRegion, self_ref)));
    ret
}

#[cfg(feature = "pti")]
pub unsafe fn set_tss_stack(pcr: *mut ProcessorControlRegion, stack: usize) {
    use super::pti::{PTI_CONTEXT_STACK, PTI_CPU_STACK};
    core::ptr::addr_of_mut!((*pcr).tss.rsp[0])
        .write_unaligned((PTI_CPU_STACK.as_ptr() as usize + PTI_CPU_STACK.len()) as u64);
    PTI_CONTEXT_STACK = stack;
}

#[cfg(not(feature = "pti"))]
pub unsafe fn set_tss_stack(pcr: *mut ProcessorControlRegion, stack: usize) {
    // TODO: If this increases performance, read gs:[offset] directly
    core::ptr::addr_of_mut!((*pcr).tss.rsp[0]).write_unaligned(stack as u64);
}

pub unsafe fn set_userspace_io_allowed(pcr: *mut ProcessorControlRegion, allowed: bool) {
    let offset = if allowed {
        u16::try_from(size_of::<TaskStateSegment>()).unwrap()
    } else {
        0xFFFF
    };
    core::ptr::addr_of_mut!((*pcr).tss.iomap_base).write(offset);
}

// Initialize startup GDT
#[cold]
pub unsafe fn init() {
    // Before the kernel can remap itself, it needs to switch to a GDT it controls. Start with a
    // minimal kernel-only GDT.
    dtables::lgdt(&DescriptorTablePointer {
        limit: (INIT_GDT.len() * size_of::<GdtEntry>() - 1) as u16,
        base: INIT_GDT.as_ptr() as *const SegmentDescriptor,
    });

    load_segments();
}
#[cold]
unsafe fn load_segments() {
    segmentation::load_cs(SegmentSelector::new(GDT_KERNEL_CODE as u16, Ring::Ring0));
    segmentation::load_ss(SegmentSelector::new(GDT_KERNEL_DATA as u16, Ring::Ring0));

    segmentation::load_ds(SegmentSelector::from_raw(0));
    segmentation::load_es(SegmentSelector::from_raw(0));
    segmentation::load_fs(SegmentSelector::from_raw(0));

    // What happens when GS is loaded with a NULL selector, is undefined on Intel CPUs. However,
    // GSBASE is set later, and percpu is not used until gdt::init_paging().
    segmentation::load_gs(SegmentSelector::from_raw(0));
}

/// Initialize GDT and PCR.
#[cold]
pub unsafe fn init_paging(stack_offset: usize, cpu_id: LogicalCpuId) {
    let alloc_order = size_of::<ProcessorControlRegion>()
        .div_ceil(PAGE_SIZE)
        .next_power_of_two()
        .trailing_zeros();
    let pcr_frame = crate::memory::allocate_p2frame(alloc_order).expect("failed to allocate PCR");
    let pcr = &mut *(RmmA::phys_to_virt(pcr_frame.base()).data() as *mut ProcessorControlRegion);

    pcr.self_ref = pcr as *mut ProcessorControlRegion as usize;

    // Setup the GDT.
    pcr.gdt = BASE_GDT;

    let limit = (pcr.gdt.len() * size_of::<GdtEntry>() - 1)
        .try_into()
        .expect("main GDT way too large");
    let base = pcr.gdt.as_ptr() as *const SegmentDescriptor;

    let gdtr: DescriptorTablePointer<SegmentDescriptor> = DescriptorTablePointer { limit, base };

    {
        pcr.tss.iomap_base = 0xFFFF;
        pcr._all_ones = 0xFF;

        let tss = &mut pcr.tss as *mut TaskStateSegment as usize as u64;
        let tss_lo = (tss & 0xFFFF_FFFF) as u32;
        let tss_hi = (tss >> 32) as u32;

        pcr.gdt[GDT_TSS].set_offset(tss_lo);
        pcr.gdt[GDT_TSS].set_limit(size_of::<TaskStateSegment>() as u32 + IOBITMAP_SIZE);

        (&mut pcr.gdt[GDT_TSS_HIGH] as *mut GdtEntry)
            .cast::<u32>()
            .write(tss_hi);
    }

    // Load the new GDT, which is correctly located in thread local storage.
    dtables::lgdt(&gdtr);

    // Load segments again, possibly resetting FSBASE and GSBASE.
    load_segments();

    // Ensure that GSBASE always points to the PCR in kernel space.
    x86::msr::wrmsr(x86::msr::IA32_GS_BASE, pcr as *mut _ as usize as u64);

    // While GSBASE points to the PCR in kernel space, userspace is free to set it to other values.
    // Zero-initialize userspace's GSBASE. The reason the GSBASE register writes are reversed, is
    // because entering usermode will entail executing the SWAPGS instruction.
    x86::msr::wrmsr(x86::msr::IA32_KERNEL_GSBASE, 0);

    // Set the userspace FSBASE to zero.
    x86::msr::wrmsr(x86::msr::IA32_FS_BASE, 0);

    // Set the stack pointer to use when coming back from userspace.
    set_tss_stack(pcr, stack_offset);

    // Load the task register
    task::load_tr(SegmentSelector::new(GDT_TSS as u16, Ring::Ring0));

    pcr.percpu = PercpuBlock::init(cpu_id);

    crate::percpu::init_tlb_shootdown(cpu_id, &mut pcr.percpu);
}
#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
pub struct GdtEntry {
    pub limitl: u16,
    pub offsetl: u16,
    pub offsetm: u8,
    pub access: u8,
    pub flags_limith: u8,
    pub offseth: u8,
}

impl GdtEntry {
    pub const fn new(offset: u32, limit: u32, access: u8, flags: u8) -> Self {
        GdtEntry {
            limitl: limit as u16,
            offsetl: offset as u16,
            offsetm: (offset >> 16) as u8,
            access,
            flags_limith: flags & 0xF0 | ((limit >> 16) as u8) & 0x0F,
            offseth: (offset >> 24) as u8,
        }
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

impl PercpuBlock {
    pub fn current() -> &'static Self {
        unsafe { &*core::ptr::addr_of!((*pcr()).percpu) }
    }
}
