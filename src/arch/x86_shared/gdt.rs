//! Global descriptor table

use core::ptr;

#[cfg(target_arch = "x86")]
use x86::bits32::task::TaskStateSegment;
#[cfg(target_arch = "x86_64")]
use x86::bits64::task::TaskStateSegment;
use x86::{
    dtables::{self, DescriptorTablePointer},
    segmentation::{self, Descriptor as SegmentDescriptor, SegmentSelector},
    task, Ring,
};

use crate::{
    cpu_set::LogicalCpuId,
    paging::{RmmA, RmmArch, PAGE_SIZE},
    percpu::PercpuBlock,
};

pub const GDT_NULL: usize = 0;
pub const GDT_KERNEL_CODE: usize = 1;
pub const GDT_KERNEL_DATA: usize = 2;
#[cfg(target_arch = "x86")]
pub const GDT_KERNEL_PERCPU: usize = 3;
#[cfg(target_arch = "x86_64")]
pub const GDT_USER_CODE32_UNUSED: usize = 3;
pub const GDT_USER_DATA: usize = 4;
pub const GDT_USER_CODE: usize = 5;
#[cfg(target_arch = "x86")]
pub const GDT_USER_FS: usize = 6;
#[cfg(target_arch = "x86")]
pub const GDT_USER_GS: usize = 7;
#[cfg(target_arch = "x86")]
pub const GDT_TSS: usize = 8;
#[cfg(target_arch = "x86_64")]
pub const GDT_TSS: usize = 6;
#[cfg(target_arch = "x86_64")]
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

#[cfg(target_arch = "x86")]
const SEGMENT_LIMIT: u32 = 0xFFFFF;
#[cfg(target_arch = "x86_64")]
const SEGMENT_LIMIT: u32 = 0;

#[cfg(target_arch = "x86")]
const SEGMENT_FLAGS: u8 = GDT_F_PAGE_SIZE | GDT_F_PROTECTED_MODE;
#[cfg(target_arch = "x86_64")]
const SEGMENT_FLAGS: u8 = GDT_F_LONG_MODE;

#[cfg(target_arch = "x86")]
const SEGMENT_COUNT: usize = 9;
#[cfg(target_arch = "x86_64")]
const SEGMENT_COUNT: usize = 8;

// Later copied into the actual GDT with various fields set.
const BASE_GDT: [GdtEntry; SEGMENT_COUNT] = [
    // Null
    GdtEntry::new(0, 0, 0, 0),
    // Kernel code
    GdtEntry::new(
        0,
        SEGMENT_LIMIT,
        GDT_A_PRESENT | GDT_A_RING_0 | GDT_A_SYSTEM | GDT_A_EXECUTABLE | GDT_A_PRIVILEGE,
        SEGMENT_FLAGS,
    ),
    // Kernel data
    GdtEntry::new(
        0,
        SEGMENT_LIMIT,
        GDT_A_PRESENT | GDT_A_RING_0 | GDT_A_SYSTEM | GDT_A_PRIVILEGE,
        SEGMENT_FLAGS,
    ),
    // Kernel TLS
    #[cfg(target_arch = "x86")]
    GdtEntry::new(
        0,
        SEGMENT_LIMIT,
        GDT_A_PRESENT | GDT_A_RING_0 | GDT_A_SYSTEM | GDT_A_PRIVILEGE,
        SEGMENT_FLAGS,
    ),
    // Dummy 32-bit user code - apparently necessary for SYSRET. We restrict it to ring 0 anyway.
    #[cfg(target_arch = "x86_64")]
    GdtEntry::new(
        0,
        0,
        GDT_A_PRESENT | GDT_A_RING_0 | GDT_A_SYSTEM | GDT_A_EXECUTABLE | GDT_A_PRIVILEGE,
        GDT_F_PROTECTED_MODE,
    ),
    // User data
    GdtEntry::new(
        0,
        SEGMENT_LIMIT,
        GDT_A_PRESENT | GDT_A_RING_3 | GDT_A_SYSTEM | GDT_A_PRIVILEGE,
        SEGMENT_FLAGS,
    ),
    // User code
    GdtEntry::new(
        0,
        SEGMENT_LIMIT,
        GDT_A_PRESENT | GDT_A_RING_3 | GDT_A_SYSTEM | GDT_A_EXECUTABLE | GDT_A_PRIVILEGE,
        SEGMENT_FLAGS,
    ),
    // User FS (for TLS)
    #[cfg(target_arch = "x86")]
    GdtEntry::new(
        0,
        SEGMENT_LIMIT,
        GDT_A_PRESENT | GDT_A_RING_3 | GDT_A_SYSTEM | GDT_A_PRIVILEGE,
        SEGMENT_FLAGS,
    ),
    // User GS (for TLS)
    #[cfg(target_arch = "x86")]
    GdtEntry::new(
        0,
        SEGMENT_LIMIT,
        GDT_A_PRESENT | GDT_A_RING_3 | GDT_A_SYSTEM | GDT_A_PRIVILEGE,
        SEGMENT_FLAGS,
    ),
    // TSS
    GdtEntry::new(0, 0, GDT_A_PRESENT | GDT_A_RING_3 | GDT_A_TSS_AVAIL, 0),
    // TSS must be 16 bytes long, twice the normal size
    #[cfg(target_arch = "x86_64")]
    GdtEntry::new(0, 0, 0, 0),
];

#[repr(C, align(16))]
struct Align([u64; 2]);

#[repr(C, align(4096))]
pub struct ProcessorControlRegion {
    // TODO: When both KASLR and KPTI are implemented, the PCR may need to be split into two pages,
    // such that "secret" kernel addresses are only stored in the protected half.
    pub self_ref: *mut ProcessorControlRegion,

    pub user_rsp_tmp: usize,
    // The GDT *must* be stored in the PCR! The paranoid interrupt handler, lacking a reliable way
    // to correctly obtain GSBASE, uses SGDT to calculate the PCR offset.
    pub gdt: [GdtEntry; SEGMENT_COUNT],
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

impl ProcessorControlRegion {
    const fn new_partial_init(cpu_id: LogicalCpuId) -> Self {
        Self {
            self_ref: ptr::null_mut(),
            user_rsp_tmp: 0,
            gdt: BASE_GDT,
            percpu: PercpuBlock::init(cpu_id),
            _rsvd: Align([0; 2]),
            tss: TaskStateSegment::new(),
            _iobitmap: [0; IOBITMAP_SIZE as usize],
            _all_ones: 0xFF,
        }
    }
}

pub unsafe fn pcr() -> *mut ProcessorControlRegion {
    unsafe {
        // Primitive benchmarking of RDFSBASE and RDGSBASE in userspace, appears to indicate that
        // obtaining FSBASE/GSBASE using mov gs:[gs_self_ref] is faster than using the (probably
        // microcoded) instructions.
        let mut ret: *mut ProcessorControlRegion;
        core::arch::asm!("mov {}, gs:[{}]", out(reg) ret, const(core::mem::offset_of!(ProcessorControlRegion, self_ref)));
        ret
    }
}

#[cfg(feature = "pti")]
pub unsafe fn set_tss_stack(pcr: *mut ProcessorControlRegion, stack: usize) {
    use super::pti::{PTI_CONTEXT_STACK, PTI_CPU_STACK};

    #[cfg(target_arch = "x86")]
    unsafe {
        core::ptr::addr_of_mut!((*pcr).tss.ss0).write((GDT_KERNEL_DATA << 3) as u16);
        core::ptr::addr_of_mut!((*pcr).tss.esp0)
            .write((PTI_CPU_STACK.as_ptr() as usize + PTI_CPU_STACK.len()) as u32);
    }

    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::ptr::addr_of_mut!((*pcr).tss.rsp[0])
            .write_unaligned((PTI_CPU_STACK.as_ptr() as usize + PTI_CPU_STACK.len()) as u64);
    }

    unsafe { PTI_CONTEXT_STACK = stack };
}

#[cfg(not(feature = "pti"))]
pub unsafe fn set_tss_stack(pcr: *mut ProcessorControlRegion, stack: usize) {
    #[cfg(target_arch = "x86")]
    unsafe {
        core::ptr::addr_of_mut!((*pcr).tss.ss0).write((GDT_KERNEL_DATA << 3) as u16);
        core::ptr::addr_of_mut!((*pcr).tss.esp0).write(stack as u32);
    }

    #[cfg(target_arch = "x86_64")]
    unsafe {
        // TODO: If this increases performance, read gs:[offset] directly
        core::ptr::addr_of_mut!((*pcr).tss.rsp[0]).write_unaligned(stack as u64);
    }
}

pub unsafe fn set_userspace_io_allowed(pcr: *mut ProcessorControlRegion, allowed: bool) {
    let offset = if allowed {
        u16::try_from(size_of::<TaskStateSegment>()).unwrap()
    } else {
        0xFFFF
    };

    unsafe {
        #[cfg(target_arch = "x86")]
        core::ptr::addr_of_mut!((*pcr).tss.iobp_offset).write(offset);

        #[cfg(target_arch = "x86_64")]
        core::ptr::addr_of_mut!((*pcr).tss.iomap_base).write(offset);
    }
}

#[cold]
fn init_pcr(pcr: &mut ProcessorControlRegion, stack_end: usize) {
    pcr.self_ref = pcr as *mut _;

    // Setup the GDT.
    pcr.gdt = BASE_GDT;
    #[cfg(target_arch = "x86")]
    pcr.gdt[GDT_KERNEL_PERCPU].set_offset(pcr as *const _ as u32);

    #[cfg(target_arch = "x86")]
    {
        pcr.tss.iobp_offset = 0xFFFF;
        let tss = &pcr.tss as *const _ as usize as u32;

        pcr.gdt[GDT_TSS].set_offset(tss);
        pcr.gdt[GDT_TSS].set_limit(size_of::<TaskStateSegment>() as u32 + IOBITMAP_SIZE as u32);
    }

    #[cfg(target_arch = "x86_64")]
    {
        pcr.tss.iomap_base = 0xFFFF;

        let tss = &mut pcr.tss as *mut TaskStateSegment as usize as u64;
        let tss_lo = (tss & 0xFFFF_FFFF) as u32;
        let tss_hi = (tss >> 32) as u32;

        pcr.gdt[GDT_TSS].set_offset(tss_lo);
        pcr.gdt[GDT_TSS].set_limit(size_of::<TaskStateSegment>() as u32 + IOBITMAP_SIZE);

        unsafe {
            (&mut pcr.gdt[GDT_TSS_HIGH] as *mut GdtEntry)
                .cast::<u32>()
                .write(tss_hi);
        }
    }

    // Set the stack pointer to use when coming back from userspace.
    unsafe {
        set_tss_stack(pcr, stack_end);
    }
}

#[cold]
pub unsafe fn install_pcr(pcr_ptr: *mut ProcessorControlRegion) {
    let pcr = unsafe { &mut *pcr_ptr };

    let gdtr: DescriptorTablePointer<SegmentDescriptor> = DescriptorTablePointer {
        limit: const { (SEGMENT_COUNT * size_of::<GdtEntry>() - 1) as u16 },
        base: pcr.gdt.as_ptr() as *const SegmentDescriptor,
    };

    // Load the new GDT, which is correctly located in thread local storage.
    unsafe { dtables::lgdt(&gdtr) };

    #[cfg(target_arch = "x86")]
    unsafe {
        // Reload the segment descriptors
        segmentation::load_cs(SegmentSelector::new(GDT_KERNEL_CODE as u16, Ring::Ring0));
        segmentation::load_ds(SegmentSelector::new(GDT_USER_DATA as u16, Ring::Ring3));
        segmentation::load_es(SegmentSelector::new(GDT_USER_DATA as u16, Ring::Ring3));
        segmentation::load_ss(SegmentSelector::new(GDT_KERNEL_DATA as u16, Ring::Ring0));

        // TODO: Use FS for kernel percpu on i686?
        segmentation::load_fs(SegmentSelector::new(GDT_USER_FS as u16, Ring::Ring0));
        segmentation::load_gs(SegmentSelector::new(GDT_KERNEL_PERCPU as u16, Ring::Ring0));
    }

    #[cfg(target_arch = "x86_64")]
    unsafe {
        // Load segments again, possibly resetting FSBASE and GSBASE.
        segmentation::load_cs(SegmentSelector::new(GDT_KERNEL_CODE as u16, Ring::Ring0));
        segmentation::load_ss(SegmentSelector::new(GDT_KERNEL_DATA as u16, Ring::Ring0));

        segmentation::load_ds(SegmentSelector::from_raw(0));
        segmentation::load_es(SegmentSelector::from_raw(0));
        segmentation::load_fs(SegmentSelector::from_raw(0));

        // What happens when GS is loaded with a NULL selector, is undefined on Intel CPUs. However,
        // GSBASE is set later.
        segmentation::load_gs(SegmentSelector::from_raw(0));

        // Ensure that GSBASE always points to the PCR in kernel space.
        x86::msr::wrmsr(x86::msr::IA32_GS_BASE, pcr as *mut _ as usize as u64);

        // While GSBASE points to the PCR in kernel space, userspace is free to set it to other values.
        // Zero-initialize userspace's GSBASE. The reason the GSBASE register writes are reversed, is
        // because entering usermode will entail executing the SWAPGS instruction.
        x86::msr::wrmsr(x86::msr::IA32_KERNEL_GSBASE, 0);

        // Set the userspace FSBASE to zero.
        x86::msr::wrmsr(x86::msr::IA32_FS_BASE, 0);
    }

    // Load the task register
    unsafe { task::load_tr(SegmentSelector::new(GDT_TSS as u16, Ring::Ring0)) };

    unsafe { crate::percpu::init_tlb_shootdown(pcr.percpu.cpu_id, &mut pcr.percpu) };
}

/// Initialize GDT and configure percpu for the BSP.
#[cold]
pub unsafe fn init_bsp(stack_end: usize) {
    static mut BSP_PCR: ProcessorControlRegion =
        ProcessorControlRegion::new_partial_init(LogicalCpuId::BSP);

    init_pcr(unsafe { &mut *ptr::addr_of_mut!(BSP_PCR) }, stack_end);

    unsafe { install_pcr(ptr::addr_of_mut!(BSP_PCR)) };
}

#[cold]
pub fn allocate_and_init_pcr(
    cpu_id: LogicalCpuId,
    stack_end: usize,
) -> *mut ProcessorControlRegion {
    let alloc_order = size_of::<ProcessorControlRegion>()
        .div_ceil(PAGE_SIZE)
        .next_power_of_two()
        .trailing_zeros();

    let pcr_frame = crate::memory::allocate_p2frame(alloc_order).expect("failed to allocate PCR");
    let pcr_ptr =
        unsafe { RmmA::phys_to_virt(pcr_frame.base()).data() as *mut ProcessorControlRegion };
    unsafe { core::ptr::write(pcr_ptr, ProcessorControlRegion::new_partial_init(cpu_id)) };

    init_pcr(unsafe { &mut *pcr_ptr }, stack_end);

    pcr_ptr
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

    #[cfg(target_arch = "x86")]
    pub const fn offset(&self) -> u32 {
        (self.offsetl as u32) | ((self.offsetm as u32) << 16) | ((self.offseth as u32) << 24)
    }

    pub const fn set_offset(&mut self, offset: u32) {
        self.offsetl = offset as u16;
        self.offsetm = (offset >> 16) as u8;
        self.offseth = (offset >> 24) as u8;
    }

    pub const fn set_limit(&mut self, limit: u32) {
        self.limitl = limit as u16;
        self.flags_limith = self.flags_limith & 0xF0 | ((limit >> 16) as u8) & 0x0F;
    }
}

impl PercpuBlock {
    pub fn current() -> &'static Self {
        unsafe { &*core::ptr::addr_of!((*pcr()).percpu) }
    }
}
