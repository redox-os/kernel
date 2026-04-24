use alloc::{boxed::Box, vec::Vec};
use core::{
    cell::{SyncUnsafeCell, UnsafeCell},
    mem::size_of,
    sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicUsize, Ordering},
};
#[cfg(target_arch = "x86_64")]
use rmm::Arch;

#[cfg(feature = "profiling")]
use crate::arch::{idt::Idt, interrupt::irq::aux_timer};
#[cfg(target_arch = "x86_64")]
use crate::arch::{
    interrupt::{self, InterruptStack},
    CurrentRmmArch,
};
use crate::{
    cpu_set::LogicalCpuId,
    percpu::PercpuBlock,
    syscall::{error::*, usercopy::UserSliceWo},
};

#[cfg(all(feature = "profiling", not(target_arch = "x86_64")))]
compile_error!("Profiling not supported outside x86_64");

const N: usize = 16 * 1024 * 1024;

pub struct RingBuffer {
    head: AtomicUsize,
    tail: AtomicUsize,
    buf: &'static [UnsafeCell<usize>; N],
    pub(crate) nmi_kcount: AtomicUsize,
    pub(crate) nmi_ucount: AtomicUsize,
}

impl RingBuffer {
    unsafe fn advance_head(&self, n: usize) {
        self.head.store(
            self.head.load(Ordering::Acquire).wrapping_add(n),
            Ordering::Release,
        );
    }
    unsafe fn advance_tail(&self, n: usize) {
        self.tail.store(
            self.tail.load(Ordering::Acquire).wrapping_add(n),
            Ordering::Release,
        );
    }
    unsafe fn sender_owned(&self) -> [&[UnsafeCell<usize>]; 2] {
        let head = self.head.load(Ordering::Acquire) % N;
        let tail = self.tail.load(Ordering::Acquire) % N;

        if head <= tail {
            [&self.buf[tail..], &self.buf[..head]]
        } else {
            [&self.buf[tail..head], &[]]
        }
    }
    unsafe fn receiver_owned(&self) -> [&[UnsafeCell<usize>]; 2] {
        let head = self.head.load(Ordering::Acquire) % N;
        let tail = self.tail.load(Ordering::Acquire) % N;

        if head > tail {
            [&self.buf[head..], &self.buf[..tail]]
        } else {
            [&self.buf[head..tail], &[]]
        }
    }
    pub unsafe fn extend(&self, mut slice: &[usize]) -> usize {
        let mut n = 0;
        for mut sender_slice in unsafe { self.sender_owned() } {
            while !slice.is_empty() && !sender_slice.is_empty() {
                unsafe { sender_slice[0].get().write(slice[0]) };
                slice = &slice[1..];
                sender_slice = &sender_slice[1..];
                n += 1;
            }
        }
        unsafe { self.advance_tail(n) };
        n
    }
    pub unsafe fn peek(&self) -> [&[usize]; 2] {
        unsafe {
            self.receiver_owned()
                .map(|slice| core::slice::from_raw_parts(slice.as_ptr().cast(), slice.len()))
        }
    }
    pub unsafe fn advance(&self, n: usize) {
        unsafe { self.advance_head(n) }
    }
    pub fn create() -> &'static Self {
        Box::leak(Box::new(Self {
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            buf: Box::leak(unsafe { Box::new_zeroed().assume_init() }),
            nmi_kcount: AtomicUsize::new(0),
            nmi_ucount: AtomicUsize::new(0),
        }))
    }
}

// SAFETY: must only be written by BSP, then constant
// TODO: probably insignificant, but maybe perf can be improved by replacing AtmomicPtr with
// SyncUnsafeCell?
static BUFS_RAW: SyncUnsafeCell<&'static [AtomicPtr<RingBuffer>]> = SyncUnsafeCell::new(&[]);

pub fn bufs() -> &'static [AtomicPtr<RingBuffer>] {
    unsafe { *BUFS_RAW.get() }
}

pub const PROFILE_TOGGLEABLE: bool = true;
pub static IS_PROFILING: AtomicBool = AtomicBool::new(false);

pub fn serio_command(index: usize, data: u8) {
    if cfg!(not(feature = "profiling")) {
        return;
    }

    if PROFILE_TOGGLEABLE {
        if index == 0 && data == 30 {
            // "a" key in QEMU
            info!("Enabling profiling");
            IS_PROFILING.store(true, Ordering::SeqCst);
        } else if index == 0 && data == 48 {
            // "b" key
            info!("Disabling profiling");
            IS_PROFILING.store(false, Ordering::SeqCst);
        }
    }
}

#[cfg_attr(not(feature = "profiling"), expect(dead_code))]
pub fn drain_buffer(cpu_num: LogicalCpuId, buf: UserSliceWo) -> Result<usize> {
    unsafe {
        let Some(src) = bufs()
            .get(cpu_num.get() as usize)
            .ok_or(Error::new(EBADFD))?
            .load(Ordering::Relaxed)
            .as_ref()
        else {
            return Ok(0);
        };
        let byte_slices = src.peek().map(|words| {
            core::slice::from_raw_parts(words.as_ptr().cast::<u8>(), size_of_val(words))
        });

        let copied_1 = buf.copy_common_bytes_from_slice(byte_slices[0])?;
        src.advance(copied_1 / size_of::<usize>());

        let copied_2 = if let Some(remaining) = buf.advance(copied_1) {
            remaining.copy_common_bytes_from_slice(byte_slices[1])?
        } else {
            0
        };
        src.advance(copied_2 / size_of::<usize>());

        Ok(copied_1 + copied_2)
    }
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn nmi_handler(stack: &InterruptStack) {
    if cfg!(not(feature = "profiling")) {
        return;
    }

    let Some(profiling) = crate::percpu::PercpuBlock::current().profiling else {
        return;
    };
    if !IS_PROFILING.load(Ordering::Relaxed) {
        return;
    }
    if stack.iret.cs & 0b00 == 0b11 {
        profiling.nmi_ucount.fetch_add(1, Ordering::Relaxed);
        return;
    } else if stack.iret.rflags & (1 << 9) != 0 {
        // Interrupts were enabled, i.e. we were in kmain, so ignore.
        return;
    } else {
        profiling.nmi_kcount.fetch_add(1, Ordering::Relaxed);
    };

    let mut buf = [0_usize; 32];
    buf[0] = stack.iret.rip & !(1 << 63);
    buf[1] = unsafe { x86::time::rdtsc() } as usize;

    let mut bp = stack.preserved.rbp;

    let mut len = 2;

    #[expect(clippy::needless_range_loop)]
    for i in 2..32 {
        if bp < CurrentRmmArch::PHYS_OFFSET
            || bp.saturating_add(16) >= CurrentRmmArch::PHYS_OFFSET + crate::PML4_SIZE
        {
            break;
        }
        let ip = unsafe { ((bp + 8) as *const usize).read() };
        bp = unsafe { (bp as *const usize).read() };

        if ip < crate::kernel_executable_offsets::__text_start()
            || ip >= crate::kernel_executable_offsets::__text_end()
        {
            break;
        }
        buf[i] = ip;

        len = i + 1;
    }

    let _ = unsafe { profiling.extend(&buf[..len]) };
}

static NUM_ORDINARY_CPUS: AtomicU32 = AtomicU32::new(u32::MAX);

#[cfg(feature = "profiling")]
pub fn cpu_exists(cpu: LogicalCpuId) -> bool {
    cpu.get() < NUM_ORDINARY_CPUS.load(Ordering::Relaxed)
}

fn profiler_cpu() -> LogicalCpuId {
    #[cfg(feature = "profiling")]
    return LogicalCpuId::new(NUM_ORDINARY_CPUS.load(Ordering::SeqCst));

    #[cfg(not(feature = "profiling"))]
    return LogicalCpuId::new(u32::MAX);
}

// SAFETY: must be called before any init()
pub unsafe fn allocate(total_cpu_count: u32) {
    if cfg!(not(feature = "profiling")) {
        return;
    }

    info!("Preliminary number of CPUs: {total_cpu_count}");

    let ordinary_cpu_count = total_cpu_count.checked_sub(1).unwrap();
    NUM_ORDINARY_CPUS.store(ordinary_cpu_count, Ordering::SeqCst);

    let slice = Box::leak(
        ((0..ordinary_cpu_count as usize)
            .map(|_| AtomicPtr::new(core::ptr::null_mut()))
            .collect::<Vec<_>>())
        .into_boxed_slice(),
    );
    unsafe {
        BUFS_RAW.get().write(slice);
    }
}

// SAFETY: must be called after allocate() or data races may occur
pub unsafe fn init() {
    if cfg!(not(feature = "profiling")) {
        return;
    }

    let percpu = PercpuBlock::current();

    if percpu.cpu_id == profiler_cpu() {
        return;
    }

    let profiling = RingBuffer::create();

    bufs()[percpu.cpu_id.get() as usize].store(
        (profiling as *const RingBuffer).cast_mut(),
        core::sync::atomic::Ordering::SeqCst,
    );
    unsafe {
        (core::ptr::addr_of!(percpu.profiling) as *mut Option<&'static RingBuffer>)
            .write(Some(profiling));
    }
}

static ACK: AtomicU32 = AtomicU32::new(0);

pub fn ready_for_profiling() {
    if cfg!(not(feature = "profiling")) {
        return;
    }

    ACK.fetch_add(1, Ordering::Relaxed);
}

pub fn maybe_run_profiling_helper_forever(cpu_id: LogicalCpuId) {
    if cfg!(not(feature = "profiling")) {
        return;
    }

    if cpu_id != profiler_cpu() {
        return;
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        for i in 33..255 {
            crate::arch::idt::IDTS
                .write()
                .get_mut(&cpu_id)
                .unwrap()
                .entries[i]
                .set_func(crate::arch::interrupt::ipi::wakeup);
        }

        let apic = &mut crate::arch::device::local_apic::the_local_apic();
        apic.set_lvt_timer((0b01 << 17) | 32);
        apic.set_div_conf(0b1011);
        apic.set_init_count(0x000f_ffff);

        while ACK.load(Ordering::Relaxed) < NUM_ORDINARY_CPUS.load(Ordering::SeqCst) {
            core::hint::spin_loop();
        }

        interrupt::enable_and_nop();
        loop {
            interrupt::halt();
        }
    }
}

#[cfg(feature = "profiling")]
pub fn maybe_setup_timer(idt: &mut Idt, cpu_id: LogicalCpuId) {
    if cfg!(not(feature = "profiling")) {
        return;
    }

    if cpu_id != profiler_cpu() {
        return;
    }
    idt.entries[32].set_func(aux_timer);
    idt.set_reserved_mut(32, true);
}
