use core::{
    cell::UnsafeCell,
    mem::size_of,
    sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicUsize, Ordering},
};

use alloc::boxed::Box;

use crate::{
    cpu_set::LogicalCpuId,
    idt::Idt,
    interrupt,
    interrupt::{irq::aux_timer, InterruptStack},
    percpu::PercpuBlock,
    syscall::{error::*, usercopy::UserSliceWo},
};

const N: usize = 16 * 1024 * 1024;

pub const HARDCODED_CPU_COUNT: u32 = 4;

pub const PROFILER_CPU: LogicalCpuId = LogicalCpuId::new(HARDCODED_CPU_COUNT);

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
        for mut sender_slice in self.sender_owned() {
            while !slice.is_empty() && !sender_slice.is_empty() {
                sender_slice[0].get().write(slice[0]);
                slice = &slice[1..];
                sender_slice = &sender_slice[1..];
                n += 1;
            }
        }
        self.advance_tail(n);
        n
    }
    pub unsafe fn peek(&self) -> [&[usize]; 2] {
        self.receiver_owned()
            .map(|slice| core::slice::from_raw_parts(slice.as_ptr().cast(), slice.len()))
    }
    pub unsafe fn advance(&self, n: usize) {
        self.advance_head(n)
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
const NULL: AtomicPtr<RingBuffer> = AtomicPtr::new(core::ptr::null_mut());
pub static BUFS: [AtomicPtr<RingBuffer>; 4] = [NULL; 4];

pub const PROFILE_TOGGLEABLE: bool = true;
pub static IS_PROFILING: AtomicBool = AtomicBool::new(false);

pub fn serio_command(index: usize, data: u8) {
    if PROFILE_TOGGLEABLE {
        if index == 0 && data == 30 {
            // "a" key in QEMU
            log::info!("Enabling profiling");
            IS_PROFILING.store(true, Ordering::SeqCst);
        } else if index == 0 && data == 48 {
            // "b" key
            log::info!("Disabling profiling");
            IS_PROFILING.store(false, Ordering::SeqCst);
        }
    }
}

pub fn drain_buffer(cpu_num: LogicalCpuId, buf: UserSliceWo) -> Result<usize> {
    unsafe {
        let Some(src) = BUFS
            .get(cpu_num.get() as usize)
            .ok_or(Error::new(EBADFD))?
            .load(Ordering::Relaxed)
            .as_ref()
        else {
            return Ok(0);
        };
        let byte_slices = src.peek().map(|words| {
            core::slice::from_raw_parts(
                words.as_ptr().cast::<u8>(),
                words.len() * size_of::<usize>(),
            )
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

pub unsafe fn nmi_handler(stack: &InterruptStack) {
    let Some(profiling) = crate::percpu::PercpuBlock::current().profiling else {
        return;
    };
    if !IS_PROFILING.load(Ordering::Relaxed) {
        return;
    }
    if stack.iret.cs & 0b00 == 0b11 {
        profiling.nmi_ucount.store(
            profiling.nmi_ucount.load(Ordering::Relaxed) + 1,
            Ordering::Relaxed,
        );
        return;
    } else if stack.iret.rflags & (1 << 9) != 0 {
        // Interrupts were enabled, i.e. we were in kmain, so ignore.
        return;
    } else {
        profiling.nmi_kcount.store(
            profiling.nmi_kcount.load(Ordering::Relaxed) + 1,
            Ordering::Relaxed,
        );
    };

    let mut buf = [0_usize; 32];
    buf[0] = stack.iret.rip & !(1 << 63);
    buf[1] = x86::time::rdtsc() as usize;

    let mut bp = stack.preserved.rbp;

    let mut len = 2;

    for i in 2..32 {
        if bp < crate::PHYS_OFFSET || bp.saturating_add(16) >= crate::PHYS_OFFSET + crate::PML4_SIZE
        {
            break;
        }
        let ip = ((bp + 8) as *const usize).read();
        bp = (bp as *const usize).read();

        if ip < crate::kernel_executable_offsets::__text_start()
            || ip >= crate::kernel_executable_offsets::__text_end()
        {
            break;
        }
        buf[i] = ip;

        len = i + 1;
    }

    let _ = profiling.extend(&buf[..len]);
}
pub unsafe fn init() {
    let percpu = PercpuBlock::current();

    if percpu.cpu_id == PROFILER_CPU {
        return;
    }

    let profiling = RingBuffer::create();

    BUFS[percpu.cpu_id.get() as usize].store(
        profiling as *const _ as *mut _,
        core::sync::atomic::Ordering::SeqCst,
    );
    (core::ptr::addr_of!(percpu.profiling) as *mut Option<&'static RingBuffer>)
        .write(Some(profiling));
}

static ACK: AtomicU32 = AtomicU32::new(0);

pub fn ready_for_profiling() {
    ACK.fetch_add(1, Ordering::Relaxed);
}

pub fn maybe_run_profiling_helper_forever(cpu_id: LogicalCpuId) {
    if cpu_id != PROFILER_CPU {
        return;
    }
    unsafe {
        for i in 33..255 {
            crate::idt::IDTS
                .write()
                .as_mut()
                .unwrap()
                .get_mut(&cpu_id)
                .unwrap()
                .entries[i]
                .set_func(crate::interrupt::ipi::wakeup);
        }

        let apic = &mut crate::device::local_apic::the_local_apic();
        apic.set_lvt_timer((0b01 << 17) | 32);
        apic.set_div_conf(0b1011);
        apic.set_init_count(0xffff_f);

        while ACK.load(Ordering::Relaxed) < HARDCODED_CPU_COUNT {
            core::hint::spin_loop();
        }
        assert_eq!(crate::cpu_count(), HARDCODED_CPU_COUNT + 1);

        interrupt::enable_and_nop();
        loop {
            interrupt::halt();
        }
    }
}

pub fn maybe_setup_timer(idt: &mut Idt, cpu_id: LogicalCpuId) {
    if cpu_id != PROFILER_CPU {
        return;
    }
    idt.entries[32].set_func(aux_timer);
    idt.set_reserved_mut(32, true);
}
