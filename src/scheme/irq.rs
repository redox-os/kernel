// TODO: Rewrite this entire scheme. Legacy x86 APIs should be abstracted by a userspace scheme,
// this scheme should only handle raw IRQ registration and delivery to userspace.

use core::{
    mem, str,
    str::FromStr,
    sync::atomic::{AtomicUsize, Ordering},
};

use alloc::{collections::BTreeMap, string::String, vec::Vec};

use spin::{Mutex, Once, RwLock};
use syscall::dirent::{DirEntry, DirentBuf, DirentKind};

use crate::context::file::InternalFlags;

use super::{CallerCtx, GlobalSchemes, OpenResult};
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
use crate::arch::interrupt::{available_irqs_iter, irq::acknowledge, is_reserved, set_reserved};
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
use crate::dtb::irqchip::{acknowledge, available_irqs_iter, is_reserved, set_reserved, IRQ_CHIP};
use crate::{
    arch::interrupt::bsp_apic_id,
    cpu_set::LogicalCpuId,
    event,
    syscall::{
        data::Stat,
        error::*,
        flag::{EventFlags, EVENT_READ, MODE_CHR, MODE_DIR, O_CREAT, O_DIRECTORY, O_STAT},
        usercopy::{UserSliceRo, UserSliceWo},
    },
};

///
/// IRQ queues
pub(super) static COUNTS: Mutex<[usize; 224]> = Mutex::new([0; 224]);
// Using BTreeMap as hashbrown doesn't have a const constructor.
static HANDLES: RwLock<BTreeMap<usize, Handle>> = RwLock::new(BTreeMap::new());

/// These are IRQs 0..=15 (corresponding to interrupt vectors 32..=47). They are opened without the
/// O_CREAT flag.
const BASE_IRQ_COUNT: u8 = 16;

/// These are the extended IRQs, 16..=223 (interrupt vectors 48..=255). Some of them are reserved
/// for other devices, and some other interrupt vectors like 0x80 (software interrupts) and
/// 0x40..=0x43 (IPI).
///
/// Since these are non-sharable, they must be opened with O_CREAT, which then reserves them. They
/// are only freed when the file descriptor is closed.
const TOTAL_IRQ_COUNT: u8 = 224;

const INO_TOPLEVEL: u64 = 0x8002_0000_0000_0000;
const INO_AVAIL: u64 = 0x8000_0000_0000_0000;
const INO_BSP: u64 = 0x8001_0000_0000_0000;
const INO_PHANDLE: u64 = 0x8003_0000_0000_0000;

/// Add to the input queue
#[no_mangle]
pub extern "C" fn irq_trigger(irq: u8) {
    COUNTS.lock()[irq as usize] += 1;

    for (fd, _) in HANDLES
        .read()
        .iter()
        .filter_map(|(fd, handle)| Some((fd, handle.as_irq_handle()?)))
        .filter(|&(_, (_, handle_irq))| handle_irq == irq)
    {
        event::trigger(GlobalSchemes::Irq.scheme_id(), *fd, EVENT_READ);
    }
}

#[allow(dead_code)]
enum Handle {
    Irq { ack: AtomicUsize, irq: u8 },
    Avail(u8), // CPU id
    TopLevel,
    Phandle(u8, Vec<u8>),
    Bsp,
}
impl Handle {
    fn as_irq_handle<'a>(&'a self) -> Option<(&'a AtomicUsize, u8)> {
        match self {
            &Self::Irq { ref ack, irq } => Some((ack, irq)),
            _ => None,
        }
    }
}

static NEXT_FD: AtomicUsize = AtomicUsize::new(1);
static CPUS: Once<Vec<u8>> = Once::new();

pub struct IrqScheme;

impl IrqScheme {
    pub fn init() {
        #[cfg(all(feature = "acpi", any(target_arch = "x86", target_arch = "x86_64")))]
        let cpus = {
            use crate::acpi::madt::*;

            match unsafe { MADT.as_ref() } {
                Some(madt) => madt
                    .iter()
                    .filter_map(|entry| match entry {
                        MadtEntry::LocalApic(apic) => Some(apic.id),
                        _ => None,
                    })
                    .collect::<Vec<_>>(),
                None => {
                    log::warn!("no MADT found, defaulting to 1 CPU");
                    vec![0]
                }
            }
        };
        #[cfg(not(all(feature = "acpi", any(target_arch = "x86", target_arch = "x86_64"))))]
        let cpus = vec![0];

        CPUS.call_once(|| cpus);
    }
    fn open_ext_irq(flags: usize, cpu_id: u8, path_str: &str) -> Result<(Handle, InternalFlags)> {
        let irq_number = u8::from_str(path_str).or(Err(Error::new(ENOENT)))?;

        Ok(
            if irq_number < BASE_IRQ_COUNT && Some(u32::from(cpu_id)) == bsp_apic_id() {
                // Give legacy IRQs only to `irq:{0..15}` and `irq:cpu-<BSP>/{0..15}` (same handles).
                //
                // The only CPUs don't have the legacy IRQs in their IDTs.

                (
                    Handle::Irq {
                        ack: AtomicUsize::new(0),
                        irq: irq_number,
                    },
                    InternalFlags::empty(),
                )
            } else if irq_number < TOTAL_IRQ_COUNT {
                if flags & O_CREAT == 0 && flags & O_STAT == 0 {
                    return Err(Error::new(EINVAL));
                }
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                if flags & O_STAT == 0 {
                    if is_reserved(LogicalCpuId::new(cpu_id.into()), irq_to_vector(irq_number)) {
                        return Err(Error::new(EEXIST));
                    }
                    set_reserved(
                        LogicalCpuId::new(cpu_id.into()),
                        irq_to_vector(irq_number),
                        true,
                    );
                }
                (
                    Handle::Irq {
                        ack: AtomicUsize::new(0),
                        irq: irq_number,
                    },
                    InternalFlags::empty(),
                )
            } else {
                return Err(Error::new(ENOENT));
            },
        )
    }

    #[cfg(dtb)]
    unsafe fn open_phandle_irq(
        flags: usize,
        phandle: usize,
        path_str: &str,
    ) -> Result<(Handle, InternalFlags)> {
        let mut path_iter = path_str.split(',');
        let addr = path_iter.next_chunk::<3>().or(Err(Error::new(ENOENT)))?;
        if path_iter.next().is_some() {
            return Err(Error::new(ENOENT));
        }
        let addr = [
            u32::from_str(addr[0]).or(Err(Error::new(ENOENT)))?,
            u32::from_str(addr[1]).or(Err(Error::new(ENOENT)))?,
            u32::from_str(addr[2]).or(Err(Error::new(ENOENT)))?,
        ];
        let ic_idx = IRQ_CHIP
            .phandle_to_ic_idx(phandle as u32)
            .ok_or(Error::new(ENOENT))?;
        Ok({
            if flags & O_CREAT == 0 && flags & O_STAT == 0 {
                return Err(Error::new(EINVAL));
            }
            let irq_number = IRQ_CHIP
                .irq_xlate(ic_idx, &addr)
                .or(Err(Error::new(ENOENT)))?;
            log::debug!("open_phandle_irq  virq={}", irq_number);
            if flags & O_STAT == 0 {
                if is_reserved(LogicalCpuId::new(0), irq_number as u8) {
                    return Err(Error::new(EEXIST));
                }
                set_reserved(LogicalCpuId::new(0), irq_number as u8, true);
            }
            (
                Handle::Irq {
                    ack: AtomicUsize::new(0),
                    irq: irq_number as u8,
                },
                InternalFlags::empty(),
            )
        })
    }
}

const fn irq_to_vector(irq: u8) -> u8 {
    irq + 32
}
const fn vector_to_irq(vector: u8) -> u8 {
    vector - 32
}

impl crate::scheme::KernelScheme for IrqScheme {
    fn kopen(&self, path: &str, flags: usize, ctx: CallerCtx) -> Result<OpenResult> {
        if ctx.uid != 0 {
            return Err(Error::new(EACCES));
        }

        let path_str = path.trim_start_matches('/');

        let (handle, int_flags) = if path_str.is_empty() {
            if flags & O_DIRECTORY == 0 && flags & O_STAT == 0 {
                return Err(Error::new(EISDIR));
            }
            // list every logical CPU in the format of e.g. `cpu-1b`

            let mut bytes = String::new();

            use core::fmt::Write;

            for cpu_id in CPUS.get().expect("IRQ scheme not initialized") {
                writeln!(bytes, "cpu-{:02x}", cpu_id).unwrap();
            }

            if bsp_apic_id().is_some() {
                writeln!(bytes, "bsp").unwrap();
            }

            #[cfg(dtb)]
            unsafe {
                for chip in &IRQ_CHIP.irq_chip_list.chips {
                    writeln!(bytes, "phandle-{}", chip.phandle).unwrap();
                }
            }

            (Handle::TopLevel, InternalFlags::POSITIONED)
        } else {
            if path_str == "bsp" {
                if bsp_apic_id().is_none() {
                    return Err(Error::new(ENOENT));
                }
                (Handle::Bsp, InternalFlags::empty())
            } else if path_str.starts_with("cpu-") {
                let path_str = &path_str[4..];
                let cpu_id = u8::from_str_radix(&path_str[..2], 16).or(Err(Error::new(ENOENT)))?;
                let path_str = path_str[2..].trim_end_matches('/');

                if path_str.is_empty() {
                    (Handle::Avail(cpu_id), InternalFlags::POSITIONED)
                } else if path_str.starts_with('/') {
                    let path_str = &path_str[1..];
                    Self::open_ext_irq(flags, cpu_id, path_str)?
                } else {
                    return Err(Error::new(ENOENT));
                }
            } else if cfg!(dtb) && path_str.starts_with("phandle-") {
                #[cfg(dtb)]
                unsafe {
                    let (phandle_str, path_str) =
                        path_str[8..].split_once('/').unwrap_or((path_str, ""));
                    let phandle = usize::from_str(phandle_str).or(Err(Error::new(ENOENT)))?;
                    if path_str.is_empty() {
                        let has_any = IRQ_CHIP.irq_iter_for(phandle as u32).next().is_some();
                        if has_any {
                            let data = String::new();
                            (
                                Handle::Phandle(phandle as u8, data.into_bytes()),
                                InternalFlags::POSITIONED,
                            )
                        } else {
                            return Err(Error::new(ENOENT));
                        }
                    } else {
                        Self::open_phandle_irq(flags, phandle, path_str)?
                    }
                }
                #[cfg(not(dtb))]
                panic!("")
            } else if let Ok(plain_irq_number) = u8::from_str(path_str) {
                if plain_irq_number < BASE_IRQ_COUNT {
                    (
                        Handle::Irq {
                            ack: AtomicUsize::new(0),
                            irq: plain_irq_number,
                        },
                        InternalFlags::empty(),
                    )
                } else {
                    return Err(Error::new(ENOENT));
                }
            } else {
                return Err(Error::new(ENOENT));
            }
        };
        let fd = NEXT_FD.fetch_add(1, Ordering::Relaxed);
        HANDLES.write().insert(fd, handle);
        Ok(OpenResult::SchemeLocal(fd, int_flags))
    }
    fn getdents(
        &self,
        id: usize,
        buf: UserSliceWo,
        header_size: u16,
        opaque_id_start: u64,
    ) -> Result<usize> {
        let Ok(opaque) = usize::try_from(opaque_id_start) else {
            return Ok(0);
        };

        use core::fmt::Write;

        let mut buf = DirentBuf::new(buf, header_size).ok_or(Error::new(EIO))?;
        let mut intermediate = String::new();

        match *HANDLES.read().get(&id).ok_or(Error::new(EBADF))? {
            Handle::TopLevel => {
                let cpus = CPUS.get().expect("IRQ scheme not initialized");

                if bsp_apic_id().is_some() && opaque == 0 {
                    buf.entry(DirEntry {
                        inode: 0,
                        next_opaque_id: 1,
                        kind: DirentKind::CharDev,
                        name: "bsp",
                    })?;
                }

                // list every logical CPU in the format of e.g. `cpu-1b`
                for cpu_id in cpus.iter().filter(|i| opaque <= usize::from(**i)) {
                    intermediate.clear();
                    write!(&mut intermediate, "cpu-{:02x}", cpu_id).unwrap();
                    buf.entry(DirEntry {
                        kind: DirentKind::Directory,
                        name: &intermediate,
                        inode: 0,
                        next_opaque_id: u64::from(*cpu_id + 1),
                    })?;
                }
            }
            Handle::Avail(cpu_id) => {
                for vector in available_irqs_iter(LogicalCpuId::new(cpu_id.into())).skip(opaque) {
                    let irq = vector_to_irq(vector);
                    if Some(u32::from(cpu_id)) == bsp_apic_id() && irq < BASE_IRQ_COUNT {
                        continue;
                    }
                    intermediate.clear();
                    write!(intermediate, "{}", irq).unwrap();
                    buf.entry(DirEntry {
                        inode: 0,
                        kind: DirentKind::CharDev,
                        name: &intermediate,
                        next_opaque_id: u64::from(vector) + 1,
                    })?;
                }
            }
            _ => return Err(Error::new(ENOTDIR)),
        }
        Ok(buf.finalize())
    }

    fn fcntl(&self, _id: usize, _cmd: usize, _arg: usize) -> Result<usize> {
        Ok(0)
    }

    fn fevent(&self, _id: usize, _flags: EventFlags) -> Result<EventFlags> {
        Ok(EventFlags::empty())
    }

    fn fsync(&self, _file: usize) -> Result<()> {
        Ok(())
    }

    fn close(&self, id: usize) -> Result<()> {
        let handles_guard = HANDLES.read();
        let handle = handles_guard.get(&id).ok_or(Error::new(EBADF))?;

        if let &Handle::Irq {
            irq: handle_irq, ..
        } = handle
        {
            if handle_irq > BASE_IRQ_COUNT {
                set_reserved(LogicalCpuId::BSP, irq_to_vector(handle_irq), false);
            }
        }
        Ok(())
    }
    fn kwrite(
        &self,
        file: usize,
        buffer: UserSliceRo,
        _flags: u32,
        _stored_flags: u32,
    ) -> Result<usize> {
        let handles_guard = HANDLES.read();
        let handle = handles_guard.get(&file).ok_or(Error::new(EBADF))?;

        match handle {
            &Handle::Irq {
                irq: handle_irq,
                ack: ref handle_ack,
            } => {
                if buffer.len() < mem::size_of::<usize>() {
                    return Err(Error::new(EINVAL));
                }
                let ack = buffer.read_usize()?;
                let current = COUNTS.lock()[handle_irq as usize];

                if ack != current {
                    return Ok(0);
                }
                handle_ack.store(ack, Ordering::SeqCst);
                unsafe {
                    acknowledge(handle_irq as usize);
                }
                Ok(mem::size_of::<usize>())
            }
            _ => Err(Error::new(EBADF)),
        }
    }

    fn kfstat(&self, id: usize, buf: UserSliceWo) -> Result<()> {
        let handles_guard = HANDLES.read();
        let handle = handles_guard.get(&id).ok_or(Error::new(EBADF))?;

        buf.copy_exactly(&match *handle {
            Handle::Irq {
                irq: handle_irq, ..
            } => Stat {
                st_mode: MODE_CHR | 0o600,
                st_size: mem::size_of::<usize>() as u64,
                st_blocks: 1,
                st_blksize: mem::size_of::<usize>() as u32,
                st_ino: handle_irq.into(),
                st_nlink: 1,
                ..Default::default()
            },
            Handle::Bsp => Stat {
                st_mode: MODE_CHR | 0o400,
                st_size: mem::size_of::<usize>() as u64,
                st_blocks: 1,
                st_blksize: mem::size_of::<usize>() as u32,
                st_ino: INO_BSP,
                st_nlink: 1,
                ..Default::default()
            },
            Handle::Avail(cpu_id) => Stat {
                st_mode: MODE_DIR | 0o700,
                st_size: 0,
                st_ino: INO_AVAIL | u64::from(cpu_id) << 32,
                st_nlink: 2,
                ..Default::default()
            },
            Handle::Phandle(phandle, ref buf) => Stat {
                st_mode: MODE_DIR | 0o700,
                st_size: buf.len() as u64,
                st_ino: INO_PHANDLE | u64::from(phandle) << 32,
                st_nlink: 2,
                ..Default::default()
            },
            Handle::TopLevel => Stat {
                st_mode: MODE_DIR | 0o500,
                st_size: 0,
                st_ino: INO_TOPLEVEL,
                st_nlink: 1,
                ..Default::default()
            },
        })?;

        Ok(())
    }
    fn kfpath(&self, id: usize, buf: UserSliceWo) -> Result<usize> {
        let handles_guard = HANDLES.read();
        let handle = handles_guard.get(&id).ok_or(Error::new(EBADF))?;

        let scheme_path = match handle {
            Handle::Irq { irq, .. } => format!("irq:{}", irq),
            Handle::Bsp => format!("irq:bsp"),
            Handle::Avail(cpu_id) => format!("irq:cpu-{:2x}", cpu_id),
            Handle::Phandle(phandle, _) => format!("irq:phandle-{}", phandle),
            Handle::TopLevel => format!("irq:"),
        }
        .into_bytes();

        buf.copy_common_bytes_from_slice(&scheme_path)
    }
    fn kreadoff(
        &self,
        file: usize,
        buffer: UserSliceWo,
        _offset: u64,
        _flags: u32,
        _stored_flags: u32,
    ) -> Result<usize> {
        let handles_guard = HANDLES.read();
        let handle = handles_guard.get(&file).ok_or(Error::new(EBADF))?;

        match *handle {
            // Ensures that the length of the buffer is larger than the size of a usize
            Handle::Irq {
                irq: handle_irq,
                ack: ref handle_ack,
            } => {
                if buffer.len() < mem::size_of::<usize>() {
                    return Err(Error::new(EINVAL));
                }
                let current = COUNTS.lock()[handle_irq as usize];
                if handle_ack.load(Ordering::SeqCst) != current {
                    buffer.write_usize(current)?;
                    Ok(mem::size_of::<usize>())
                } else {
                    Ok(0)
                }
            }
            Handle::Bsp => {
                if buffer.len() < mem::size_of::<usize>() {
                    return Err(Error::new(EINVAL));
                }
                if let Some(bsp_apic_id) = bsp_apic_id() {
                    buffer.write_u32(bsp_apic_id)?;
                    Ok(mem::size_of::<usize>())
                } else {
                    Err(Error::new(EBADFD))
                }
            }
            Handle::Avail(_) | Handle::TopLevel | Handle::Phandle(_, _) => Err(Error::new(EISDIR)),
        }
    }
}
