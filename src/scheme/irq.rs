use core::{
    mem, str,
    str::FromStr,
    sync::atomic::{AtomicUsize, Ordering},
};

use alloc::{collections::BTreeMap, string::String, vec::Vec};

use spin::{Mutex, Once, RwLock};

use crate::arch::interrupt::{available_irqs_iter, bsp_apic_id, is_reserved, set_reserved};

use crate::{
    cpu_set::LogicalCpuId,
    event,
    interrupt::irq::acknowledge,
    syscall::{
        data::Stat,
        error::*,
        flag::{EventFlags, EVENT_READ, MODE_CHR, MODE_DIR, O_CREAT, O_DIRECTORY, O_STAT},
        usercopy::{UserSliceRo, UserSliceWo},
    },
};

use super::{calc_seek_offset, CallerCtx, GlobalSchemes, OpenResult};

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

enum Handle {
    Irq { ack: AtomicUsize, irq: u8 },
    Avail(u8, Vec<u8>, AtomicUsize), // CPU id, data, offset
    TopLevel(Vec<u8>, AtomicUsize),  // data, offset
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
    fn open_ext_irq(flags: usize, cpu_id: u8, path_str: &str) -> Result<Handle> {
        let irq_number = u8::from_str(path_str).or(Err(Error::new(ENOENT)))?;

        Ok(
            if irq_number < BASE_IRQ_COUNT && Some(u32::from(cpu_id)) == bsp_apic_id() {
                // Give legacy IRQs only to `irq:{0..15}` and `irq:cpu-<BSP>/{0..15}` (same handles).
                //
                // The only CPUs don't have the legacy IRQs in their IDTs.

                Handle::Irq {
                    ack: AtomicUsize::new(0),
                    irq: irq_number,
                }
            } else if irq_number < TOTAL_IRQ_COUNT {
                if flags & O_CREAT == 0 && flags & O_STAT == 0 {
                    return Err(Error::new(EINVAL));
                }
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
                Handle::Irq {
                    ack: AtomicUsize::new(0),
                    irq: irq_number,
                }
            } else {
                return Err(Error::new(ENOENT));
            },
        )
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

        let handle: Handle = if path_str.is_empty() {
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

            // TODO: When signals are used for IRQs, there will probably also be a file
            // `irq:signal` that maps IRQ numbers and their source APIC IDs to signal numbers.

            Handle::TopLevel(bytes.into_bytes(), AtomicUsize::new(0))
        } else {
            if path_str == "bsp" {
                if bsp_apic_id().is_none() {
                    return Err(Error::new(ENOENT));
                }
                Handle::Bsp
            } else if path_str.starts_with("cpu-") {
                let path_str = &path_str[4..];
                let cpu_id = u8::from_str_radix(&path_str[..2], 16).or(Err(Error::new(ENOENT)))?;
                let path_str = path_str[2..].trim_end_matches('/');

                if path_str.is_empty() {
                    let mut data = String::new();
                    use core::fmt::Write;

                    for vector in available_irqs_iter(LogicalCpuId::new(cpu_id.into())) {
                        let irq = vector_to_irq(vector);
                        if Some(u32::from(cpu_id)) == bsp_apic_id() && irq < BASE_IRQ_COUNT {
                            continue;
                        }
                        writeln!(data, "{}", irq).unwrap();
                    }

                    Handle::Avail(cpu_id, data.into_bytes(), AtomicUsize::new(0))
                } else if path_str.starts_with('/') {
                    let path_str = &path_str[1..];
                    Self::open_ext_irq(flags, cpu_id, path_str)?
                } else {
                    return Err(Error::new(ENOENT));
                }
            } else if let Ok(plain_irq_number) = u8::from_str(path_str) {
                if plain_irq_number < BASE_IRQ_COUNT {
                    Handle::Irq {
                        ack: AtomicUsize::new(0),
                        irq: plain_irq_number,
                    }
                } else {
                    return Err(Error::new(ENOENT));
                }
            } else {
                return Err(Error::new(ENOENT));
            }
        };
        let fd = NEXT_FD.fetch_add(1, Ordering::Relaxed);
        HANDLES.write().insert(fd, handle);
        Ok(OpenResult::SchemeLocal(fd))
    }

    fn seek(&self, id: usize, pos: isize, whence: usize) -> Result<usize> {
        let handles_guard = HANDLES.read();
        let handle = handles_guard.get(&id).ok_or(Error::new(EBADF))?;

        match handle {
            &Handle::Avail(_, ref buf, ref offset) | &Handle::TopLevel(ref buf, ref offset) => {
                let cur_offset = offset.load(Ordering::SeqCst);
                let new_offset = calc_seek_offset(cur_offset, pos, whence, buf.len())?;
                offset.store(new_offset as usize, Ordering::SeqCst);
                Ok(new_offset as usize)
            }
            _ => Err(Error::new(ESPIPE)),
        }
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
    fn kwrite(&self, file: usize, buffer: UserSliceRo) -> Result<usize> {
        let handles_guard = HANDLES.read();
        let handle = handles_guard.get(&file).ok_or(Error::new(EBADF))?;

        match handle {
            &Handle::Irq {
                irq: handle_irq,
                ack: ref handle_ack,
            } => {
                if buffer.len() >= mem::size_of::<usize>() {
                    let ack = buffer.read_usize()?;
                    let current = COUNTS.lock()[handle_irq as usize];

                    if ack == current {
                        handle_ack.store(ack, Ordering::SeqCst);
                        unsafe {
                            acknowledge(handle_irq as usize);
                        }
                        Ok(mem::size_of::<usize>())
                    } else {
                        Ok(0)
                    }
                } else {
                    Err(Error::new(EINVAL))
                }
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
            Handle::Avail(cpu_id, ref buf, _) => Stat {
                st_mode: MODE_DIR | 0o700,
                st_size: buf.len() as u64,
                st_ino: INO_AVAIL | u64::from(cpu_id) << 32,
                st_nlink: 2,
                ..Default::default()
            },
            Handle::TopLevel(ref buf, _) => Stat {
                st_mode: MODE_DIR | 0o500,
                st_size: buf.len() as u64,
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
            Handle::Avail(cpu_id, _, _) => format!("irq:cpu-{:2x}", cpu_id),
            Handle::TopLevel(_, _) => format!("irq:"),
        }
        .into_bytes();

        buf.copy_common_bytes_from_slice(&scheme_path)
    }
    fn kread(&self, file: usize, buffer: UserSliceWo) -> Result<usize> {
        let handles_guard = HANDLES.read();
        let handle = handles_guard.get(&file).ok_or(Error::new(EBADF))?;

        match *handle {
            // Ensures that the length of the buffer is larger than the size of a usize
            Handle::Irq {
                irq: handle_irq,
                ack: ref handle_ack,
            } => {
                if buffer.len() >= mem::size_of::<usize>() {
                    let current = COUNTS.lock()[handle_irq as usize];
                    if handle_ack.load(Ordering::SeqCst) != current {
                        buffer.write_usize(current)?;
                        Ok(mem::size_of::<usize>())
                    } else {
                        Ok(0)
                    }
                } else {
                    Err(Error::new(EINVAL))
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
            Handle::Avail(_, ref buf, ref offset) | Handle::TopLevel(ref buf, ref offset) => {
                let cur_offset = offset.load(Ordering::SeqCst);
                let avail_buf = buf.get(cur_offset..).unwrap_or(&[]);
                let bytes_read = buffer.copy_common_bytes_from_slice(avail_buf)?;
                offset.fetch_add(bytes_read, Ordering::SeqCst);
                Ok(bytes_read)
            }
        }
    }
}
