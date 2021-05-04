use core::{mem, str};
use core::str::FromStr;
use core::sync::atomic::{AtomicUsize, Ordering};

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use alloc::string::String;

use spin::{Mutex, RwLock};

use crate::arch::interrupt::{available_irqs_iter, bsp_apic_id, is_reserved, set_reserved};

use crate::event;
use crate::interrupt::irq::acknowledge;
use crate::scheme::{AtomicSchemeId, SchemeId};
use crate::syscall::error::*;
use crate::syscall::flag::{EventFlags, EVENT_READ, O_DIRECTORY, O_CREAT, O_STAT, MODE_CHR, MODE_DIR};
use crate::syscall::scheme::{calc_seek_offset_usize, Scheme};

pub static IRQ_SCHEME_ID: AtomicSchemeId = AtomicSchemeId::default();

/// IRQ queues
static COUNTS: Mutex<[usize; 224]> = Mutex::new([0; 224]);
static HANDLES: RwLock<Option<BTreeMap<usize, Handle>>> = RwLock::new(None);

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
pub extern fn irq_trigger(irq: u8) {
    COUNTS.lock()[irq as usize] += 1;

    let guard = HANDLES.read();
    if let Some(handles) = guard.as_ref() {
        for (fd, _) in handles.iter().filter_map(|(fd, handle)| Some((fd, handle.as_irq_handle()?))).filter(|&(_, (_, handle_irq))| handle_irq == irq) {
            event::trigger(IRQ_SCHEME_ID.load(Ordering::SeqCst), *fd, EVENT_READ);
        }
    } else {
        println!("Calling IRQ without triggering");
    }
}

enum Handle {
    Irq {
        ack: AtomicUsize,
        irq: u8,
    },
    Avail(u8, Vec<u8>, AtomicUsize),    // CPU id, data, offset
    TopLevel(Vec<u8>, AtomicUsize),     // data, offset
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

pub struct IrqScheme {
    next_fd: AtomicUsize,
    cpus: Vec<u8>,
}

impl IrqScheme {
    pub fn new(scheme_id: SchemeId) -> IrqScheme {
        IRQ_SCHEME_ID.store(scheme_id, Ordering::SeqCst);

        *HANDLES.write() = Some(BTreeMap::new());

        #[cfg(all(feature = "acpi", target_arch = "x86_64"))]
        let cpus = {
            use crate::acpi::madt::*;

            let madt: &Madt = unsafe { MADT.as_ref().unwrap() };

            madt.iter().filter_map(|entry| match entry {
                MadtEntry::LocalApic(apic) => Some(apic.id),
                _ => None,
            }).collect::<Vec<_>>()
        };
        #[cfg(not(all(feature = "acpi", target_arch = "x86_64")))]
        let cpus = vec!(0);

        IrqScheme {
            next_fd: AtomicUsize::new(0),
            cpus,
        }
    }
    fn open_ext_irq(flags: usize, cpu_id: u8, path_str: &str) -> Result<Handle> {
        let irq_number = u8::from_str(path_str).or(Err(Error::new(ENOENT)))?;

        Ok(if irq_number < BASE_IRQ_COUNT && Some(u32::from(cpu_id)) == bsp_apic_id() {
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
                if is_reserved(usize::from(cpu_id), irq_to_vector(irq_number)) {
                    return Err(Error::new(EEXIST));
                }
                set_reserved(usize::from(cpu_id), irq_to_vector(irq_number), true);
            }
            Handle::Irq { ack: AtomicUsize::new(0), irq: irq_number }
        } else {
            return Err(Error::new(ENOENT));
        })
    }
}

const fn irq_to_vector(irq: u8) -> u8 {
    irq + 32
}
const fn vector_to_irq(vector: u8) -> u8 {
    vector - 32
}

impl Scheme for IrqScheme {
    fn open(&self, path: &str, flags: usize, uid: u32, _gid: u32) -> Result<usize> {
        if uid != 0 { return Err(Error::new(EACCES)) }

        let path_str = path.trim_start_matches('/');

        let handle: Handle = if path_str.is_empty() {
            if flags & O_DIRECTORY == 0 && flags & O_STAT == 0 { return Err(Error::new(EISDIR)) }

            // list every logical CPU in the format of e.g. `cpu-1b`

            let mut bytes = String::new();

            use core::fmt::Write;

            for cpu_id in &self.cpus {
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

                    for vector in available_irqs_iter(cpu_id.into()) {
                        let irq = vector_to_irq(vector);
                        if Some(u32::from(cpu_id)) == bsp_apic_id() && irq < BASE_IRQ_COUNT {
                            continue;
                        }
                        writeln!(data, "{}", irq).unwrap();
                    }

                    Handle::Avail(cpu_id, data.into_bytes(), AtomicUsize::new(0))
                } else if path_str.chars().next() == Some('/') {
                    let path_str = &path_str[1..];
                    Self::open_ext_irq(flags, cpu_id, path_str)?
                } else {
                    return Err(Error::new(ENOENT));
                }
            } else if let Ok(plain_irq_number) = u8::from_str(path_str) {
                if plain_irq_number < BASE_IRQ_COUNT {
                    Handle::Irq { ack: AtomicUsize::new(0), irq: plain_irq_number }
                } else {
                    return Err(Error::new(ENOENT));
                }
            } else {
                return Err(Error::new(ENOENT));
            }
        };
        let fd = self.next_fd.fetch_add(1, Ordering::SeqCst);
        HANDLES.write().as_mut().unwrap().insert(fd, handle);
        Ok(fd)
    }

    fn read(&self, file: usize, buffer: &mut [u8]) -> Result<usize> {
        let handles_guard = HANDLES.read();
        let handle = handles_guard.as_ref().unwrap().get(&file).ok_or(Error::new(EBADF))?;

        match handle {
            // Ensures that the length of the buffer is larger than the size of a usize
            &Handle::Irq { irq: handle_irq, ack: ref handle_ack } => if buffer.len() >= mem::size_of::<usize>() {
                let current = COUNTS.lock()[handle_irq as usize];
                if handle_ack.load(Ordering::SeqCst) != current {
                    // Safe if the length of the buffer is larger than the size of a usize
                    assert!(buffer.len() >= mem::size_of::<usize>());
                    unsafe { *(buffer.as_mut_ptr() as *mut usize) = current; }
                    Ok(mem::size_of::<usize>())
                } else {
                    Ok(0)
                }
            } else {
                return Err(Error::new(EINVAL));
            }
            &Handle::Bsp => {
                if buffer.len() < mem::size_of::<usize>() {
                    return Err(Error::new(EINVAL));
                }
                if let Some(bsp_apic_id) = bsp_apic_id() {
                    unsafe { *(buffer.as_mut_ptr() as *mut usize) = bsp_apic_id as usize; }
                    Ok(mem::size_of::<usize>())
                } else {
                    return Err(Error::new(EBADFD));
                }
            }
            &Handle::Avail(_, ref buf, ref offset) | &Handle::TopLevel(ref buf, ref offset) => {
                let cur_offset = offset.load(Ordering::SeqCst);
                let max_bytes_to_read = core::cmp::min(buf.len(), buffer.len());
                let bytes_to_read = core::cmp::max(max_bytes_to_read, cur_offset) - cur_offset;
                buffer[..bytes_to_read].copy_from_slice(&buf[cur_offset..cur_offset + bytes_to_read]);
                offset.fetch_add(bytes_to_read, Ordering::SeqCst);
                Ok(bytes_to_read)
            }
        }
    }

    fn seek(&self, id: usize, pos: isize, whence: usize) -> Result<isize> {
        let handles_guard = HANDLES.read();
        let handle = handles_guard.as_ref().unwrap().get(&id).ok_or(Error::new(EBADF))?;

        match handle {
            &Handle::Avail(_, ref buf, ref offset) | &Handle::TopLevel(ref buf, ref offset) => {
                let cur_offset = offset.load(Ordering::SeqCst);
                let new_offset = calc_seek_offset_usize(cur_offset, pos, whence, buf.len())?;
                offset.store(new_offset as usize, Ordering::SeqCst);
                Ok(new_offset)
            }
            _ => return Err(Error::new(ESPIPE)),
        }
    }

    fn write(&self, file: usize, buffer: &[u8]) -> Result<usize> {
        let handles_guard = HANDLES.read();
        let handle = handles_guard.as_ref().unwrap().get(&file).ok_or(Error::new(EBADF))?;

        match handle {
            &Handle::Irq { irq: handle_irq, ack: ref handle_ack } => if buffer.len() >= mem::size_of::<usize>() {
                assert!(buffer.len() >= mem::size_of::<usize>());

                let ack = unsafe { *(buffer.as_ptr() as *const usize) };
                let current = COUNTS.lock()[handle_irq as usize];

                if ack == current {
                    handle_ack.store(ack, Ordering::SeqCst);
                    unsafe { acknowledge(handle_irq as usize); }
                    Ok(mem::size_of::<usize>())
                } else {
                    Ok(0)
                }
            } else {
                return Err(Error::new(EINVAL));
            }
            _ => return Err(Error::new(EBADF)),
        }
    }

    fn fstat(&self, id: usize, stat: &mut syscall::data::Stat) -> Result<usize> {
        let handles_guard = HANDLES.read();
        let handle = handles_guard.as_ref().unwrap().get(&id).ok_or(Error::new(EBADF))?;

        match handle {
            &Handle::Irq { irq: handle_irq, .. } => {
                stat.st_mode = MODE_CHR | 0o600;
                stat.st_size = mem::size_of::<usize>() as u64;
                stat.st_blocks = 1;
                stat.st_blksize = mem::size_of::<usize>() as u32;
                stat.st_ino = handle_irq.into();
                stat.st_nlink = 1;
            }
            &Handle::Bsp => {
                stat.st_mode = MODE_CHR | 0o400;
                stat.st_size = mem::size_of::<usize>() as u64;
                stat.st_blocks = 1;
                stat.st_blksize = mem::size_of::<usize>() as u32;
                stat.st_ino = INO_BSP;
                stat.st_nlink = 1;
            }
            &Handle::Avail(cpu_id, ref buf, _) => {
                stat.st_mode = MODE_DIR | 0o700;
                stat.st_size = buf.len() as u64;
                stat.st_ino = INO_AVAIL | u64::from(cpu_id) << 32;
                stat.st_nlink = 2;
            }
            &Handle::TopLevel(ref buf, _) => {
                stat.st_mode = MODE_DIR | 0o500;
                stat.st_size = buf.len() as u64;
                stat.st_ino = INO_TOPLEVEL;
                stat.st_nlink = 1;
            }
        }
        Ok(0)
    }

    fn fcntl(&self, _id: usize, _cmd: usize, _arg: usize) -> Result<usize> {
        Ok(0)
    }

    fn fevent(&self, _id: usize, _flags: EventFlags) -> Result<EventFlags> {
        Ok(EventFlags::empty())
    }

    fn fpath(&self, id: usize, buf: &mut [u8]) -> Result<usize> {
        let handles_guard = HANDLES.read();
        let handle = handles_guard.as_ref().unwrap().get(&id).ok_or(Error::new(EBADF))?;

        let scheme_path = match handle {
            &Handle::Irq { irq, .. } => format!("irq:{}", irq),
            &Handle::Bsp => format!("irq:bsp"),
            &Handle::Avail(cpu_id, _, _) => format!("irq:cpu-{:2x}", cpu_id),
            &Handle::TopLevel(_, _) => format!("irq:"),
        }.into_bytes();

        let mut i = 0;
        while i < buf.len() && i < scheme_path.len() {
            buf[i] = scheme_path[i];
            i += 1;
        }
        Ok(i)
    }

    fn fsync(&self, _file: usize) -> Result<usize> {
        Ok(0)
    }

    fn close(&self, id: usize) -> Result<usize> {
        let handles_guard = HANDLES.read();
        let handle = handles_guard.as_ref().unwrap().get(&id).ok_or(Error::new(EBADF))?;

        if let &Handle::Irq { irq: handle_irq, .. } = handle {
            if handle_irq > BASE_IRQ_COUNT {
                set_reserved(0, irq_to_vector(handle_irq), false);
            }
        }
        Ok(0)
    }
}
