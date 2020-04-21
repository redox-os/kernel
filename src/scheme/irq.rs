use core::{mem, str};
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::{Mutex, RwLock};

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use alloc::string::String;

use crate::arch::interrupt::{available_irqs_iter, bsp_apic_id, is_reserved, set_reserved};

use crate::event;
use crate::interrupt::irq::acknowledge;
use crate::scheme::{AtomicSchemeId, SchemeId};
use crate::syscall::error::*;
use crate::syscall::flag::{EventFlags, EVENT_READ, O_DIRECTORY, O_CREAT, O_STAT, MODE_CHR, MODE_DIR, SEEK_CUR, SEEK_END, SEEK_SET};
use crate::syscall::scheme::Scheme;

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

const INO_AVAIL: u64 = 0x8000_0000_0000_0000;
const INO_BSP: u64 = 0x8000_0000_0000_0001;

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
    Avail(Vec<u8>, AtomicUsize),
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
}

impl IrqScheme {
    pub fn new(scheme_id: SchemeId) -> IrqScheme {
        IRQ_SCHEME_ID.store(scheme_id, Ordering::SeqCst);

        *HANDLES.write() = Some(BTreeMap::new());

        IrqScheme {
            next_fd: AtomicUsize::new(0),
        }
    }
}

const fn irq_to_vector(irq: u8) -> u8 {
    irq + 32
}
const fn vector_to_irq(vector: u8) -> u8 {
    vector - 32
}

impl Scheme for IrqScheme {
    fn open(&self, path: &[u8], flags: usize, uid: u32, _gid: u32) -> Result<usize> {
        if uid != 0 { return Err(Error::new(EACCES)) }

        let path_str = str::from_utf8(path).or(Err(Error::new(ENOENT)))?;
        let path_str = path_str.trim_start_matches('/');

        let handle = if (flags & O_DIRECTORY != 0 || flags & O_STAT != 0) && path_str.is_empty() {
            // list all of the allocatable IRQs

            let mut bytes = String::new();

            use core::fmt::Write;

            for avail in available_irqs_iter() {
                write!(bytes, "{}\n", vector_to_irq(avail)).unwrap();
            }
            if bsp_apic_id().is_some() {
                write!(bytes, "bsp\n").unwrap();
            }

            Handle::Avail(bytes.into_bytes(), AtomicUsize::new(0))
        } else {
            if path_str == "bsp" {
                if bsp_apic_id().is_none() {
                    return Err(Error::new(ENOENT));
                }
                Handle::Bsp
            } else if let Ok(id) = path_str.parse::<u8>() {
                if id < BASE_IRQ_COUNT {
                    Handle::Irq { ack: AtomicUsize::new(0), irq: id }
                } else if id < TOTAL_IRQ_COUNT {
                    if flags & O_CREAT == 0 && flags & O_STAT == 0 {
                        return Err(Error::new(EINVAL));
                    }
                    if flags & O_STAT == 0 {
                        // FIXME
                        if is_reserved(0, irq_to_vector(id)) {
                            return Err(Error::new(EEXIST));
                        }
                        set_reserved(0, irq_to_vector(id), true);
                    }
                    Handle::Irq { ack: AtomicUsize::new(0), irq: id }
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
            &Handle::Avail(ref buf, ref offset) => {
                let cur_offset = offset.load(Ordering::SeqCst);
                let max_bytes_to_read = core::cmp::min(buf.len(), buffer.len());
                let bytes_to_read = core::cmp::max(max_bytes_to_read, cur_offset) - cur_offset;
                buffer[..bytes_to_read].copy_from_slice(&buf[cur_offset..cur_offset + bytes_to_read]);
                offset.fetch_add(bytes_to_read, Ordering::SeqCst);
                Ok(bytes_to_read)
            }
        }
    }

    fn seek(&self, id: usize, pos: usize, whence: usize) -> Result<usize> {
        let handles_guard = HANDLES.read();
        let handle = handles_guard.as_ref().unwrap().get(&id).ok_or(Error::new(EBADF))?;

        match handle {
            &Handle::Avail(ref buf, ref offset) => {
                let cur_offset = offset.load(Ordering::SeqCst);
                let new_offset = match whence {
                    SEEK_CUR => core::cmp::min(cur_offset + pos, buf.len()),
                    SEEK_END => core::cmp::min(buf.len() + pos, buf.len()),
                    SEEK_SET => core::cmp::min(buf.len(), pos),
                    _ => return Err(Error::new(EINVAL)),
                };
                offset.store(new_offset, Ordering::SeqCst);
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
            Handle::Bsp => {
                stat.st_mode = MODE_CHR | 0o400;
                stat.st_size = mem::size_of::<usize>() as u64;
                stat.st_blocks = 1;
                stat.st_blksize = mem::size_of::<usize>() as u32;
                stat.st_ino = INO_BSP;
                stat.st_nlink = 1;
            }
            Handle::Avail(ref buf, _) => {
                stat.st_mode = MODE_DIR | 0o500;
                stat.st_size = buf.len() as u64;
                stat.st_ino = INO_AVAIL;
                stat.st_nlink = 2;
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
            &Handle::Avail(_, _) => format!("irq:"),
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
