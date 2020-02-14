use core::{mem, str};
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::{Mutex, RwLock};

use alloc::collections::BTreeMap;

use crate::event;
use crate::interrupt::irq::acknowledge;
use crate::scheme::{AtomicSchemeId, SchemeId};
use crate::syscall::error::*;
use crate::syscall::flag::{EventFlags, EVENT_READ};
use crate::syscall::scheme::Scheme;

pub static IRQ_SCHEME_ID: AtomicSchemeId = AtomicSchemeId::default();

/// IRQ queues
static COUNTS: Mutex<[usize; 16]> = Mutex::new([0; 16]);
static HANDLES: RwLock<Option<BTreeMap<usize, Handle>>> = RwLock::new(None);

/// Add to the input queue
#[no_mangle]
pub extern fn irq_trigger(irq: u8) {
    COUNTS.lock()[irq as usize] += 1;

    let guard = HANDLES.read();
    if let Some(handles) = guard.as_ref() {
        for (fd, _) in handles.iter().filter(|(_, handle)| handle.irq == irq) {
            event::trigger(IRQ_SCHEME_ID.load(Ordering::SeqCst), *fd, EVENT_READ);
        }
    } else {
        println!("Calling IRQ without triggering");
    }
}

struct Handle {
    ack: AtomicUsize,
    irq: u8,
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

impl Scheme for IrqScheme {
    fn open(&self, path: &[u8], _flags: usize, uid: u32, _gid: u32) -> Result<usize> {
        if uid == 0 {
            let path_str = str::from_utf8(path).or(Err(Error::new(ENOENT)))?;

            let id = path_str.parse::<usize>().or(Err(Error::new(ENOENT)))?;

            if id < COUNTS.lock().len() {
                let fd = self.next_fd.fetch_add(1, Ordering::Relaxed);
                HANDLES.write().as_mut().unwrap().insert(fd, Handle { ack: AtomicUsize::new(0), irq: id as u8 });
                Ok(fd)
            } else {
                Err(Error::new(ENOENT))
            }
        } else {
            Err(Error::new(EACCES))
        }
    }

    fn read(&self, file: usize, buffer: &mut [u8]) -> Result<usize> {
        // Ensures that the length of the buffer is larger than the size of a usize
        if buffer.len() >= mem::size_of::<usize>() {
            let handles_guard = HANDLES.read();
            let handle = &handles_guard.as_ref().unwrap().get(&file).ok_or(Error::new(EBADF))?;

            let current = COUNTS.lock()[handle.irq as usize];
            if handle.ack.load(Ordering::SeqCst) != current {
                // Safe if the length of the buffer is larger than the size of a usize
                assert!(buffer.len() >= mem::size_of::<usize>());
                unsafe { *(buffer.as_mut_ptr() as *mut usize) = current; }
                Ok(mem::size_of::<usize>())
            } else {
                Ok(0)
            }
        } else {
            Err(Error::new(EINVAL))
        }
    }

    fn write(&self, file: usize, buffer: &[u8]) -> Result<usize> {
        if buffer.len() >= mem::size_of::<usize>() {
            assert!(buffer.len() >= mem::size_of::<usize>());

            let handles_guard = HANDLES.read();
            let handle = &handles_guard.as_ref().unwrap().get(&file).ok_or(Error::new(EBADF))?;

            let ack = unsafe { *(buffer.as_ptr() as *const usize) };
            let current = COUNTS.lock()[handle.irq as usize];

            if ack == current {
                handle.ack.store(ack, Ordering::SeqCst);
                unsafe { acknowledge(handle.irq as usize); }
                Ok(mem::size_of::<usize>())
            } else {
                Ok(0)
            }
        } else {
            Err(Error::new(EINVAL))
        }
    }

    fn fcntl(&self, _id: usize, _cmd: usize, _arg: usize) -> Result<usize> {
        Ok(0)
    }

    fn fevent(&self, _id: usize, _flags: EventFlags) -> Result<EventFlags> {
        Ok(EventFlags::empty())
    }

    fn fpath(&self, id: usize, buf: &mut [u8]) -> Result<usize> {
        let mut i = 0;
        let scheme_path = format!("irq:{}", id).into_bytes();
        while i < buf.len() && i < scheme_path.len() {
            buf[i] = scheme_path[i];
            i += 1;
        }
        Ok(i)
    }

    fn fsync(&self, _file: usize) -> Result<usize> {
        Ok(0)
    }

    fn close(&self, _file: usize) -> Result<usize> {
        Ok(0)
    }
}
