use core::sync::atomic::Ordering;
use spin::Once;

use context;
use device::serial::COM1;
use scheme::*;
use sync::WaitQueue;
use syscall::flag::{EVENT_READ, F_GETFL, F_SETFL, O_ACCMODE, O_NONBLOCK};
use syscall::scheme::Scheme;

pub static DEBUG_SCHEME_ID: AtomicSchemeId = ATOMIC_SCHEMEID_INIT;

/// Input queue
static INPUT: Once<WaitQueue<u8>> = Once::new();

/// Initialize input queue, called if needed
fn init_input() -> WaitQueue<u8> {
    WaitQueue::new()
}

/// Add to the input queue
pub fn debug_input(b: u8) {
    let len = INPUT.call_once(init_input).send(b);
    context::event::trigger(DEBUG_SCHEME_ID.load(Ordering::SeqCst), 0, EVENT_READ, len);
}

pub struct DebugScheme {
    next_id: AtomicUsize,
    handles: RwLock<BTreeMap<usize, usize>>
}

impl DebugScheme {
    pub fn new(scheme_id: SchemeId) -> DebugScheme {
        DEBUG_SCHEME_ID.store(scheme_id, Ordering::SeqCst);
        DebugScheme {
            next_id: AtomicUsize::new(0),
            handles: RwLock::new(BTreeMap::new())
        }
    }
}

impl Scheme for DebugScheme {
    fn open(&self, _path: &[u8], flags: usize, _uid: u32, _gid: u32) -> Result<usize> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        self.handles.write().insert(id, flags & ! O_ACCMODE);

        Ok(id)
    }

    fn dup(&self, id: usize, buf: &[u8]) -> Result<usize> {
        if ! buf.is_empty() {
            return Err(Error::new(ENOENT));
        }

        let flags = {
            let handles = self.handles.read();
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        let new_id = self.next_id.fetch_add(1, Ordering::SeqCst);
        self.handles.write().insert(new_id, flags);

        Ok(new_id)
    }

    /// Read the file `number` into the `buffer`
    ///
    /// Returns the number of bytes read
    fn read(&self, id: usize, buf: &mut [u8]) -> Result<usize> {
        let flags = {
            let handles = self.handles.read();
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        Ok(INPUT.call_once(init_input).receive_into(buf, flags & O_NONBLOCK != O_NONBLOCK))
    }

    /// Write the `buffer` to the `file`
    ///
    /// Returns the number of bytes written
    fn write(&self, id: usize, buffer: &[u8]) -> Result<usize> {
        let _flags = {
            let handles = self.handles.read();
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        let mut com = COM1.lock();
        for &byte in buffer.iter() {
            com.send(byte);
        }

        Ok(buffer.len())
    }

    fn fcntl(&self, id: usize, cmd: usize, arg: usize) -> Result<usize> {
        let mut handles = self.handles.write();
        if let Some(flags) = handles.get_mut(&id) {
            match cmd {
                F_GETFL => Ok(*flags),
                F_SETFL => {
                    *flags = arg & ! O_ACCMODE;
                    Ok(0)
                },
                _ => Err(Error::new(EINVAL))
            }
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn fevent(&self, id: usize, _flags: usize) -> Result<usize> {
        let _flags = {
            let handles = self.handles.read();
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        Ok(0)
    }

    fn fpath(&self, id: usize, buf: &mut [u8]) -> Result<usize> {
        let _flags = {
            let handles = self.handles.read();
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        let mut i = 0;
        let scheme_path = b"debug:";
        while i < buf.len() && i < scheme_path.len() {
            buf[i] = scheme_path[i];
            i += 1;
        }

        Ok(i)
    }

    fn fsync(&self, id: usize) -> Result<usize> {
        let _flags = {
            let handles = self.handles.read();
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        Ok(0)
    }

    /// Close the file `number`
    fn close(&self, id: usize) -> Result<usize> {
        let _flags = {
            let mut handles = self.handles.write();
            handles.remove(&id).ok_or(Error::new(EBADF))?
        };

        Ok(0)
    }
}
