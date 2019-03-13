use core::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT};
use spin::{Once, RwLock, RwLockReadGuard, RwLockWriteGuard};

use arch::debug::Writer;
use event;
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

static NEXT_ID: AtomicUsize = ATOMIC_USIZE_INIT;

static HANDLES: Once<RwLock<BTreeMap<usize, usize>>> = Once::new();

fn init_handles() -> RwLock<BTreeMap<usize, usize>> {
    RwLock::new(BTreeMap::new())
}

fn handles() -> RwLockReadGuard<'static, BTreeMap<usize, usize>> {
    HANDLES.call_once(init_handles).read()
}

fn handles_mut() -> RwLockWriteGuard<'static, BTreeMap<usize, usize>> {
    HANDLES.call_once(init_handles).write()
}

/// Add to the input queue
pub fn debug_input(b: u8) {
    INPUT.call_once(init_input).send(b);
    for (id, _flags) in handles().iter() {
        event::trigger(DEBUG_SCHEME_ID.load(Ordering::SeqCst), *id, EVENT_READ);
    }
}

pub struct DebugScheme;

impl DebugScheme {
    pub fn new(scheme_id: SchemeId) -> DebugScheme {
        DEBUG_SCHEME_ID.store(scheme_id, Ordering::SeqCst);
        DebugScheme
    }
}

impl Scheme for DebugScheme {
    fn open(&self, _path: &[u8], flags: usize, _uid: u32, _gid: u32) -> Result<usize> {
        let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
        handles_mut().insert(id, flags & ! O_ACCMODE);

        Ok(id)
    }

    /// Read the file `number` into the `buffer`
    ///
    /// Returns the number of bytes read
    fn read(&self, id: usize, buf: &mut [u8]) -> Result<usize> {
        let flags = {
            let handles = handles();
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        INPUT.call_once(init_input)
            .receive_into(buf, flags & O_NONBLOCK != O_NONBLOCK)
            .ok_or(Error::new(EINTR))
    }

    /// Write the `buffer` to the `file`
    ///
    /// Returns the number of bytes written
    fn write(&self, id: usize, buf: &[u8]) -> Result<usize> {
        let _flags = {
            let handles = handles();
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        Writer::new().write(buf);
        Ok(buf.len())
    }

    fn fcntl(&self, id: usize, cmd: usize, arg: usize) -> Result<usize> {
        let mut handles = handles_mut();
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
            let handles = handles();
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        Ok(0)
    }

    fn fpath(&self, id: usize, buf: &mut [u8]) -> Result<usize> {
        let _flags = {
            let handles = handles();
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
            let handles = handles();
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        Ok(0)
    }

    /// Close the file `number`
    fn close(&self, id: usize) -> Result<usize> {
        let _flags = {
            let mut handles = handles_mut();
            handles.remove(&id).ok_or(Error::new(EBADF))?
        };

        Ok(0)
    }
}
