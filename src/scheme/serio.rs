//! PS/2 unfortunately requires a kernel driver to prevent race conditions due
//! to how status is utilized
use core::str;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::{Once, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::event;
use crate::scheme::*;
use crate::sync::WaitQueue;
use crate::syscall::flag::{EventFlags, EVENT_READ, F_GETFL, F_SETFL, O_ACCMODE, O_NONBLOCK};
use crate::syscall::scheme::Scheme;

static SCHEME_ID: AtomicSchemeId = AtomicSchemeId::default();

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

/// Input queue
static INPUT: [Once<WaitQueue<u8>>; 2] = [Once::new(), Once::new()];

/// Initialize input queue, called if needed
fn init_input() -> WaitQueue<u8> {
    WaitQueue::new()
}

#[derive(Clone, Copy)]
struct Handle {
    index: usize,
    flags: usize,
}

static HANDLES: Once<RwLock<BTreeMap<usize, Handle>>> = Once::new();

fn init_handles() -> RwLock<BTreeMap<usize, Handle>> {
    RwLock::new(BTreeMap::new())
}

fn handles() -> RwLockReadGuard<'static, BTreeMap<usize, Handle>> {
    HANDLES.call_once(init_handles).read()
}

fn handles_mut() -> RwLockWriteGuard<'static, BTreeMap<usize, Handle>> {
    HANDLES.call_once(init_handles).write()
}

/// Add to the input queue
pub fn serio_input(index: usize, data: u8) {
    INPUT[index].call_once(init_input).send(data);
    for (id, _handle) in handles().iter() {
        event::trigger(SCHEME_ID.load(Ordering::SeqCst), *id, EVENT_READ);
    }
}

pub struct SerioScheme;

impl SerioScheme {
    pub fn new(scheme_id: SchemeId) -> Self {
        SCHEME_ID.store(scheme_id, Ordering::SeqCst);
        Self
    }
}

impl Scheme for SerioScheme {
    fn open(&self, path: &str, flags: usize, uid: u32, _gid: u32) -> Result<usize> {
        if uid != 0 {
            return Err(Error::new(EPERM));
        }

        let index = path
            .parse::<usize>()
            .or(Err(Error::new(ENOENT)))?;
        if index >= INPUT.len() {
            return Err(Error::new(ENOENT));
        }

        let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
        handles_mut().insert(id, Handle {
            index,
            flags: flags & ! O_ACCMODE
        });

        Ok(id)
    }

    /// Read the file `number` into the `buffer`
    ///
    /// Returns the number of bytes read
    fn read(&self, id: usize, buf: &mut [u8]) -> Result<usize> {
        let handle = {
            let handles = handles();
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        INPUT[handle.index].call_once(init_input)
            .receive_into(buf, handle.flags & O_NONBLOCK != O_NONBLOCK, "SerioScheme::read")
            .ok_or(Error::new(EINTR))
    }

    fn fcntl(&self, id: usize, cmd: usize, arg: usize) -> Result<usize> {
        let mut handles = handles_mut();
        if let Some(handle) = handles.get_mut(&id) {
            match cmd {
                F_GETFL => Ok(handle.flags),
                F_SETFL => {
                    handle.flags = arg & ! O_ACCMODE;
                    Ok(0)
                },
                _ => Err(Error::new(EINVAL))
            }
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn fevent(&self, id: usize, _flags: EventFlags) -> Result<EventFlags> {
        let _handle = {
            let handles = handles();
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        Ok(EventFlags::empty())
    }

    fn fpath(&self, id: usize, buf: &mut [u8]) -> Result<usize> {
        let handle = {
            let handles = handles();
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        let mut i = 0;
        let scheme_path = b"serio:";
        while i < buf.len() && i < scheme_path.len() {
            buf[i] = scheme_path[i];
            i += 1;
        }

        let file_path = format!("{}", handle.index).into_bytes();
        let mut j = 0;
        while i < buf.len() && j < file_path.len() {
            buf[i] = file_path[j];
            j += 1;
        }

        Ok(i)
    }

    fn fsync(&self, id: usize) -> Result<usize> {
        let _handle = {
            let handles = handles();
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        Ok(0)
    }

    /// Close the file `number`
    fn close(&self, id: usize) -> Result<usize> {
        let _handle = {
            let mut handles = handles_mut();
            handles.remove(&id).ok_or(Error::new(EBADF))?
        };

        Ok(0)
    }
}
