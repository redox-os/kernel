//! PS/2 unfortunately requires a kernel driver to prevent race conditions due
//! to how status is utilized
use core::str;
use core::sync::atomic::{AtomicUsize, Ordering};

use spin::{Once, RwLock};

use crate::event;
use crate::scheme::*;
use crate::sync::WaitQueue;
use crate::syscall::flag::{EventFlags, EVENT_READ, F_GETFL, F_SETFL, O_ACCMODE, O_NONBLOCK};
use crate::syscall::scheme::Scheme;
use crate::syscall::usercopy::UserSliceWo;

static SCHEME_ID: Once<SchemeId> = Once::new();

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

/// Input queue
static INPUT: [WaitQueue<u8>; 2] = [WaitQueue::new(), WaitQueue::new()];

#[derive(Clone, Copy)]
struct Handle {
    index: usize,
    flags: usize,
}

static HANDLES: RwLock<BTreeMap<usize, Handle>> = RwLock::new(BTreeMap::new());

/// Add to the input queue
pub fn serio_input(index: usize, data: u8) {
    INPUT[index].send(data);

    let Some(scheme_id) = SCHEME_ID.get().copied() else {
        return;
    };

    for (id, _handle) in HANDLES.read().iter() {
        event::trigger(scheme_id, *id, EVENT_READ);
    }
}

pub struct SerioScheme;

impl SerioScheme {
    pub fn new(scheme_id: SchemeId) -> Self {
        SCHEME_ID.call_once(|| scheme_id);
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

        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        HANDLES.write().insert(id, Handle {
            index,
            flags: flags & ! O_ACCMODE
        });

        Ok(id)
    }

    fn fcntl(&self, id: usize, cmd: usize, arg: usize) -> Result<usize> {
        let mut handles = HANDLES.write();
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
            let handles = HANDLES.read();
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        Ok(EventFlags::empty())
    }

    fn fsync(&self, id: usize) -> Result<usize> {
        let _handle = {
            let handles = HANDLES.read();
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        Ok(0)
    }

    /// Close the file `number`
    fn close(&self, id: usize) -> Result<usize> {
        let _handle = {
            let mut handles = HANDLES.write();
            handles.remove(&id).ok_or(Error::new(EBADF))?
        };

        Ok(0)
    }
}
impl crate::scheme::KernelScheme for SerioScheme {
    fn kread(&self, id: usize, buf: UserSliceWo) -> Result<usize> {
        let handle = {
            let handles = HANDLES.read();
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        INPUT[handle.index]
            .receive_into_user(buf, handle.flags & O_NONBLOCK != O_NONBLOCK, "SerioScheme::read")
    }

    fn kfpath(&self, id: usize, buf: UserSliceWo) -> Result<usize> {
        let handle = {
            let handles = HANDLES.read();
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };
        let path = format!("serio:{}", handle.index).into_bytes();

        buf.copy_common_bytes_from_slice(&path)
    }
}
