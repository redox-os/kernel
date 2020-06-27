use alloc::sync::{Arc, Weak};
use alloc::collections::{BTreeMap, VecDeque};
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::{Mutex, Once, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::event;
use crate::scheme::{AtomicSchemeId, SchemeId};
use crate::sync::WaitCondition;
use crate::syscall::error::{Error, Result, EAGAIN, EBADF, EINTR, EINVAL, EPIPE, ESPIPE};
use crate::syscall::flag::{EventFlags, EVENT_READ, EVENT_WRITE, F_GETFL, F_SETFL, O_ACCMODE, O_NONBLOCK, MODE_FIFO};
use crate::syscall::scheme::Scheme;
use crate::syscall::data::Stat;

/// Pipes list
pub static PIPE_SCHEME_ID: AtomicSchemeId = AtomicSchemeId::default();
static PIPE_NEXT_ID: AtomicUsize = AtomicUsize::new(0);
static PIPES: Once<RwLock<(BTreeMap<usize, Arc<PipeRead>>, BTreeMap<usize, Arc<PipeWrite>>)>> = Once::new();

/// Initialize pipes, called if needed
fn init_pipes() -> RwLock<(BTreeMap<usize, Arc<PipeRead>>, BTreeMap<usize, Arc<PipeWrite>>)> {
    RwLock::new((BTreeMap::new(), BTreeMap::new()))
}

/// Get the global pipes list, const
fn pipes() -> RwLockReadGuard<'static, (BTreeMap<usize, Arc<PipeRead>>, BTreeMap<usize, Arc<PipeWrite>>)> {
    PIPES.call_once(init_pipes).read()
}

/// Get the global pipes list, mutable
fn pipes_mut() -> RwLockWriteGuard<'static, (BTreeMap<usize, Arc<PipeRead>>, BTreeMap<usize, Arc<PipeWrite>>)> {
    PIPES.call_once(init_pipes).write()
}

pub fn pipe(flags: usize) -> (usize, usize) {
    let mut pipes = pipes_mut();
    let scheme_id = PIPE_SCHEME_ID.load(Ordering::SeqCst);
    let read_id = PIPE_NEXT_ID.fetch_add(1, Ordering::SeqCst);
    let write_id = PIPE_NEXT_ID.fetch_add(1, Ordering::SeqCst);
    let read = PipeRead::new(scheme_id, write_id, flags);
    let write = PipeWrite::new(&read, read_id, flags);
    pipes.0.insert(read_id, Arc::new(read));
    pipes.1.insert(write_id, Arc::new(write));
    (read_id, write_id)
}

pub struct PipeScheme;

impl PipeScheme {
    pub fn new(scheme_id: SchemeId) -> PipeScheme {
        PIPE_SCHEME_ID.store(scheme_id, Ordering::SeqCst);
        PipeScheme
    }
}

impl Scheme for PipeScheme {
    fn read(&self, id: usize, buf: &mut [u8]) -> Result<usize> {
        // Clone to prevent deadlocks
        let pipe = {
            let pipes = pipes();
            pipes.0.get(&id).map(|pipe| pipe.clone()).ok_or(Error::new(EBADF))?
        };

        pipe.read(buf)
    }

    fn write(&self, id: usize, buf: &[u8]) -> Result<usize> {
        // Clone to prevent deadlocks
        let pipe = {
            let pipes = pipes();
            pipes.1.get(&id).map(|pipe| pipe.clone()).ok_or(Error::new(EBADF))?
        };

        pipe.write(buf)
    }

    fn fcntl(&self, id: usize, cmd: usize, arg: usize) -> Result<usize> {
        let pipes = pipes();

        if let Some(pipe) = pipes.0.get(&id) {
            return pipe.fcntl(cmd, arg);
        }

        if let Some(pipe) = pipes.1.get(&id) {
            return pipe.fcntl(cmd, arg);
        }

        Err(Error::new(EBADF))
    }

    fn fevent(&self, id: usize, flags: EventFlags) -> Result<EventFlags> {
        let pipes = pipes();

        if let Some(pipe) = pipes.0.get(&id) {
            if flags == EVENT_READ {
                // TODO: Return correct flags
                if pipe.vec.lock().is_empty() {
                    return Ok(EventFlags::empty());
                } else {
                    return Ok(EVENT_READ);
                }
            }
        }

        if let Some(_pipe) = pipes.1.get(&id) {
            if flags == EVENT_WRITE {
                return Ok(EVENT_WRITE);
            }
        }

        Err(Error::new(EBADF))
    }

    fn fpath(&self, _id: usize, buf: &mut [u8]) -> Result<usize> {
        let mut i = 0;
        let scheme_path = b"pipe:";
        while i < buf.len() && i < scheme_path.len() {
            buf[i] = scheme_path[i];
            i += 1;
        }
        Ok(i)
    }

    fn fstat(&self, _id: usize, stat: &mut Stat) -> Result<usize> {
        *stat = Stat {
            st_mode: MODE_FIFO | 0o666,
            ..Default::default()
        };

        Ok(0)
    }

    fn fsync(&self, _id: usize) -> Result<usize> {
        Ok(0)
    }

    fn close(&self, id: usize) -> Result<usize> {
        let mut pipes = pipes_mut();

        drop(pipes.0.remove(&id));
        drop(pipes.1.remove(&id));

        Ok(0)
    }

    fn seek(&self, _id: usize, _pos: isize, _whence: usize) -> Result<isize> {
        Err(Error::new(ESPIPE))
    }
}

/// Read side of a pipe
pub struct PipeRead {
    scheme_id: SchemeId,
    write_id: usize,
    flags: AtomicUsize,
    condition: Arc<WaitCondition>,
    vec: Arc<Mutex<VecDeque<u8>>>
}

impl PipeRead {
    pub fn new(scheme_id: SchemeId, write_id: usize, flags: usize) -> Self {
        PipeRead {
            scheme_id,
            write_id,
            flags: AtomicUsize::new(flags),
            condition: Arc::new(WaitCondition::new()),
            vec: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    fn fcntl(&self, cmd: usize, arg: usize) -> Result<usize> {
        match cmd {
            F_GETFL => Ok(self.flags.load(Ordering::SeqCst)),
            F_SETFL => {
                self.flags.store(arg & ! O_ACCMODE, Ordering::SeqCst);
                Ok(0)
            },
            _ => Err(Error::new(EINVAL))
        }
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        loop {
            let mut vec = self.vec.lock();

            let mut i = 0;
            while i < buf.len() {
                if let Some(b) = vec.pop_front() {
                    buf[i] = b;
                    i += 1;
                } else {
                    break;
                }
            }

            if i > 0 {
                event::trigger(self.scheme_id, self.write_id, EVENT_WRITE);

                return Ok(i);
            }

            if Arc::weak_count(&self.vec) == 0 {
                return Ok(0);
            } else if self.flags.load(Ordering::SeqCst) & O_NONBLOCK == O_NONBLOCK {
                return Err(Error::new(EAGAIN));
            } else if ! self.condition.wait(vec, "PipeRead::read") {
                return Err(Error::new(EINTR));
            }
        }
    }
}

/// Read side of a pipe
pub struct PipeWrite {
    scheme_id: SchemeId,
    read_id: usize,
    flags: AtomicUsize,
    condition: Arc<WaitCondition>,
    vec: Option<Weak<Mutex<VecDeque<u8>>>>
}

impl PipeWrite {
    pub fn new(read: &PipeRead, read_id: usize, flags: usize) -> Self {
        PipeWrite {
            scheme_id: read.scheme_id,
            read_id,
            flags: AtomicUsize::new(flags),
            condition: read.condition.clone(),
            vec: Some(Arc::downgrade(&read.vec)),
        }
    }

    fn fcntl(&self, cmd: usize, arg: usize) -> Result<usize> {
        match cmd {
            F_GETFL => Ok(self.flags.load(Ordering::SeqCst)),
            F_SETFL => {
                self.flags.store(arg & ! O_ACCMODE, Ordering::SeqCst);
                Ok(0)
            },
            _ => Err(Error::new(EINVAL))
        }
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        if let Some(ref vec_weak) = self.vec {
            if let Some(vec_lock) = vec_weak.upgrade() {
                {
                    let mut vec = vec_lock.lock();

                    for &b in buf.iter() {
                        vec.push_back(b);
                    }
                }

                event::trigger(self.scheme_id, self.read_id, EVENT_READ);
                self.condition.notify();

                Ok(buf.len())
            } else {
                Err(Error::new(EPIPE))
            }
        } else {
            panic!("PipeWrite dropped before write");
        }
    }
}

impl Drop for PipeWrite {
    fn drop(&mut self) {
        drop(self.vec.take());
        event::trigger(self.scheme_id, self.read_id, EVENT_READ);
        self.condition.notify();
    }
}
