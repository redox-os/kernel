use core::sync::atomic::{AtomicUsize, Ordering, AtomicBool};

use alloc::sync::Arc;
use alloc::collections::{BTreeMap, VecDeque};

use spin::{Mutex, Once, RwLock};

use crate::event;
use crate::scheme::SchemeId;
use crate::sync::WaitCondition;
use crate::syscall::error::{Error, Result, EAGAIN, EBADF, EINTR, EINVAL, ENOENT, EPIPE, ESPIPE};
use crate::syscall::flag::{EventFlags, EVENT_READ, EVENT_WRITE, F_GETFL, F_SETFL, O_ACCMODE, O_NONBLOCK, MODE_FIFO};
use crate::syscall::scheme::Scheme;
use crate::syscall::data::Stat;

use super::KernelScheme;

// TODO: Preallocate a number of scheme IDs, since there can only be *one* root namespace, and
// therefore only *one* pipe scheme.
static THE_PIPE_SCHEME: Once<(SchemeId, Arc<dyn KernelScheme>)> = Once::new();
static PIPE_NEXT_ID: AtomicUsize = AtomicUsize::new(1);

// TODO: SLOB?
static PIPES: RwLock<BTreeMap<usize, Arc<Pipe>>> = RwLock::new(BTreeMap::new());

pub fn pipe_scheme_id() -> SchemeId {
    THE_PIPE_SCHEME.get().expect("pipe scheme must be initialized").0
}

const MAX_QUEUE_SIZE: usize = 65536;

// In almost all places where Rust (and LLVM) uses pointers, they are limited to nonnegative isize,
// so this is fine.
const WRITE_NOT_READ_BIT: usize = 1 << (usize::BITS - 1);

fn from_raw_id(id: usize) -> (bool, usize) {
    (id & WRITE_NOT_READ_BIT != 0, id & !WRITE_NOT_READ_BIT)
}

pub fn pipe(flags: usize) -> Result<(usize, usize)> {
    let id = PIPE_NEXT_ID.fetch_add(1, Ordering::Relaxed);

    PIPES.write().insert(id, Arc::new(Pipe {
        read_flags: AtomicUsize::new(flags),
        write_flags: AtomicUsize::new(flags),
        queue: Mutex::new(VecDeque::new()),
        read_condition: WaitCondition::new(),
        write_condition: WaitCondition::new(),
        writer_is_alive: AtomicBool::new(true),
        reader_is_alive: AtomicBool::new(true),
        has_run_dup: AtomicBool::new(false),
    }));

    Ok((id, id | WRITE_NOT_READ_BIT))
}

pub struct PipeScheme;

impl PipeScheme {
    pub fn new(scheme_id: SchemeId) -> Arc<dyn KernelScheme> {
        Arc::clone(&THE_PIPE_SCHEME.call_once(|| {
            (scheme_id, Arc::new(Self))
        }).1)
    }
}

impl Scheme for PipeScheme {
    fn open(&self, path: &str, flags: usize, _uid: u32, _gid: u32) -> Result<usize> {
        if !path.trim_start_matches('/').is_empty() {
            return Err(Error::new(ENOENT));
        }

        let (read_id, _) = pipe(flags)?;

        Ok(read_id)
    }
    fn read(&self, id: usize, buf: &mut [u8]) -> Result<usize> {
        let (is_write_not_read, key) = from_raw_id(id);

        if is_write_not_read {
            return Err(Error::new(EBADF));
        }
        let pipe = Arc::clone(PIPES.read().get(&key).ok_or(Error::new(EBADF))?);

        loop {
            let mut vec = pipe.queue.lock();

            let (s1, s2) = vec.as_slices();
            let s1_count = core::cmp::min(buf.len(), s1.len());

            let (s1_dst, s2_buf) = buf.split_at_mut(s1_count);
            s1_dst.copy_from_slice(&s1[..s1_count]);

            let s2_count = core::cmp::min(s2_buf.len(), s2.len());
            s2_buf[..s2_count].copy_from_slice(&s2[..s2_count]);

            let bytes_read = s1_count + s2_count;
            let _ = vec.drain(..bytes_read);

            if bytes_read > 0 {
                event::trigger(pipe_scheme_id(), key | WRITE_NOT_READ_BIT, EVENT_WRITE);
                pipe.write_condition.notify();

                return Ok(bytes_read);
            } else if buf.is_empty() {
                return Ok(0);
            }

            if !pipe.writer_is_alive.load(Ordering::SeqCst) {
                return Ok(0);
            } else if pipe.read_flags.load(Ordering::SeqCst) & O_NONBLOCK == O_NONBLOCK {
                return Err(Error::new(EAGAIN));
            } else if !pipe.read_condition.wait(vec, "PipeRead::read") {
                return Err(Error::new(EINTR));
            }
        }
    }
    fn write(&self, id: usize, buf: &[u8]) -> Result<usize> {
        let (is_write_not_read, key) = from_raw_id(id);

        if !is_write_not_read {
            return Err(Error::new(EBADF));
        }
        let pipe = Arc::clone(PIPES.read().get(&key).ok_or(Error::new(EBADF))?);

        loop {
            let mut vec = pipe.queue.lock();

            let bytes_left = MAX_QUEUE_SIZE.saturating_sub(vec.len());
            let byte_count = core::cmp::min(bytes_left, buf.len());

            vec.extend(buf[..byte_count].iter());

            if byte_count > 0 {
                event::trigger(pipe_scheme_id(), key, EVENT_READ);
                pipe.read_condition.notify();

                return Ok(byte_count);
            } else if buf.is_empty() {
                return Ok(0);
            }

            if !pipe.reader_is_alive.load(Ordering::SeqCst) {
                return Err(Error::new(EPIPE));
            } else if pipe.write_flags.load(Ordering::SeqCst) & O_NONBLOCK == O_NONBLOCK {
                return Err(Error::new(EAGAIN));
            } else if !pipe.write_condition.wait(vec, "PipeWrite::write") {
                return Err(Error::new(EINTR));
            }
        }
    }

    fn dup(&self, old_id: usize, buf: &[u8]) -> Result<usize> {
        let (is_writer_not_reader, key) = from_raw_id(old_id);

        if is_writer_not_reader {
            return Err(Error::new(EBADF));
        }
        if buf != b"write" {
            return Err(Error::new(EINVAL));
        }

        let pipe = Arc::clone(PIPES.read().get(&key).ok_or(Error::new(EBADF))?);

        if pipe.has_run_dup.swap(true, Ordering::SeqCst) {
            return Err(Error::new(EBADF));
        }

        Ok(key | WRITE_NOT_READ_BIT)
    }

    fn fcntl(&self, id: usize, cmd: usize, arg: usize) -> Result<usize> {
        let (is_writer_not_reader, key) = from_raw_id(id);
        let pipe = Arc::clone(PIPES.read().get(&key).ok_or(Error::new(EBADF))?);

        let flags = if is_writer_not_reader { &pipe.write_flags } else { &pipe.read_flags };

        match cmd {
            F_GETFL => Ok(flags.load(Ordering::SeqCst)),
            F_SETFL => {
                flags.store(arg & !O_ACCMODE, Ordering::SeqCst);
                Ok(0)
            },
            _ => Err(Error::new(EINVAL))
        }
    }

    fn fevent(&self, id: usize, flags: EventFlags) -> Result<EventFlags> {
        let (is_writer_not_reader, key) = from_raw_id(id);
        let pipe = Arc::clone(PIPES.read().get(&key).ok_or(Error::new(EBADF))?);

        if is_writer_not_reader && flags == EVENT_WRITE {
            // TODO: Return correct flags
            if pipe.queue.lock().len() >= MAX_QUEUE_SIZE {
                return Ok(EventFlags::empty());
            } else {
                return Ok(EVENT_WRITE);
            }
        } else if flags == EVENT_READ {
            // TODO: Return correct flags
            if pipe.queue.lock().is_empty() {
                return Ok(EventFlags::empty());
            } else {
                return Ok(EVENT_READ);
            }
        }

        Err(Error::new(EBADF))
    }

    fn fpath(&self, _id: usize, buf: &mut [u8]) -> Result<usize> {
        let scheme_path = b"pipe:";
        let to_copy = core::cmp::min(buf.len(), scheme_path.len());
        buf[..to_copy].copy_from_slice(&scheme_path[..to_copy]);
        Ok(to_copy)
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
        let (is_write_not_read, key) = from_raw_id(id);

        let pipe = Arc::clone(PIPES.read().get(&key).ok_or(Error::new(EBADF))?);
        let scheme_id = pipe_scheme_id();

        let can_remove = if is_write_not_read {
            event::trigger(scheme_id, key, EVENT_READ);

            pipe.read_condition.notify();
            pipe.writer_is_alive.store(false, Ordering::SeqCst);

            !pipe.reader_is_alive.load(Ordering::SeqCst)
        } else {
            event::trigger(scheme_id, key | WRITE_NOT_READ_BIT, EVENT_WRITE);

            pipe.write_condition.notify();
            pipe.reader_is_alive.store(false, Ordering::SeqCst);

            !pipe.writer_is_alive.load(Ordering::SeqCst)
        };

        if can_remove {
            let _ = PIPES.write().remove(&key);
        }

        Ok(0)
    }

    fn seek(&self, _id: usize, _pos: isize, _whence: usize) -> Result<isize> {
        Err(Error::new(ESPIPE))
    }
}

pub struct Pipe {
    read_flags: AtomicUsize, // fcntl read flags
    write_flags: AtomicUsize, // fcntl write flags
    read_condition: WaitCondition, // signals whether there are available bytes to read
    write_condition: WaitCondition, // signals whether there is room for additional bytes
    queue: Mutex<VecDeque<u8>>,
    reader_is_alive: AtomicBool, // starts set, unset when reader closes
    writer_is_alive: AtomicBool, // starts set, unset when writer closes
    has_run_dup: AtomicBool,
}

impl crate::scheme::KernelScheme for PipeScheme {}
