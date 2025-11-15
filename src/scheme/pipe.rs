use alloc::{collections::VecDeque, sync::Arc};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use hashbrown::{hash_map::DefaultHashBuilder, HashMap};
use spin::Mutex;

use crate::{
    context::file::InternalFlags,
    event,
    sync::{CleanLockToken, RwLock, WaitCondition, L1},
    syscall::{
        data::Stat,
        error::{Error, Result, EAGAIN, EBADF, EINTR, EINVAL, ENOENT, EPIPE},
        flag::{EventFlags, EVENT_READ, EVENT_WRITE, MODE_FIFO, O_NONBLOCK},
        usercopy::{UserSliceRo, UserSliceWo},
    },
};

use super::{CallerCtx, GlobalSchemes, KernelScheme, OpenResult, StrOrBytes};

// TODO: Preallocate a number of scheme IDs, since there can only be *one* root namespace, and
// therefore only *one* pipe scheme.
static PIPE_NEXT_ID: AtomicUsize = AtomicUsize::new(0);

// TODO: SLOB?
static PIPES: RwLock<L1, HashMap<usize, Arc<Pipe>>> =
    RwLock::new(HashMap::with_hasher(DefaultHashBuilder::new()));

const MAX_QUEUE_SIZE: usize = 65536;

// In almost all places where Rust (and LLVM) uses pointers, they are limited to nonnegative isize,
// so this is fine.
const WRITE_NOT_READ_BIT: usize = 1;

fn from_raw_id(id: usize) -> (bool, usize) {
    (id & WRITE_NOT_READ_BIT != 0, id & !WRITE_NOT_READ_BIT)
}

pub fn pipe(token: &mut CleanLockToken) -> Result<(usize, usize)> {
    // Bit 0 is used for WRITE_NOT_READ_BIT
    let id = PIPE_NEXT_ID.fetch_add(2, Ordering::Relaxed);

    PIPES.write(token.token()).insert(
        id,
        Arc::new(Pipe {
            queue: Mutex::new(VecDeque::new()),
            read_condition: WaitCondition::new(),
            write_condition: WaitCondition::new(),
            writer_is_alive: AtomicBool::new(true),
            reader_is_alive: AtomicBool::new(true),
            has_run_dup: AtomicBool::new(false),
        }),
    );

    Ok((id, id | WRITE_NOT_READ_BIT))
}

pub struct PipeScheme;

impl KernelScheme for PipeScheme {
    fn fevent(
        &self,
        id: usize,
        flags: EventFlags,
        token: &mut CleanLockToken,
    ) -> Result<EventFlags> {
        let (is_writer_not_reader, key) = from_raw_id(id);
        let pipe = Arc::clone(
            PIPES
                .read(token.token())
                .get(&key)
                .ok_or(Error::new(EBADF))?,
        );

        let mut ready = EventFlags::empty();

        if is_writer_not_reader
            && flags.contains(EVENT_WRITE)
            && (pipe.queue.lock().len() <= MAX_QUEUE_SIZE
                || !pipe.reader_is_alive.load(Ordering::Acquire))
        {
            ready |= EventFlags::EVENT_WRITE;
        }
        if !is_writer_not_reader
            && flags.contains(EVENT_READ)
            && (!pipe.queue.lock().is_empty() || !pipe.writer_is_alive.load(Ordering::Acquire))
        {
            ready |= EventFlags::EVENT_READ;
        }

        Ok(ready)
    }

    fn close(&self, id: usize, token: &mut CleanLockToken) -> Result<()> {
        let (is_write_not_read, key) = from_raw_id(id);

        let pipe = Arc::clone(
            PIPES
                .read(token.token())
                .get(&key)
                .ok_or(Error::new(EBADF))?,
        );
        let scheme_id = GlobalSchemes::Pipe.scheme_id();

        let can_remove = if is_write_not_read {
            pipe.writer_is_alive.store(false, Ordering::SeqCst);
            event::trigger(scheme_id, key, EVENT_READ);
            pipe.read_condition.notify(token);

            !pipe.reader_is_alive.load(Ordering::SeqCst)
        } else {
            pipe.reader_is_alive.store(false, Ordering::SeqCst);
            event::trigger(scheme_id, key | WRITE_NOT_READ_BIT, EVENT_WRITE);
            pipe.write_condition.notify(token);

            !pipe.writer_is_alive.load(Ordering::SeqCst)
        };

        if can_remove {
            let _ = PIPES.write(token.token()).remove(&key);
        }

        Ok(())
    }

    fn kdup(
        &self,
        old_id: usize,
        user_buf: UserSliceRo,
        _ctx: CallerCtx,
        token: &mut CleanLockToken,
    ) -> Result<OpenResult> {
        let (is_writer_not_reader, key) = from_raw_id(old_id);

        if is_writer_not_reader {
            return Err(Error::new(EBADF));
        }

        let mut buf = [0_u8; 5];

        if user_buf.copy_common_bytes_to_slice(&mut buf)? < 5 || buf != *b"write" {
            return Err(Error::new(EINVAL));
        }

        let pipe = Arc::clone(
            PIPES
                .read(token.token())
                .get(&key)
                .ok_or(Error::new(EBADF))?,
        );

        if pipe.has_run_dup.swap(true, Ordering::SeqCst) {
            return Err(Error::new(EBADF));
        }

        Ok(OpenResult::SchemeLocal(
            key | WRITE_NOT_READ_BIT,
            InternalFlags::empty(),
        ))
    }
    fn kopen(
        &self,
        path: &str,
        _flags: usize,
        _ctx: CallerCtx,
        token: &mut CleanLockToken,
    ) -> Result<OpenResult> {
        if !path.trim_start_matches('/').is_empty() {
            return Err(Error::new(ENOENT));
        }

        let (read_id, _) = pipe(token)?;

        Ok(OpenResult::SchemeLocal(read_id, InternalFlags::empty()))
    }

    fn kopenat(
        &self,
        id: usize,
        user_buf: StrOrBytes,
        _flags: usize,
        _fcntl_flags: u32,
        _ctx: CallerCtx,
        token: &mut CleanLockToken,
    ) -> Result<OpenResult> {
        let (_, key) = from_raw_id(id);

        let buf = user_buf.as_str().or(Err(Error::new(EINVAL)))?;
        if buf == "write" {
            return Err(Error::new(EINVAL));
        }

        let pipe = Arc::clone(
            PIPES
                .read(token.token())
                .get(&key)
                .ok_or(Error::new(EBADF))?,
        );

        if pipe.has_run_dup.swap(true, Ordering::SeqCst) {
            return Err(Error::new(EBADF));
        }

        Ok(OpenResult::SchemeLocal(
            key | WRITE_NOT_READ_BIT,
            InternalFlags::empty(),
        ))
    }

    fn kread(
        &self,
        id: usize,
        user_buf: UserSliceWo,
        fcntl_flags: u32,
        _stored_flags: u32,
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        let (is_write_not_read, key) = from_raw_id(id);

        if is_write_not_read {
            return Err(Error::new(EBADF));
        }
        let pipe = Arc::clone(
            PIPES
                .read(token.token())
                .get(&key)
                .ok_or(Error::new(EBADF))?,
        );

        loop {
            let mut vec = pipe.queue.lock();

            let (s1, s2) = vec.as_slices();
            let s1_count = core::cmp::min(user_buf.len(), s1.len());

            let (s1_dst, s2_buf) = user_buf
                .split_at(s1_count)
                .expect("s1_count <= user_buf.len()");
            s1_dst.copy_from_slice(&s1[..s1_count])?;

            let s2_count = core::cmp::min(s2_buf.len(), s2.len());
            s2_buf
                .limit(s2_count)
                .expect("s2_count <= s2_buf.len()")
                .copy_from_slice(&s2[..s2_count])?;

            let bytes_read = s1_count + s2_count;
            let _ = vec.drain(..bytes_read);

            if bytes_read > 0 {
                event::trigger(
                    GlobalSchemes::Pipe.scheme_id(),
                    key | WRITE_NOT_READ_BIT,
                    EVENT_WRITE,
                );
                pipe.write_condition.notify(token);

                return Ok(bytes_read);
            } else if user_buf.is_empty() {
                return Ok(0);
            }

            if !pipe.writer_is_alive.load(Ordering::SeqCst) {
                return Ok(0);
            } else if fcntl_flags & O_NONBLOCK as u32 != 0 {
                return Err(Error::new(EAGAIN));
            } else if !pipe.read_condition.wait(vec, "PipeRead::read", token) {
                return Err(Error::new(EINTR));
            }
        }
    }
    fn kwrite(
        &self,
        id: usize,
        user_buf: UserSliceRo,
        fcntl_flags: u32,
        _stored_flags: u32,
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        let (is_write_not_read, key) = from_raw_id(id);

        if !is_write_not_read {
            return Err(Error::new(EBADF));
        }
        let pipe = Arc::clone(
            PIPES
                .read(token.token())
                .get(&key)
                .ok_or(Error::new(EBADF))?,
        );

        loop {
            let mut vec = pipe.queue.lock();

            if !pipe.reader_is_alive.load(Ordering::Relaxed) {
                return Err(Error::new(EPIPE));
            }

            let bytes_left = MAX_QUEUE_SIZE.saturating_sub(vec.len());
            let bytes_to_write = core::cmp::min(bytes_left, user_buf.len());
            let src_buf = user_buf
                .limit(bytes_to_write)
                .expect("bytes_to_write <= user_buf.len()");

            const TMPBUF_SIZE: usize = 512;
            let mut tmp_buf = [0_u8; TMPBUF_SIZE];

            let mut bytes_written = 0;

            // TODO: Modify VecDeque so that the unwritten portions can be accessed directly?
            for (idx, chunk) in src_buf.in_variable_chunks(TMPBUF_SIZE).enumerate() {
                let chunk_byte_count = match chunk.copy_common_bytes_to_slice(&mut tmp_buf) {
                    Ok(c) => c,
                    Err(_) if idx > 0 => break,
                    Err(error) => return Err(error),
                };
                vec.extend(&tmp_buf[..chunk_byte_count]);
                bytes_written += chunk_byte_count;
            }

            if bytes_written > 0 {
                event::trigger(GlobalSchemes::Pipe.scheme_id(), key, EVENT_READ);
                pipe.read_condition.notify(token);

                return Ok(bytes_written);
            } else if user_buf.is_empty() {
                return Ok(0);
            }

            if fcntl_flags & O_NONBLOCK as u32 != 0 {
                return Err(Error::new(EAGAIN));
            } else if !pipe.write_condition.wait(vec, "PipeWrite::write", token) {
                return Err(Error::new(EINTR));
            }
        }
    }
    fn kfpath(&self, id: usize, buf: UserSliceWo, token: &mut CleanLockToken) -> Result<usize> {
        //TODO: construct useful path?
        buf.copy_common_bytes_from_slice("/scheme/pipe/".as_bytes())
    }
    fn kfstat(&self, _id: usize, buf: UserSliceWo, _token: &mut CleanLockToken) -> Result<()> {
        buf.copy_exactly(&Stat {
            st_mode: MODE_FIFO | 0o666,
            ..Default::default()
        })?;

        Ok(())
    }
}

pub struct Pipe {
    read_condition: WaitCondition, // signals whether there are available bytes to read
    write_condition: WaitCondition, // signals whether there is room for additional bytes
    queue: Mutex<VecDeque<u8>>,
    reader_is_alive: AtomicBool, // starts set, unset when reader closes
    writer_is_alive: AtomicBool, // starts set, unset when writer closes
    has_run_dup: AtomicBool,
}
