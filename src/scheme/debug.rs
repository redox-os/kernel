use core::sync::atomic::{AtomicUsize, Ordering, AtomicPtr};
use spin::RwLock;

use crate::arch::debug::Writer;
use crate::event;
use crate::percpu::RingBuffer;
use crate::scheme::*;
use crate::sync::WaitQueue;
use crate::syscall::flag::{EventFlags, EVENT_READ, F_GETFL, F_SETFL, O_ACCMODE, O_NONBLOCK};
use crate::syscall::usercopy::{UserSliceRo, UserSliceWo};

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

/// Input queue
static INPUT: WaitQueue<u8> = WaitQueue::new();

#[derive(Clone, Copy)]
struct Handle {
    flags: usize,
    num: usize,
}

// Using BTreeMap as hashbrown doesn't have a const constructor.
static HANDLES: RwLock<BTreeMap<usize, Handle>> = RwLock::new(BTreeMap::new());

/// Add to the input queue
pub fn debug_input(data: u8) {
    INPUT.send(data);
}

// Notify readers of input updates
pub fn debug_notify() {
    for (id, _handle) in HANDLES.read().iter() {
        event::trigger(GlobalSchemes::Debug.scheme_id(), *id, EVENT_READ);
    }
}

pub struct DebugScheme;

impl KernelScheme for DebugScheme {
    fn kopen(&self, path: &str, flags: usize, ctx: CallerCtx) -> Result<OpenResult> {
        if ctx.uid != 0 {
            return Err(Error::new(EPERM));
        }

        let num = match path {
            "" => !0,
            "profiling" => flags & 0xffff,

            _ => return Err(Error::new(ENOENT)),
        };

        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        HANDLES.write().insert(id, Handle {
            flags: flags & ! O_ACCMODE,
            num,
        });

        Ok(OpenResult::SchemeLocal(id))
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

    fn fsync(&self, id: usize) -> Result<()> {
        let _handle = {
            let handles = HANDLES.read();
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        Ok(())
    }

    /// Close the file `number`
    fn close(&self, id: usize) -> Result<()> {
        let _handle = {
            let mut handles = HANDLES.write();
            handles.remove(&id).ok_or(Error::new(EBADF))?
        };

        Ok(())
    }
    fn kread(&self, id: usize, buf: UserSliceWo) -> Result<usize> {
        let handle = {
            let handles = HANDLES.read();
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        if handle.num == !0 {
            INPUT
                .receive_into_user(buf, handle.flags & O_NONBLOCK != O_NONBLOCK, "DebugScheme::read")
        } else {
            unsafe {
                let Some(src) = BUFS.get(handle.num).ok_or(Error::new(EBADFD))?.load(Ordering::Relaxed).as_ref() else {
                    return Ok(0);
                };
                let byte_slices = src.peek().map(|words| core::slice::from_raw_parts(words.as_ptr().cast::<u8>(), words.len() * 8));

                let copied_1 = buf.copy_common_bytes_from_slice(byte_slices[0])?;
                src.advance(copied_1 / 8);

                let copied_2 = if let Some(remaining) = buf.advance(copied_1) {
                    remaining.copy_common_bytes_from_slice(byte_slices[1])?
                } else {
                    0
                };
                src.advance(copied_2 / 8);

                Ok(copied_1 + copied_2)
            }
        }
    }

    fn kwrite(&self, id: usize, buf: UserSliceRo) -> Result<usize> {
        let _handle = {
            let handles = HANDLES.read();
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        let mut tmp = [0_u8; 512];

        for chunk in buf.in_variable_chunks(tmp.len()) {
            let byte_count = chunk.copy_common_bytes_to_slice(&mut tmp)?;
            let tmp_bytes = &tmp[..byte_count];

            // The reason why a new writer is created for each iteration, is because the page fault
            // handler in usercopy might use the same lock when printing for debug purposes, and
            // although it most likely won't, it would be dangerous to rely on that assumption.
            Writer::new().write(tmp_bytes);
        }

        Ok(buf.len())
    }
    fn kfpath(&self, id: usize, buf: UserSliceWo) -> Result<usize> {
        let _handle = {
            let handles = HANDLES.read();
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        // TODO: Copy elsewhere in the kernel?
        const SRC: &[u8] = b"debug:";
        let byte_count = core::cmp::min(buf.len(), SRC.len());
        buf.limit(byte_count).expect("must succeed").copy_from_slice(&SRC[..byte_count])?;

        Ok(byte_count)
    }
}

const NULL: AtomicPtr<RingBuffer> = AtomicPtr::new(core::ptr::null_mut());
pub static BUFS: [AtomicPtr<RingBuffer>; 4] = [NULL; 4];
