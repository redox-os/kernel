use core::sync::atomic::{AtomicUsize, Ordering};

use crate::{
    devices::graphical_debug,
    event,
    log::Writer,
    scheme::*,
    sync::{CleanLockToken, RwLock, WaitQueue, L1},
    syscall::{
        flag::{EventFlags, EVENT_READ, O_NONBLOCK},
        usercopy::{UserSliceRo, UserSliceWo},
    },
};

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

/// Input queue
static INPUT: WaitQueue<u8> = WaitQueue::new();

#[derive(Clone, Copy)]
struct Handle {
    num: usize,
}

static HANDLES: RwLock<L1, HashMap<usize, Handle>> =
    RwLock::new(HashMap::with_hasher(DefaultHashBuilder::new()));

/// Add to the input queue
pub fn debug_input(data: u8, token: &mut CleanLockToken) {
    INPUT.send(data, token);
}

// Notify readers of input updates
pub fn debug_notify(token: &mut CleanLockToken) {
    for (id, _handle) in HANDLES.read(token.token()).iter() {
        event::trigger(GlobalSchemes::Debug.scheme_id(), *id, EVENT_READ);
    }
}

pub struct DebugScheme;

#[repr(usize)]
enum SpecialFds {
    Default = !0,
    NoPreserve = !0 - 1,
    DisableGraphicalDebug = !0 - 2,

    #[cfg(feature = "profiling")]
    CtlProfiling = !0 - 3,
}

impl KernelScheme for DebugScheme {
    fn kopen(
        &self,
        path: &str,
        _flags: usize,
        ctx: CallerCtx,
        token: &mut CleanLockToken,
    ) -> Result<OpenResult> {
        if ctx.uid != 0 {
            return Err(Error::new(EPERM));
        }

        let num = match path {
            "" => SpecialFds::Default as usize,

            "no-preserve" => SpecialFds::NoPreserve as usize,

            "disable-graphical-debug" => SpecialFds::DisableGraphicalDebug as usize,

            #[cfg(feature = "profiling")]
            p if p.starts_with("profiling-") => {
                path[10..].parse().map_err(|_| Error::new(ENOENT))?
            }

            #[cfg(feature = "profiling")]
            "ctl-profiling" => SpecialFds::CtlProfiling as usize,

            _ => return Err(Error::new(ENOENT)),
        };

        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        HANDLES.write(token.token()).insert(id, Handle { num });

        Ok(OpenResult::SchemeLocal(id, InternalFlags::empty()))
    }

    fn fevent(
        &self,
        id: usize,
        _flags: EventFlags,
        token: &mut CleanLockToken,
    ) -> Result<EventFlags> {
        let _handle = {
            let handles = HANDLES.read(token.token());
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        Ok(EventFlags::empty())
    }

    fn fsync(&self, id: usize, token: &mut CleanLockToken) -> Result<()> {
        let _handle = {
            let handles = HANDLES.read(token.token());
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        Ok(())
    }

    fn close(&self, id: usize, token: &mut CleanLockToken) -> Result<()> {
        let _handle = {
            let mut handles = HANDLES.write(token.token());
            handles.remove(&id).ok_or(Error::new(EBADF))?
        };

        Ok(())
    }
    fn kread(
        &self,
        id: usize,
        buf: UserSliceWo,
        flags: u32,
        _stored_flags: u32,
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        let handle = {
            let handles = HANDLES.read(token.token());
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        if handle.num == SpecialFds::DisableGraphicalDebug as usize {
            return Err(Error::new(EBADF));
        }

        #[cfg(feature = "profiling")]
        if handle.num == SpecialFds::CtlProfiling as usize {
            return Err(Error::new(EBADF));
        }

        #[cfg(feature = "profiling")]
        if handle.num != SpecialFds::Default as usize {
            return crate::profiling::drain_buffer(
                crate::cpu_set::LogicalCpuId::new(handle.num as u32),
                buf,
            );
        }

        INPUT.receive_into_user(
            buf,
            flags & O_NONBLOCK as u32 == 0,
            "DebugScheme::read",
            token,
        )
    }

    fn kwrite(
        &self,
        id: usize,
        buf: UserSliceRo,
        _flags: u32,
        _stored_flags: u32,
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        let handle = {
            let handles = HANDLES.read(token.token());
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };

        #[cfg(feature = "profiling")]
        if handle.num == SpecialFds::CtlProfiling as usize {
            let mut dst = [0];
            buf.copy_to_slice(&mut dst)?;

            let is_profiling = match dst[0] {
                b'0' => false,
                b'1' => true,
                _ => return Err(Error::new(EINVAL)),
            };
            info!("Wrote {is_profiling} to IS_PROFILING");
            crate::profiling::IS_PROFILING.store(is_profiling, Ordering::Relaxed);

            return Ok(1);
        }

        if handle.num == SpecialFds::DisableGraphicalDebug as usize {
            graphical_debug::fini();

            return Ok(0);
        }

        if handle.num != SpecialFds::Default as usize
            && handle.num != SpecialFds::NoPreserve as usize
        {
            return Err(Error::new(EINVAL));
        }

        let mut tmp = [0_u8; 512];

        for chunk in buf.in_variable_chunks(tmp.len()) {
            let byte_count = chunk.copy_common_bytes_to_slice(&mut tmp)?;
            let tmp_bytes = &tmp[..byte_count];

            // The reason why a new writer is created for each iteration, is because the page fault
            // handler in usercopy might use the same lock when printing for debug purposes, and
            // although it most likely won't, it would be dangerous to rely on that assumption.
            Writer::new().write(tmp_bytes, handle.num != SpecialFds::NoPreserve as usize);
        }

        Ok(buf.len())
    }
    fn kfpath(&self, id: usize, buf: UserSliceWo, token: &mut CleanLockToken) -> Result<usize> {
        let handle = {
            let handles = HANDLES.read(token.token());
            *handles.get(&id).ok_or(Error::new(EBADF))?
        };
        if handle.num != SpecialFds::Default as usize
            && handle.num != SpecialFds::NoPreserve as usize
        {
            return Err(Error::new(EINVAL));
        }

        // TODO: Copy elsewhere in the kernel?
        const SRC: &[u8] = b"debug:";
        let byte_count = core::cmp::min(buf.len(), SRC.len());
        buf.limit(byte_count)
            .expect("must succeed")
            .copy_from_slice(&SRC[..byte_count])?;

        Ok(byte_count)
    }
}
