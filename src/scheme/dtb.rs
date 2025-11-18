use core::sync::atomic::{self, AtomicUsize};

use alloc::boxed::Box;
use hashbrown::{hash_map::DefaultHashBuilder, HashMap};
use spin::Once;

use super::{CallerCtx, KernelScheme, OpenResult};
use crate::{
    dtb::DTB_BINARY,
    scheme::InternalFlags,
    sync::{CleanLockToken, RwLock, L1},
    syscall::{
        data::Stat,
        error::*,
        flag::{MODE_FILE, O_STAT},
        usercopy::UserSliceWo,
    },
};

pub struct DtbScheme;

#[derive(Eq, PartialEq)]
enum HandleKind {
    RawData,
}

struct Handle {
    kind: HandleKind,
    stat: bool,
}

static HANDLES: RwLock<L1, HashMap<usize, Handle>> =
    RwLock::new(HashMap::with_hasher(DefaultHashBuilder::new()));
static NEXT_FD: AtomicUsize = AtomicUsize::new(0);
static DATA: Once<Box<[u8]>> = Once::new();

impl DtbScheme {
    pub fn init() {
        let mut data_init = false;

        DATA.call_once(|| {
            data_init = true;

            Box::from(DTB_BINARY.get().map(|&d| d).unwrap_or(&[]))
        });

        if !data_init {
            error!("DtbScheme::new called multiple times");
        }
    }
}

impl KernelScheme for DtbScheme {
    fn kopen(
        &self,
        path: &str,
        _flags: usize,
        _ctx: CallerCtx,
        token: &mut CleanLockToken,
    ) -> Result<OpenResult> {
        let path = path.trim_matches('/');

        if path.is_empty() {
            let id = NEXT_FD.fetch_add(1, atomic::Ordering::Relaxed);

            let mut handles_guard = HANDLES.write(token.token());

            let _ = handles_guard.insert(
                id,
                Handle {
                    kind: HandleKind::RawData,
                    stat: _flags & O_STAT == O_STAT,
                },
            );
            return Ok(OpenResult::SchemeLocal(id, InternalFlags::POSITIONED));
        }

        Err(Error::new(ENOENT))
    }

    fn fsize(&self, id: usize, token: &mut CleanLockToken) -> Result<u64> {
        let mut handles = HANDLES.write(token.token());
        let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;

        if handle.stat {
            return Err(Error::new(EBADF));
        }

        let file_len = match handle.kind {
            HandleKind::RawData => DATA.get().ok_or(Error::new(EBADFD))?.len(),
        };

        Ok(file_len as u64)
    }

    fn close(&self, id: usize, token: &mut CleanLockToken) -> Result<()> {
        if HANDLES.write(token.token()).remove(&id).is_none() {
            return Err(Error::new(EBADF));
        }
        Ok(())
    }

    fn kreadoff(
        &self,
        id: usize,
        dst_buf: UserSliceWo,
        offset: u64,
        _flags: u32,
        _stored_flags: u32,
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        let mut handles = HANDLES.write(token.token());
        let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;

        if handle.stat {
            return Err(Error::new(EBADF));
        }

        let data = match handle.kind {
            HandleKind::RawData => DATA.get().ok_or(Error::new(EBADFD))?,
        };

        let src_offset = core::cmp::min(offset.try_into().unwrap(), data.len());
        let src_buf = data
            .get(src_offset..)
            .expect("expected data to be at least data.len() bytes long");

        dst_buf.copy_common_bytes_from_slice(src_buf)
    }

    fn kfpath(&self, id: usize, buf: UserSliceWo, token: &mut CleanLockToken) -> Result<usize> {
        //TODO: construct useful path?
        buf.copy_common_bytes_from_slice("/scheme/kernel.dtb/".as_bytes())
    }

    fn kfstat(&self, id: usize, buf: UserSliceWo, token: &mut CleanLockToken) -> Result<()> {
        let handles = HANDLES.read(token.token());
        let handle = handles.get(&id).ok_or(Error::new(EBADF))?;
        buf.copy_exactly(&match handle.kind {
            HandleKind::RawData => {
                let data = DATA.get().ok_or(Error::new(EBADFD))?;
                Stat {
                    st_mode: MODE_FILE,
                    st_uid: 0,
                    st_gid: 0,
                    st_size: data.len().try_into().unwrap_or(u64::max_value()),
                    ..Default::default()
                }
            }
        })?;

        Ok(())
    }
}
