use core::sync::atomic::{self, AtomicUsize};

use alloc::{boxed::Box, collections::BTreeMap};
use spin::{Once, RwLock};

use super::{CallerCtx, KernelScheme, OpenResult};
use crate::{
    dtb::DTB_BINARY,
    scheme::SchemeId,
    syscall::{
        data::Stat,
        error::*,
        flag::{MODE_FILE, O_STAT, SEEK_CUR, SEEK_END, SEEK_SET},
        usercopy::{UserSliceRo, UserSliceWo},
    },
};

pub struct DtbScheme;

#[derive(Eq, PartialEq)]
enum HandleKind {
    RawData,
}

struct Handle {
    offset: usize,
    kind: HandleKind,
    stat: bool,
}

static HANDLES: RwLock<BTreeMap<usize, Handle>> = RwLock::new(BTreeMap::new());
static NEXT_FD: AtomicUsize = AtomicUsize::new(0);
static DATA: Once<Box<[u8]>> = Once::new();

impl DtbScheme {
    pub fn init() {
        let mut data_init = false;

        DATA.call_once(|| {
            data_init = true;

            let dtb = match DTB_BINARY.get() {
                Some(dtb) => dtb.as_slice(),
                None => &[],
            };

            Box::from(dtb)
        });

        if !data_init {
            log::error!("DtbScheme::new called multiple times");
        }
    }
}

impl KernelScheme for DtbScheme {
    fn kopen(&self, path: &str, _flags: usize, _ctx: CallerCtx) -> Result<OpenResult> {
        let path = path.trim_matches('/');

        if path.is_empty() {
            let id = NEXT_FD.fetch_add(1, atomic::Ordering::Relaxed);

            let mut handles_guard = HANDLES.write();

            let _ = handles_guard.insert(
                id,
                Handle {
                    offset: 0,
                    kind: HandleKind::RawData,
                    stat: _flags & O_STAT == O_STAT,
                },
            );
            return Ok(OpenResult::SchemeLocal(id));
        }

        Err(Error::new(ENOENT))
    }

    fn seek(&self, id: usize, pos: isize, whence: usize) -> Result<usize> {
        let mut handles = HANDLES.write();
        let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;

        if handle.stat {
            return Err(Error::new(EBADF));
        }

        let file_len = match handle.kind {
            HandleKind::RawData => DATA.get().ok_or(Error::new(EBADFD))?.len(),
        };

        let new_offset = match whence {
            SEEK_SET => pos as usize,
            SEEK_CUR => {
                if pos < 0 {
                    handle
                        .offset
                        .checked_sub((-pos) as usize)
                        .ok_or(Error::new(EINVAL))?
                } else {
                    handle.offset.saturating_add(pos as usize)
                }
            }
            SEEK_END => {
                if pos < 0 {
                    file_len
                        .checked_sub((-pos) as usize)
                        .ok_or(Error::new(EINVAL))?
                } else {
                    file_len
                }
            }
            _ => return Err(Error::new(EINVAL)),
        };

        handle.offset = new_offset;

        Ok(new_offset as usize)
    }

    fn close(&self, id: usize) -> Result<()> {
        if HANDLES.write().remove(&id).is_none() {
            return Err(Error::new(EBADF));
        }
        Ok(())
    }

    fn kwrite(&self, _id: usize, _buf: UserSliceRo) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    fn kread(&self, id: usize, dst_buf: UserSliceWo) -> Result<usize> {
        let mut handles = HANDLES.write();
        let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;

        if handle.stat {
            return Err(Error::new(EBADF));
        }

        let data = match handle.kind {
            HandleKind::RawData => DATA.get().ok_or(Error::new(EBADFD))?,
        };

        let src_offset = core::cmp::min(handle.offset, data.len());
        let src_buf = data
            .get(src_offset..)
            .expect("expected data to be at least data.len() bytes long");

        let bytes_copied = dst_buf.copy_common_bytes_from_slice(src_buf)?;
        handle.offset += bytes_copied;

        Ok(bytes_copied)
    }

    fn kfstat(&self, id: usize, buf: UserSliceWo) -> Result<()> {
        let handles = HANDLES.read();
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
