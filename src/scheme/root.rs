use alloc::{boxed::Box, string::ToString, sync::Arc, vec::Vec};
use core::{
    str,
    sync::atomic::{AtomicUsize, Ordering},
};
use hashbrown::HashMap;
use spin::{Mutex, RwLock};

use crate::{
    context,
    scheme::{
        self,
        user::{UserInner, UserScheme},
        SchemeId, SchemeNamespace,
    },
    syscall::{
        data::Stat,
        error::*,
        flag::{EventFlags, MODE_DIR, MODE_FILE, O_CREAT},
        usercopy::{UserSliceRo, UserSliceWo},
    },
};

use super::{calc_seek_offset, CallerCtx, KernelScheme, KernelSchemes, OpenResult};

struct FolderInner {
    data: Box<[u8]>,
    pos: Mutex<usize>,
}

impl FolderInner {
    fn read(&self, buf: UserSliceWo) -> Result<usize> {
        let mut pos_guard = self.pos.lock();

        let avail_buf = self.data.get(*pos_guard..).unwrap_or(&[]);
        let bytes_read = buf.copy_common_bytes_from_slice(avail_buf)?;
        *pos_guard += bytes_read;

        Ok(bytes_read)
    }

    fn seek(&self, pos: isize, whence: usize) -> Result<usize> {
        let mut seek = self.pos.lock();
        let new_offset = calc_seek_offset(*seek, pos, whence, self.data.len())?;
        *seek = new_offset as usize;
        Ok(new_offset)
    }
}

#[derive(Clone)]
enum Handle {
    Scheme(Arc<UserInner>),
    File(Arc<Box<[u8]>>),
    Folder(Arc<FolderInner>),
}

pub struct RootScheme {
    scheme_ns: SchemeNamespace,
    scheme_id: SchemeId,
    next_id: AtomicUsize,
    handles: RwLock<HashMap<usize, Handle>>,
}

impl RootScheme {
    pub fn new(scheme_ns: SchemeNamespace, scheme_id: SchemeId) -> RootScheme {
        RootScheme {
            scheme_ns,
            scheme_id,
            next_id: AtomicUsize::new(0),
            handles: RwLock::new(HashMap::new()),
        }
    }
}

impl KernelScheme for RootScheme {
    fn kopen(&self, path: &str, flags: usize, ctx: CallerCtx) -> Result<OpenResult> {
        let path = path.trim_start_matches('/');

        //TODO: Make this follow standards for flags and errors
        if flags & O_CREAT == O_CREAT {
            if ctx.uid != 0 {
                return Err(Error::new(EACCES));
            };

            if path.contains('/') {
                return Err(Error::new(EINVAL));
            }

            let context = {
                let contexts = context::contexts();
                let context = contexts.current().ok_or(Error::new(ESRCH))?;
                Arc::downgrade(context)
            };

            let id = self.next_id.fetch_add(1, Ordering::Relaxed);

            let inner = {
                let path_box = path.to_string().into_boxed_str();
                let mut schemes = scheme::schemes_mut();

                let (_scheme_id, inner) =
                    schemes.insert_and_pass(self.scheme_ns, path, |scheme_id| {
                        let inner = Arc::new(UserInner::new(
                            self.scheme_id,
                            scheme_id,
                            id,
                            path_box,
                            flags,
                            context,
                        ));
                        (
                            KernelSchemes::User(UserScheme::new(Arc::downgrade(&inner))),
                            inner,
                        )
                    })?;

                inner
            };

            self.handles.write().insert(id, Handle::Scheme(inner));

            Ok(OpenResult::SchemeLocal(id))
        } else if path.is_empty() {
            let scheme_ns = {
                let contexts = context::contexts();
                let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
                let context = context_lock.read();
                context.ens
            };

            let mut data = Vec::new();
            {
                let schemes = scheme::schemes();
                for (name, _scheme_id) in schemes.iter_name(scheme_ns) {
                    data.extend_from_slice(name.as_bytes());
                    data.push(b'\n');
                }
            }

            let inner = Arc::new(FolderInner {
                data: data.into_boxed_slice(),
                pos: Mutex::new(0),
            });

            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            self.handles.write().insert(id, Handle::Folder(inner));
            Ok(OpenResult::SchemeLocal(id))
        } else {
            let inner = Arc::new(path.as_bytes().to_vec().into_boxed_slice());

            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            self.handles.write().insert(id, Handle::File(inner));
            Ok(OpenResult::SchemeLocal(id))
        }
    }

    fn unlink(&self, path: &str, ctx: CallerCtx) -> Result<()> {
        let path = path.trim_matches('/');

        if ctx.uid != 0 {
            return Err(Error::new(EACCES));
        }
        let inner = {
            let handles = self.handles.read();
            handles
                .iter()
                .find_map(|(_id, handle)| {
                    match handle {
                        Handle::Scheme(inner) => {
                            if path == inner.name.as_ref() {
                                return Some(inner.clone());
                            }
                        }
                        _ => (),
                    }
                    None
                })
                .ok_or(Error::new(ENOENT))?
        };

        inner.unmount()
    }

    fn seek(&self, file: usize, pos: isize, whence: usize) -> Result<usize> {
        let handle = {
            let handles = self.handles.read();
            let handle = handles.get(&file).ok_or(Error::new(EBADF))?;
            handle.clone()
        };

        match handle {
            Handle::Scheme(_) => Err(Error::new(EBADF)),
            Handle::File(_) => Err(Error::new(EBADF)),
            Handle::Folder(inner) => inner.seek(pos, whence),
        }
    }

    fn fevent(&self, file: usize, flags: EventFlags) -> Result<EventFlags> {
        let handle = {
            let handles = self.handles.read();
            let handle = handles.get(&file).ok_or(Error::new(EBADF))?;
            handle.clone()
        };

        match handle {
            Handle::Scheme(inner) => inner.fevent(flags),
            Handle::File(_) => Err(Error::new(EBADF)),
            Handle::Folder(_) => Err(Error::new(EBADF)),
        }
    }

    fn kfpath(&self, file: usize, mut buf: UserSliceWo) -> Result<usize> {
        let handle = {
            let handles = self.handles.read();
            let handle = handles.get(&file).ok_or(Error::new(EBADF))?;
            handle.clone()
        };

        let mut bytes_copied = buf.copy_common_bytes_from_slice(b":")?;
        buf = buf.advance(bytes_copied).ok_or(Error::new(EINVAL))?;

        match handle {
            Handle::Scheme(inner) => {
                bytes_copied += buf.copy_common_bytes_from_slice(inner.name.as_bytes())?;
            }
            Handle::File(inner) => {
                bytes_copied += buf.copy_common_bytes_from_slice(&inner)?;
            }
            Handle::Folder(_) => (),
        }

        Ok(bytes_copied)
    }

    fn fsync(&self, file: usize) -> Result<()> {
        let handle = {
            let handles = self.handles.read();
            let handle = handles.get(&file).ok_or(Error::new(EBADF))?;
            handle.clone()
        };

        match handle {
            Handle::Scheme(inner) => inner.fsync(),
            Handle::File(_) => Err(Error::new(EBADF)),
            Handle::Folder(_) => Err(Error::new(EBADF)),
        }
    }

    fn close(&self, file: usize) -> Result<()> {
        let handle = self
            .handles
            .write()
            .remove(&file)
            .ok_or(Error::new(EBADF))?;
        match handle {
            Handle::Scheme(inner) => {
                scheme::schemes_mut().remove(inner.scheme_id);
            }
            _ => (),
        }
        Ok(())
    }
    fn kread(&self, file: usize, buf: UserSliceWo) -> Result<usize> {
        let handle = {
            let handles = self.handles.read();
            let handle = handles.get(&file).ok_or(Error::new(EBADF))?;
            handle.clone()
        };

        match handle {
            Handle::Scheme(inner) => inner.read(buf),
            Handle::File(_) => Err(Error::new(EBADF)),
            Handle::Folder(inner) => inner.read(buf),
        }
    }

    fn kwrite(&self, file: usize, buf: UserSliceRo) -> Result<usize> {
        let handle = {
            let handles = self.handles.read();
            let handle = handles.get(&file).ok_or(Error::new(EBADF))?;
            handle.clone()
        };

        match handle {
            Handle::Scheme(inner) => inner.write(buf),
            Handle::File(_) => Err(Error::new(EBADF)),
            Handle::Folder(_) => Err(Error::new(EBADF)),
        }
    }

    fn kfstat(&self, file: usize, buf: UserSliceWo) -> Result<()> {
        let handle = {
            let handles = self.handles.read();
            let handle = handles.get(&file).ok_or(Error::new(EBADF))?;
            handle.clone()
        };

        buf.copy_exactly(&match handle {
            Handle::Scheme(_) => Stat {
                st_mode: MODE_FILE,
                st_uid: 0,
                st_gid: 0,
                st_size: 0,
                ..Default::default()
            },
            Handle::File(_) => Stat {
                st_mode: MODE_FILE,
                st_uid: 0,
                st_gid: 0,
                st_size: 0,
                ..Default::default()
            },
            Handle::Folder(inner) => Stat {
                st_mode: MODE_DIR,
                st_uid: 0,
                st_gid: 0,
                st_size: inner.data.len() as u64,
                ..Default::default()
            },
        })?;

        Ok(())
    }
}
