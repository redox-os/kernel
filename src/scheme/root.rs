use alloc::{boxed::Box, string::ToString, sync::Arc};
use core::{
    str,
    sync::atomic::{AtomicUsize, Ordering},
};
use hashbrown::HashMap;
use spin::RwLock;
use syscall::{
    dirent::{DirEntry, DirentBuf, DirentKind},
    O_FSYNC,
};

use crate::{
    context::{self, file::InternalFlags, process},
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

use super::{CallerCtx, KernelScheme, KernelSchemes, OpenResult};

#[derive(Clone)]
enum Handle {
    Scheme(Arc<UserInner>),
    File(Arc<Box<[u8]>>),
    List { ens: SchemeNamespace },
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

            let context = Arc::downgrade(&context::current());

            let id = self.next_id.fetch_add(1, Ordering::Relaxed);

            let inner = {
                let path_box = path.to_string().into_boxed_str();
                let mut schemes = scheme::schemes_mut();

                let v2 = flags & O_FSYNC == O_FSYNC;

                if !v2 {
                    //log::warn!("Context {} opened a v1 scheme", context::current().read().name);
                }

                let (_scheme_id, inner) =
                    schemes.insert_and_pass(self.scheme_ns, path, |scheme_id| {
                        let inner = Arc::new(UserInner::new(
                            self.scheme_id,
                            scheme_id,
                            // TODO: This is a hack, but eventually the legacy interface will be
                            // removed.
                            v2,
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

            Ok(OpenResult::SchemeLocal(id, InternalFlags::empty()))
        } else if path.is_empty() {
            let ens = process::current()?.read().ens;

            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            self.handles.write().insert(id, Handle::List { ens });
            Ok(OpenResult::SchemeLocal(id, InternalFlags::POSITIONED))
        } else {
            let inner = Arc::new(path.as_bytes().to_vec().into_boxed_slice());

            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            self.handles.write().insert(id, Handle::File(inner));
            Ok(OpenResult::SchemeLocal(id, InternalFlags::POSITIONED))
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

    fn fsize(&self, file: usize) -> Result<u64> {
        let handle = {
            let handles = self.handles.read();
            let handle = handles.get(&file).ok_or(Error::new(EBADF))?;
            handle.clone()
        };

        match handle {
            Handle::Scheme(_) => Err(Error::new(EBADF)),
            Handle::File(_) => Err(Error::new(EBADF)),
            Handle::List { .. } => Ok(0),
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
            Handle::List { .. } => Err(Error::new(EBADF)),
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
            Handle::List { .. } => (),
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
            Handle::List { .. } => Err(Error::new(EBADF)),
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
    fn kreadoff(
        &self,
        file: usize,
        buf: UserSliceWo,
        _offset: u64,
        flags: u32,
        _stored_flags: u32,
    ) -> Result<usize> {
        let handle = {
            let handles = self.handles.read();
            let handle = handles.get(&file).ok_or(Error::new(EBADF))?;
            handle.clone()
        };

        match handle {
            Handle::Scheme(inner) => inner.read(buf, flags),
            Handle::File(_) => Err(Error::new(EBADF)),
            Handle::List { .. } => Err(Error::new(EISDIR)),
        }
    }
    fn getdents(
        &self,
        id: usize,
        buf: UserSliceWo,
        header_size: u16,
        opaque: u64,
    ) -> Result<usize> {
        let Handle::List { ens } = *self.handles.read().get(&id).ok_or(Error::new(EBADF))? else {
            return Err(Error::new(ENOTDIR));
        };

        let mut buf = DirentBuf::new(buf, header_size).ok_or(Error::new(EIO))?;
        {
            let schemes = scheme::schemes();
            for (i, (name, _)) in schemes
                .iter_name(ens)
                .enumerate()
                .skip_while(|(i, _)| (*i as u64) < opaque)
                .filter(|(_, (name, _))| !name.is_empty())
            {
                buf.entry(DirEntry {
                    kind: DirentKind::Unspecified,
                    name,
                    inode: 0,
                    next_opaque_id: i as u64 + 1,
                })?;
            }
        }

        Ok(buf.finalize())
    }

    fn kwrite(
        &self,
        file: usize,
        buf: UserSliceRo,
        _flags: u32,
        _stored_flags: u32,
    ) -> Result<usize> {
        let handle = {
            let handles = self.handles.read();
            let handle = handles.get(&file).ok_or(Error::new(EBADF))?;
            handle.clone()
        };

        match handle {
            Handle::Scheme(inner) => inner.write(buf),
            Handle::File(_) => Err(Error::new(EBADF)),
            Handle::List { .. } => Err(Error::new(EISDIR)),
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
                ..Default::default()
            },
            Handle::File(_) => Stat {
                st_mode: MODE_FILE,
                ..Default::default()
            },
            Handle::List { .. } => Stat {
                st_mode: MODE_DIR,
                ..Default::default()
            },
        })?;

        Ok(())
    }
}
