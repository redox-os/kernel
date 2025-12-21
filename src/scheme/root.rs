use alloc::{boxed::Box, string::ToString, sync::Arc, vec::Vec};
use core::{
    str,
    sync::atomic::{AtomicUsize, Ordering},
};
use hashbrown::HashMap;
use syscall::{
    dirent::{DirEntry, DirentBuf, DirentKind},
    O_EXLOCK, O_FSYNC,
};

use crate::{
    context::{self, file::InternalFlags},
    scheme::{
        self,
        user::{UserInner, UserScheme},
        FileDescription, SchemeId, SchemeNamespace,
    },
    sync::{CleanLockToken, RwLock, L1},
    syscall::{
        data::Stat,
        error::*,
        flag::{CallFlags, EventFlags, MODE_DIR, MODE_FILE, O_CREAT},
        usercopy::{UserSliceRo, UserSliceRw, UserSliceWo},
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
    handles: RwLock<L1, HashMap<usize, Handle>>,
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
    fn kopen(
        &self,
        path: &str,
        flags: usize,
        ctx: CallerCtx,
        token: &mut CleanLockToken,
    ) -> Result<OpenResult> {
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
                let v2 = flags & O_FSYNC == O_FSYNC;
                let new_close = flags & O_EXLOCK == O_EXLOCK;

                if !v2 {
                    error!(
                        "Context {} tried to open a v1 scheme",
                        context::current().read(token.token()).name
                    );
                    return Err(Error::new(EINVAL));
                }
                if !new_close {
                    warn!(
                        "Context {} opened a non-async-close scheme",
                        context::current().read(token.token()).name
                    );
                }

                let path_box = path.to_string().into_boxed_str();
                let mut schemes = scheme::schemes_mut(token.token());

                let (_scheme_id, inner) =
                    schemes.insert_and_pass(self.scheme_ns, path, |scheme_id| {
                        let inner = Arc::new(UserInner::new(
                            self.scheme_id,
                            scheme_id,
                            new_close,
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

            self.handles
                .write(token.token())
                .insert(id, Handle::Scheme(inner));

            Ok(OpenResult::SchemeLocal(id, InternalFlags::empty()))
        } else if path.is_empty() {
            let ens = context::current().read(token.token()).ens;

            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            self.handles
                .write(token.token())
                .insert(id, Handle::List { ens });
            Ok(OpenResult::SchemeLocal(id, InternalFlags::POSITIONED))
        } else {
            let inner = Arc::new(path.as_bytes().to_vec().into_boxed_slice());

            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            self.handles
                .write(token.token())
                .insert(id, Handle::File(inner));
            Ok(OpenResult::SchemeLocal(id, InternalFlags::POSITIONED))
        }
    }

    fn unlinkat(
        &self,
        fd: usize,
        path: &str,
        _flags: usize,
        ctx: CallerCtx,
        token: &mut CleanLockToken,
    ) -> Result<()> {
        let path = path.trim_matches('/');

        let ens = {
            let handles = self.handles.read(token.token());
            let Handle::List { ens } = handles.get(&fd).ok_or(Error::new(ENOENT))? else {
                return Err(Error::new(EPERM));
            };
            *ens
        };

        if ctx.uid != 0 {
            return Err(Error::new(EACCES));
        }

        {
            let schemes = scheme::schemes(token.token());
            if schemes.get_name(ens, path).is_none() {
                return Err(Error::new(ENODEV));
            }
        }

        let inner = {
            let handles = self.handles.read(token.token());
            handles
                .iter()
                .find_map(|(_id, handle)| {
                    if let Handle::Scheme(inner) = handle
                        && path == inner.name.as_ref()
                    {
                        return Some(inner.clone());
                    }
                    None
                })
                .ok_or(Error::new(ENOENT))?
        };

        inner.unmount(token)
    }

    fn fsize(&self, file: usize, token: &mut CleanLockToken) -> Result<u64> {
        let handle = {
            let handles = self.handles.read(token.token());
            let handle = handles.get(&file).ok_or(Error::new(EBADF))?;
            handle.clone()
        };

        match handle {
            Handle::Scheme(_) => Err(Error::new(EBADF)),
            Handle::File(_) => Err(Error::new(EBADF)),
            Handle::List { .. } => Ok(0),
        }
    }

    fn fevent(
        &self,
        file: usize,
        flags: EventFlags,
        token: &mut CleanLockToken,
    ) -> Result<EventFlags> {
        let handle = {
            let handles = self.handles.read(token.token());
            let handle = handles.get(&file).ok_or(Error::new(EBADF))?;
            handle.clone()
        };

        match handle {
            Handle::Scheme(inner) => inner.fevent(flags),
            Handle::File(_) => Err(Error::new(EBADF)),
            Handle::List { .. } => Err(Error::new(EBADF)),
        }
    }

    fn kfpath(
        &self,
        file: usize,
        mut buf: UserSliceWo,
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        let handle = {
            let handles = self.handles.read(token.token());
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

    fn fsync(&self, file: usize, token: &mut CleanLockToken) -> Result<()> {
        let handle = {
            let handles = self.handles.read(token.token());
            let handle = handles.get(&file).ok_or(Error::new(EBADF))?;
            handle.clone()
        };

        match handle {
            Handle::Scheme(inner) => inner.fsync(),
            Handle::File(_) => Err(Error::new(EBADF)),
            Handle::List { .. } => Err(Error::new(EBADF)),
        }
    }

    fn close(&self, file: usize, token: &mut CleanLockToken) -> Result<()> {
        let handle = self
            .handles
            .write(token.token())
            .remove(&file)
            .ok_or(Error::new(EBADF))?;
        if let Handle::Scheme(inner) = handle {
            scheme::schemes_mut(token.token()).remove(inner.scheme_id);
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
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        let handle = {
            let handles = self.handles.read(token.token());
            let handle = handles.get(&file).ok_or(Error::new(EBADF))?;
            handle.clone()
        };

        match handle {
            Handle::Scheme(inner) => inner.read(buf, flags, token),
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
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        let Handle::List { ens } = *self
            .handles
            .read(token.token())
            .get(&id)
            .ok_or(Error::new(EBADF))?
        else {
            return Err(Error::new(ENOTDIR));
        };

        let mut buf = DirentBuf::new(buf, header_size).ok_or(Error::new(EIO))?;
        {
            let schemes = scheme::schemes(token.token());
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
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        let handle = {
            let handles = self.handles.read(token.token());
            let handle = handles.get(&file).ok_or(Error::new(EBADF))?;
            handle.clone()
        };

        match handle {
            Handle::Scheme(inner) => inner.write(buf, token),
            Handle::File(_) => Err(Error::new(EBADF)),
            Handle::List { .. } => Err(Error::new(EISDIR)),
        }
    }

    fn kfstat(&self, file: usize, buf: UserSliceWo, token: &mut CleanLockToken) -> Result<()> {
        let handle = {
            let handles = self.handles.read(token.token());
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

    fn kfdwrite(
        &self,
        id: usize,
        descs: Vec<Arc<spin::RwLock<FileDescription>>>,
        flags: CallFlags,
        arg: u64,
        metadata: &[u64],
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        let handle = {
            let handles = self.handles.read(token.token());
            let handle = handles.get(&id).ok_or(Error::new(EBADF))?;
            handle.clone()
        };

        match handle {
            Handle::Scheme(inner) => inner.call_fdwrite(descs, flags, arg, metadata),
            Handle::File(_) => Err(Error::new(EBADF)),
            Handle::List { .. } => Err(Error::new(EISDIR)),
        }
    }

    fn kfdread(
        &self,
        id: usize,
        payload: UserSliceRw,
        flags: CallFlags,
        metadata: &[u64],
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        let handle = {
            let handles = self.handles.read(token.token());
            let handle = handles.get(&id).ok_or(Error::new(EBADF))?;
            handle.clone()
        };

        match handle {
            Handle::Scheme(inner) => inner.call_fdread(payload, flags, metadata, token),
            Handle::File(_) => Err(Error::new(EBADF)),
            Handle::List { .. } => Err(Error::new(EISDIR)),
        }
    }
}
