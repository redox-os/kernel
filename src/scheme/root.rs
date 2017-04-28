use alloc::arc::Arc;
use alloc::boxed::Box;
use collections::BTreeMap;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::RwLock;

use context;
use syscall::error::*;
use syscall::scheme::Scheme;
use scheme::{self, SchemeNamespace, SchemeId};
use scheme::user::{UserInner, UserScheme};

pub struct RootScheme {
    scheme_ns: SchemeNamespace,
    scheme_id: SchemeId,
    next_id: AtomicUsize,
    handles: RwLock<BTreeMap<usize, Arc<UserInner>>>,
    ls_handles: RwLock<BTreeMap<usize, AtomicUsize>>,
}

impl RootScheme {
    pub fn new(scheme_ns: SchemeNamespace, scheme_id: SchemeId) -> RootScheme {
        RootScheme {
            scheme_ns: scheme_ns,
            scheme_id: scheme_id,
            next_id: AtomicUsize::new(0),
            handles: RwLock::new(BTreeMap::new()),
            ls_handles: RwLock::new(BTreeMap::new()),
        }
    }
}

impl Scheme for RootScheme {
    fn open(&self, path: &[u8], flags: usize, uid: u32, _gid: u32) -> Result<usize> {
        use syscall::flag::*;

        if uid == 0 {
            if flags & O_DIRECTORY == O_DIRECTORY {
                if flags & O_ACCMODE != O_RDONLY {
                    return Err(Error::new(EACCES));
                }
                let id = self.next_id.fetch_add(1, Ordering::SeqCst);
                self.ls_handles.write().insert(id, AtomicUsize::new(0));
                return Ok(id);
            }

            let context = {
                let contexts = context::contexts();
                let context = contexts.current().ok_or(Error::new(ESRCH))?;
                Arc::downgrade(&context)
            };

            let id = self.next_id.fetch_add(1, Ordering::SeqCst);

            let inner = {
                use scheme;
                let path_box = path.to_vec().into_boxed_slice();
                let mut schemes = scheme::schemes_mut();
                let inner = Arc::new(UserInner::new(self.scheme_id, id, path_box.clone(), flags, context));
                schemes.insert(self.scheme_ns, path_box, |scheme_id| {
                        inner.scheme_id.store(scheme_id, Ordering::SeqCst);
                        Arc::new(Box::new(UserScheme::new(Arc::downgrade(&inner))))
                    })?;
                inner
            };

            self.handles.write().insert(id, inner);

            Ok(id)
        } else {
            Err(Error::new(EACCES))
        }
    }

    fn dup(&self, file: usize, _buf: &[u8]) -> Result<usize> {
        let mut handles = self.handles.write();
        let inner = {
            let inner = handles.get(&file).ok_or(Error::new(EBADF))?;
            inner.clone()
        };

        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        handles.insert(id, inner);

        Ok(id)
    }

    fn read(&self, file: usize, buf: &mut [u8]) -> Result<usize> {
        let inner = {
            let handles = self.handles.read();
            handles.get(&file).map(Clone::clone)
        };

        if let Some(inner) = inner {
            inner.read(buf)
        } else {
            let scheme_ns = {
                let contexts = context::contexts();
                let context_lock = contexts.current().ok_or(Error::new(ESRCH))?;
                let context = context_lock.read();
                context.ens
            };

            let schemes = scheme::schemes();
            let mut schemes_iter = schemes.iter_name(scheme_ns);

            let num = {
                let handles = self.ls_handles.read();
                let inner = handles.get(&file).ok_or(Error::new(EBADF))?;
                inner.load(Ordering::SeqCst)
            };

            if let Some(scheme) = schemes_iter.nth(num) {
                let mut i = 0;
                while i < buf.len() && i < scheme.0.len() {
                    buf[i] = scheme.0[i];
                    i += 1;
                }

                {
                    let handles = self.ls_handles.read();
                    let inner = handles.get(&file).ok_or(Error::new(EBADF))?;
                    inner.fetch_add(1, Ordering::SeqCst)
                };

                Ok(i)
            } else {
                Ok(0)
            }
        }
    }

    fn write(&self, file: usize, buf: &[u8]) -> Result<usize> {
        let inner = {
            let handles = self.handles.read();
            let inner = handles.get(&file).ok_or(Error::new(EBADF))?;
            inner.clone()
        };

        inner.write(buf)
    }

    fn fevent(&self, file: usize, flags: usize) -> Result<usize> {
        let inner = {
            let handles = self.handles.read();
            let inner = handles.get(&file).ok_or(Error::new(EBADF))?;
            inner.clone()
        };

        inner.fevent(flags)
    }

    fn fpath(&self, file: usize, buf: &mut [u8]) -> Result<usize> {
        let inner = {
            let handles = self.handles.read();
            let inner = handles.get(&file).ok_or(Error::new(EBADF))?;
            inner.clone()
        };

        let mut i = 0;
        let scheme_path = b":";
        while i < buf.len() && i < scheme_path.len() {
            buf[i] = scheme_path[i];
            i += 1;
        }

        let mut j = 0;
        while i < buf.len() && j < inner.name.len() {
            buf[i] = inner.name[j];
            i += 1;
            j += 1;
        }

        Ok(i)
    }

    fn fsync(&self, file: usize) -> Result<usize> {
        let inner = {
            let handles = self.handles.read();
            let inner = handles.get(&file).ok_or(Error::new(EBADF))?;
            inner.clone()
        };

        inner.fsync()
    }

    fn close(&self, file: usize) -> Result<usize> {
        self.handles.write().remove(&file).ok_or(Error::new(EBADF)).and(Ok(0))
    }
}
