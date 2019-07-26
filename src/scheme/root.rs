use alloc::sync::Arc;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::{cmp, str};
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::{Mutex, RwLock};

use crate::context;
use crate::syscall::data::Stat;
use crate::syscall::error::*;
use crate::syscall::flag::{EventFlags, O_CREAT, MODE_FILE, MODE_DIR, SEEK_SET, SEEK_CUR, SEEK_END};
use crate::syscall::scheme::Scheme;
use crate::scheme::{self, SchemeNamespace, SchemeId};
use crate::scheme::user::{UserInner, UserScheme};

struct FolderInner {
    data: Box<[u8]>,
    pos: Mutex<usize>
}

impl FolderInner {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let mut i = 0;
        let mut pos = self.pos.lock();

        while i < buf.len() && *pos < self.data.len() {
            buf[i] = self.data[*pos];
            i += 1;
            *pos += 1;
        }

        Ok(i)
    }

    fn seek(&self, pos: usize, whence: usize) -> Result<usize> {
        let mut seek = self.pos.lock();
        *seek = match whence {
            SEEK_SET => cmp::min(self.data.len(), pos),
            SEEK_CUR => cmp::max(0, cmp::min(self.data.len() as isize, *seek as isize + pos as isize)) as usize,
            SEEK_END => cmp::max(0, cmp::min(self.data.len() as isize, self.data.len() as isize + pos as isize)) as usize,
            _ => return Err(Error::new(EINVAL))
        };

        Ok(*seek)
    }
}

#[derive(Clone)]
enum Handle {
    Scheme(Arc<UserInner>),
    File(Arc<Box<[u8]>>),
    Folder(Arc<FolderInner>)
}

pub struct RootScheme {
    scheme_ns: SchemeNamespace,
    scheme_id: SchemeId,
    next_id: AtomicUsize,
    handles: RwLock<BTreeMap<usize, Handle>>,
}

impl RootScheme {
    pub fn new(scheme_ns: SchemeNamespace, scheme_id: SchemeId) -> RootScheme {
        RootScheme {
            scheme_ns: scheme_ns,
            scheme_id: scheme_id,
            next_id: AtomicUsize::new(0),
            handles: RwLock::new(BTreeMap::new()),
        }
    }
}

impl Scheme for RootScheme {
    fn open(&self, path: &[u8], flags: usize, uid: u32, _gid: u32) -> Result<usize> {
        let path_utf8 = str::from_utf8(path).or(Err(Error::new(ENOENT)))?;
        let path_trimmed = path_utf8.trim_matches('/');

        //TODO: Make this follow standards for flags and errors
        if flags & O_CREAT == O_CREAT {
            if uid == 0 {
                let context = {
                    let contexts = context::contexts();
                    let context = contexts.current().ok_or(Error::new(ESRCH))?;
                    Arc::downgrade(&context)
                };

                let id = self.next_id.fetch_add(1, Ordering::SeqCst);

                let inner = {
                    let path_box = path_trimmed.as_bytes().to_vec().into_boxed_slice();
                    let mut schemes = scheme::schemes_mut();
                    let inner = Arc::new(UserInner::new(self.scheme_id, id, path_box.clone(), flags, context));
                    schemes.insert(self.scheme_ns, path_box, |scheme_id| {
                        inner.scheme_id.store(scheme_id, Ordering::SeqCst);
                        Arc::new(Box::new(UserScheme::new(Arc::downgrade(&inner))))
                    })?;
                    inner
                };

                self.handles.write().insert(id, Handle::Scheme(inner));

                Ok(id)
            } else {
                Err(Error::new(EACCES))
            }
        } else if path_trimmed.is_empty() {
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
                    data.extend_from_slice(name);
                    data.push(b'\n');
                }
            }

            let inner = Arc::new(FolderInner {
                data: data.into_boxed_slice(),
                pos: Mutex::new(0)
            });

            let id = self.next_id.fetch_add(1, Ordering::SeqCst);
            self.handles.write().insert(id, Handle::Folder(inner));
            Ok(id)
        } else {
            let inner = Arc::new(
                path_trimmed.as_bytes().to_vec().into_boxed_slice()
            );

            let id = self.next_id.fetch_add(1, Ordering::SeqCst);
            self.handles.write().insert(id, Handle::File(inner));
            Ok(id)
        }
    }

    fn unlink(&self, path: &[u8], uid: u32, _gid: u32) -> Result<usize> {
        let path_utf8 = str::from_utf8(path).or(Err(Error::new(ENOENT)))?;
        let path_trimmed = path_utf8.trim_matches('/');

        if uid == 0 {
            let inner = {
                let handles = self.handles.read();
                handles.iter().find_map(|(_id, handle)| {
                    match handle {
                        Handle::Scheme(inner) => {
                            if path_trimmed.as_bytes() == inner.name.as_ref() {
                                return Some(inner.clone());
                            }
                        },
                        _ => (),
                    }
                    None
                }).ok_or(Error::new(ENOENT))?
            };

            inner.unmount()
        } else {
            Err(Error::new(EACCES))
        }
    }

    fn read(&self, file: usize, buf: &mut [u8]) -> Result<usize> {
        let handle = {
            let handles = self.handles.read();
            let handle = handles.get(&file).ok_or(Error::new(EBADF))?;
            handle.clone()
        };

        match handle {
            Handle::Scheme(inner) => {
                inner.read(buf)
            },
            Handle::File(_) => {
                Err(Error::new(EBADF))
            },
            Handle::Folder(inner) => {
                inner.read(buf)
            }
        }
    }

    fn write(&self, file: usize, buf: &[u8]) -> Result<usize> {
        let handle = {
            let handles = self.handles.read();
            let handle = handles.get(&file).ok_or(Error::new(EBADF))?;
            handle.clone()
        };

        match handle {
            Handle::Scheme(inner) => {
                inner.write(buf)
            },
            Handle::File(_) => {
                Err(Error::new(EBADF))
            },
            Handle::Folder(_) => {
                Err(Error::new(EBADF))
            }
        }
    }

    fn seek(&self, file: usize, pos: usize, whence: usize) -> Result<usize> {
        let handle = {
            let handles = self.handles.read();
            let handle = handles.get(&file).ok_or(Error::new(EBADF))?;
            handle.clone()
        };

        match handle {
            Handle::Scheme(_) => {
                Err(Error::new(EBADF))
            },
            Handle::File(_) => {
                Err(Error::new(EBADF))
            },
            Handle::Folder(inner) => {
                inner.seek(pos, whence)
            }
        }
    }

    fn fevent(&self, file: usize, flags: EventFlags) -> Result<EventFlags> {
        let handle = {
            let handles = self.handles.read();
            let handle = handles.get(&file).ok_or(Error::new(EBADF))?;
            handle.clone()
        };

        match handle {
            Handle::Scheme(inner) => {
                inner.fevent(flags)
            },
            Handle::File(_) => {
                Err(Error::new(EBADF))
            },
            Handle::Folder(_) => {
                Err(Error::new(EBADF))
            }
        }
    }

    fn fpath(&self, file: usize, buf: &mut [u8]) -> Result<usize> {
        let handle = {
            let handles = self.handles.read();
            let handle = handles.get(&file).ok_or(Error::new(EBADF))?;
            handle.clone()
        };

        let mut i = 0;
        let scheme_path = b":";
        while i < buf.len() && i < scheme_path.len() {
            buf[i] = scheme_path[i];
            i += 1;
        }

        match handle {
            Handle::Scheme(inner) => {
                let mut j = 0;
                while i < buf.len() && j < inner.name.len() {
                    buf[i] = inner.name[j];
                    i += 1;
                    j += 1;
                }
            },
            Handle::File(inner) => {
                let mut j = 0;
                while i < buf.len() && j < inner.len() {
                    buf[i] = inner[j];
                    i += 1;
                    j += 1;
                }
            },
            Handle::Folder(_) => ()
        }

        Ok(i)
    }

    fn fstat(&self, file: usize, stat: &mut Stat) -> Result<usize> {
        let handle = {
            let handles = self.handles.read();
            let handle = handles.get(&file).ok_or(Error::new(EBADF))?;
            handle.clone()
        };

        match handle {
            Handle::Scheme(_) => {
                stat.st_mode = MODE_FILE;
                stat.st_uid = 0;
                stat.st_gid = 0;
                stat.st_size = 0;
            },
            Handle::File(_) => {
                stat.st_mode = MODE_FILE;
                stat.st_uid = 0;
                stat.st_gid = 0;
                stat.st_size = 0;
            },
            Handle::Folder(inner) => {
                stat.st_mode = MODE_DIR;
                stat.st_uid = 0;
                stat.st_gid = 0;
                stat.st_size = inner.data.len() as u64;
            }
        }

        Ok(0)
    }

    fn fsync(&self, file: usize) -> Result<usize> {
        let handle = {
            let handles = self.handles.read();
            let handle = handles.get(&file).ok_or(Error::new(EBADF))?;
            handle.clone()
        };

        match handle {
            Handle::Scheme(inner) => {
                inner.fsync()
            },
            Handle::File(_) => {
                Err(Error::new(EBADF))
            },
            Handle::Folder(_) => {
                Err(Error::new(EBADF))
            }
        }
    }

    fn close(&self, file: usize) -> Result<usize> {
        let handle = self.handles.write().remove(&file).ok_or(Error::new(EBADF))?;
        match handle {
            Handle::Scheme(inner) => {
                let scheme_id = inner.scheme_id.load(Ordering::SeqCst);
                let mut schemes = scheme::schemes_mut();
                schemes.remove(scheme_id);
            },
            _ => ()
        }
        Ok(0)
    }
}
