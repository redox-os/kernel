use core::convert::TryFrom;
use core::str;
use core::sync::atomic::{AtomicUsize, Ordering};

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use spin::{Once, RwLock};

use redox_initfs::{InitFs, InodeStruct, Inode, InodeDir, InodeKind, types::Timespec};

use crate::syscall::data::Stat;
use crate::syscall::error::*;
use crate::syscall::flag::{MODE_DIR, MODE_FILE};
use crate::syscall::scheme::{calc_seek_offset_usize, Scheme};

struct Handle {
    inode: Inode,
    seek: usize,
    // TODO: Any better way to implement fpath? Or maybe work around it, e.g. by giving paths such
    // as `initfs:__inodes__/<inode>`?
    filename: String,
}

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
static HANDLES: RwLock<BTreeMap<usize, Handle>> = RwLock::new(BTreeMap::new());

static FS: Once<InitFs<'static>> = Once::new();

fn fs() -> Result<InitFs<'static>> {
    FS.get().copied().ok_or(Error::new(ENODEV))
}
fn get_inode(inode: Inode) -> Result<InodeStruct<'static>> {
    fs()?.get_inode(inode).ok_or_else(|| Error::new(EIO))
}

pub fn init(bytes: &'static [u8]) {
    let mut called = false;

    FS.call_once(|| {
        called = true;

        InitFs::new(bytes)
            .expect("failed to parse initfs header")
    });

    assert!(called, "called initfs::init more than once");
}

fn next_id() -> usize {
    let old = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    assert_ne!(old, usize::MAX, "usize overflow in initfs scheme");
    old
}

pub struct InitFsScheme;

struct Iter {
    dir: InodeDir<'static>,
    idx: u32,
}
impl Iterator for Iter {
    type Item = Result<redox_initfs::Entry<'static>>;

    fn next(&mut self) -> Option<Self::Item> {
        let entry = self.dir.get_entry(self.idx).map_err(|_| Error::new(EIO));
        self.idx += 1;
        entry.transpose()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        match self.dir.entry_count().ok() {
            Some(size) => {
                let size = usize::try_from(size).expect("expected u32 to be convertible into usize");
                (size, Some(size))
            }
            None => (0, None),
        }
    }
}

fn entries_iter(dir: InodeDir<'static>) -> impl IntoIterator<Item = Result<redox_initfs::Entry<'static>>> + 'static {
    let mut index = 0_u32;

    core::iter::from_fn(move || {
        let idx = index;
        index += 1;

        dir.get_entry(idx).map_err(|_| Error::new(EIO)).transpose()
    })
}
fn inode_len(inode: InodeStruct<'static>) -> Result<usize> {
    Ok(match inode.kind() {
        InodeKind::File(file) => file.data().map_err(|_| Error::new(EIO))?.len(),
        InodeKind::Dir(dir) => (Iter { dir, idx: 0 })
            .fold(0, |len, entry| len + entry.and_then(|entry| entry.name().map_err(|_| Error::new(EIO))).map_or(0, |name| name.len() + 1)),
        InodeKind::Unknown => return Err(Error::new(EIO)),
    })
}

impl Scheme for InitFsScheme {
    fn open(&self, path: &str, _flags: usize, _uid: u32, _gid: u32) -> Result<usize> {
        let mut components = path
            // trim leading and trailing slash
            .trim_matches('/')
            // divide into components
            .split('/')
            // filter out double slashes (e.g. /usr//bin/...)
            .filter(|c| !c.is_empty());

        let mut current_inode = InitFs::ROOT_INODE;

        while let Some(component) = components.next() {
            match component {
                "." => continue,
                ".." => {
                    let _ = components.next_back();
                    continue
                }

                _ => (),
            }

            let current_inode_struct = get_inode(current_inode)?;

            let dir = match current_inode_struct.kind() {
                InodeKind::Dir(dir) => dir,

                // If we still have more components in the path, and the file tree for that
                // particular branch is not all directories except the last, then that file cannot
                // exist.
                InodeKind::File(_) | InodeKind::Unknown => return Err(Error::new(ENOENT)),
            };

            let mut entries = Iter {
                dir,
                idx: 0,
            };

            current_inode = loop {
                let entry_res = match entries.next() {
                    Some(e) => e,
                    None => return Err(Error::new(ENOENT)),
                };
                let entry = entry_res?;
                let name = entry.name().map_err(|_| Error::new(EIO))?;
                if name == component.as_bytes() {
                    break entry.inode();
                }
            };
        }

        let id = next_id();
        let old = HANDLES.write().insert(id, Handle {
            inode: current_inode,
            seek: 0_usize,
            filename: path.into(),
        });
        assert!(old.is_none());

        Ok(id)
    }

    fn read(&self, id: usize, buffer: &mut [u8]) -> Result<usize> {
        let mut handles = HANDLES.write();
        let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;

        match get_inode(handle.inode)?.kind() {
            InodeKind::Dir(dir) => {
                let mut bytes_read = 0;
                let mut bytes_skipped = 0;

                for entry_res in (Iter { dir, idx: 0 }) {
                    let entry = entry_res?;
                    let name = entry.name().map_err(|_| Error::new(EIO))?;
                    let entry_len = name.len() + 1;

                    let to_skip = core::cmp::min(handle.seek - bytes_skipped, entry_len);
                    let max_to_read = core::cmp::min(entry_len - to_skip, buffer.len());

                    let to_copy = entry_len.saturating_sub(to_skip).saturating_sub(1);
                    buffer[bytes_read..bytes_read + to_copy].copy_from_slice(&name[..to_copy]);

                    if to_copy.saturating_sub(to_skip) == 1 {
                        buffer[bytes_read + to_copy] = b'\n';
                        bytes_read += 1;
                    }

                    bytes_read += to_copy;
                    bytes_skipped += to_skip;
                }

                handle.seek = handle.seek.checked_add(bytes_read).ok_or(Error::new(EOVERFLOW))?;

                Ok(bytes_read)
            }
            InodeKind::File(file) => {
                let data = file.data().map_err(|_| Error::new(EIO))?;
                let src_buf = &data[core::cmp::min(handle.seek, data.len())..];

                let to_copy = core::cmp::min(src_buf.len(), buffer.len());
                buffer[..to_copy].copy_from_slice(&src_buf[..to_copy]);

                handle.seek = handle.seek.checked_add(to_copy).ok_or(Error::new(EOVERFLOW))?;

                Ok(to_copy)
            }
            InodeKind::Unknown => return Err(Error::new(EIO)),
        }
    }

    fn seek(&self, id: usize, pos: isize, whence: usize) -> Result<isize> {
        let mut handles = HANDLES.write();
        let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;

        let new_offset = calc_seek_offset_usize(handle.seek, pos, whence, inode_len(get_inode(handle.inode)?)?)?;
        handle.seek = new_offset as usize;
        Ok(new_offset)
    }

    fn fcntl(&self, id: usize, _cmd: usize, _arg: usize) -> Result<usize> {
        let handles = HANDLES.read();
        let _handle = handles.get(&id).ok_or(Error::new(EBADF))?;

        Ok(0)
    }

    fn fpath(&self, id: usize, buf: &mut [u8]) -> Result<usize> {
        let handles = HANDLES.read();
        let handle = handles.get(&id).ok_or(Error::new(EBADF))?;

        // TODO: Copy scheme part in kernel
        let scheme_path = b"initfs:";
        let scheme_bytes = core::cmp::min(scheme_path.len(), buf.len());
        buf[..scheme_bytes].copy_from_slice(&scheme_path[..scheme_bytes]);

        let source = handle.filename.as_bytes();
        let path_bytes = core::cmp::min(buf.len() - scheme_bytes, source.len());
        buf[scheme_bytes..scheme_bytes + path_bytes].copy_from_slice(&source[..path_bytes]);

        Ok(scheme_bytes + path_bytes)
    }

    fn fstat(&self, id: usize, stat: &mut Stat) -> Result<usize> {
        let handles = HANDLES.read();
        let handle = handles.get(&id).ok_or(Error::new(EBADF))?;

        let Timespec { sec, nsec } = fs()?.image_creation_time();

        let inode = get_inode(handle.inode)?;

        stat.st_mode = inode.mode() | match inode.kind() { InodeKind::Dir(_) => MODE_DIR, InodeKind::File(_) => MODE_FILE, _ => 0 };
        stat.st_uid = inode.uid();
        stat.st_gid = inode.gid();
        stat.st_size = u64::try_from(inode_len(inode)?).unwrap_or(u64::MAX);

        stat.st_ctime = sec.get();
        stat.st_ctime_nsec = nsec.get();
        stat.st_mtime = sec.get();
        stat.st_mtime_nsec = nsec.get();

        Ok(0)
    }

    fn fsync(&self, id: usize) -> Result<usize> {
        let handles = HANDLES.read();
        let _handle = handles.get(&id).ok_or(Error::new(EBADF))?;
        Ok(0)
    }

    fn close(&self, id: usize) -> Result<usize> {
        let _ = HANDLES.write().remove(&id).ok_or(Error::new(EBADF))?;
        Ok(0)
    }
}
