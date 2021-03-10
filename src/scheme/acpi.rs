use core::convert::TryInto;
use core::fmt::Write;
use core::str;
use core::sync::atomic::{self, AtomicUsize};

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use syscall::data::Stat;
use syscall::error::{EACCES, EBADF, EBADFD, EINVAL, EIO, EISDIR, ENOENT, ENOTDIR};
use syscall::flag::{O_ACCMODE, O_DIRECTORY, O_RDWR, O_STAT, O_WRONLY, SEEK_SET, SEEK_CUR, SEEK_END};
use syscall::scheme::{calc_seek_offset_usize, Scheme};
use syscall::{Error, Result};
use syscall::{MODE_DIR, MODE_FILE};

use spin::{Once, RwLock};

use crate::acpi::{RXSDT_ENUM, RxsdtEnum};

#[derive(Clone, Copy)]
struct PhysSlice {
    phys_ptr: usize,
    len: usize,
    /// These appear to be identity mapped, so this is technically not needed.
    virt: usize,
}

/// A scheme used to access the RSDT or XSDT, which is needed for e.g. `acpid` to function.
pub struct AcpiScheme;

struct Handle {
    offset: usize,
}

static HANDLES: RwLock<BTreeMap<usize, Handle>> = RwLock::new(BTreeMap::new());
static NEXT_FD: AtomicUsize = AtomicUsize::new(0);

static DATA: Once<Box<[u8]>> = Once::new();

impl AcpiScheme {
    pub fn new() -> Self {
        // NOTE: This __must__ be called from the main kernel context, while initializing all
        // schemes. If it is called by any other context, then all ACPI data will probably not even
        // be mapped.

        let mut initialized = false;

        DATA.call_once(|| {
            let rsdt_or_xsdt = RXSDT_ENUM
                .r#try()
                .expect("expected RXSDT_ENUM to be initialized before AcpiScheme");

            let table = match rsdt_or_xsdt {
                RxsdtEnum::Rsdt(rsdt) => rsdt.as_slice(),
                RxsdtEnum::Xsdt(xsdt) => xsdt.as_slice(),
            };

            Box::from(table)
        });

        if !initialized {
            log::error!("AcpiScheme::init called multiple times");
        }

        Self
    }
}

impl Scheme for AcpiScheme {
    fn open(&self, _path: &str, flags: usize, opener_uid: u32, _opener_gid: u32) -> Result<usize> {
        if opener_uid != 0 {
            return Err(Error::new(EACCES));
        }
        if flags & O_DIRECTORY == O_DIRECTORY && flags & O_STAT != O_STAT {
            return Err(Error::new(ENOTDIR));
        }

        let fd = NEXT_FD.fetch_add(1, atomic::Ordering::Relaxed);

        let mut handles_guard = HANDLES.write();
        let handle = Handle { offset: 0 };

        let _ = handles_guard.insert(fd, handle);

        Ok(fd)
    }
    fn fstat(&self, id: usize, stat: &mut Stat) -> Result<usize> {
        if ! HANDLES.read().contains_key(&id) {
            return Err(Error::new(EBADF));
        }

        let data = DATA.r#try().ok_or(Error::new(EBADFD))?;

        stat.st_mode = MODE_FILE;
        stat.st_size = data.len().try_into().unwrap_or(u64::max_value());

        Ok(0)
    }
    fn seek(&self, id: usize, pos: isize, whence: usize) -> Result<isize> {
        let mut handles = HANDLES.write();
        let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;

        let data = DATA.r#try().ok_or(Error::new(EBADFD))?;

        let new_offset = match whence {
            SEEK_SET => pos as usize,
            SEEK_CUR => if pos < 0 {
                handle.offset.checked_sub((-pos) as usize).ok_or(Error::new(EINVAL))?
            } else {
                handle.offset.saturating_add(pos as usize)
            }
            SEEK_END => if pos < 0 {
                data.len().checked_sub((-pos) as usize).ok_or(Error::new(EINVAL))?
            } else {
                data.len()
            }
            _ => return Err(Error::new(EINVAL)),
        };

        handle.offset = new_offset;

        Ok(new_offset as isize)
    }
    fn read(&self, id: usize, dst_buf: &mut [u8]) -> Result<usize> {
        let mut handles = HANDLES.write();
        let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;

        let data = DATA.r#try().ok_or(Error::new(EBADFD))?;

        let src_offset = core::cmp::min(handle.offset, data.len());
        let src_buf = data
            .get(src_offset..)
            .expect("expected data to be at least data.len() bytes long");

        let bytes_to_copy = core::cmp::min(dst_buf.len(), src_buf.len());

        dst_buf[..bytes_to_copy].copy_from_slice(&src_buf[..bytes_to_copy]);

        Ok(bytes_to_copy)
    }
    fn write(&self, _id: usize, _buf: &[u8]) -> Result<usize> {
        Err(Error::new(EBADF))
    }
    fn close(&self, id: usize) -> Result<usize> {
        if ! HANDLES.read().contains_key(&id) {
            return Err(Error::new(EBADF));
        }
        Ok(0)
    }
}
