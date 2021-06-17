use core::convert::TryInto;
use core::str;
use core::sync::atomic::{self, AtomicUsize};

use alloc::boxed::Box;
use alloc::collections::BTreeMap;

use spin::{Mutex, Once, RwLock};

use crate::acpi::{RXSDT_ENUM, RxsdtEnum};
use crate::event;
use crate::scheme::SchemeId;
use crate::sync::WaitCondition;

use crate::syscall::data::Stat;
use crate::syscall::error::{EACCES, EBADF, EBADFD, EINTR, EINVAL, EISDIR, ENOENT, ENOTDIR, EROFS};
use crate::syscall::flag::{
    EventFlags, EVENT_READ,
    MODE_CHR, MODE_DIR, MODE_FILE,
    O_ACCMODE, O_CREAT, O_DIRECTORY, O_EXCL, O_RDONLY, O_STAT, O_SYMLINK,
    SEEK_SET, SEEK_CUR, SEEK_END,
};
use crate::syscall::scheme::Scheme;
use crate::syscall::error::{Error, Result};

/// A scheme used to access the RSDT or XSDT, which is needed for e.g. `acpid` to function.
pub struct AcpiScheme;

struct Handle {
    offset: usize,
    kind: HandleKind,
    stat: bool,
}
#[derive(Eq, PartialEq)]
enum HandleKind {
    TopLevel,
    Rxsdt,
    ShutdownPipe,
}

static HANDLES: RwLock<BTreeMap<usize, Handle>> = RwLock::new(BTreeMap::new());
static NEXT_FD: AtomicUsize = AtomicUsize::new(0);

static DATA: Once<Box<[u8]>> = Once::new();

const TOPLEVEL_CONTENTS: &[u8] = b"rxsdt\nkstop\n";

static KSTOP_WAITCOND: WaitCondition = WaitCondition::new();
static KSTOP_FLAG: Mutex<bool> = Mutex::new(false);

static SCHEME_ID: Once<SchemeId> = Once::new();

pub fn register_kstop() -> bool {
    *KSTOP_FLAG.lock() = true;
    let mut waiters_awoken = KSTOP_WAITCOND.notify();

    if let Some(&acpi_scheme) = SCHEME_ID.get() {
        let handles = HANDLES.read();

        for (&fd, _) in handles.iter().filter(|(_, handle)| handle.kind == HandleKind::ShutdownPipe) {
            event::trigger(acpi_scheme, fd, EVENT_READ);
            waiters_awoken += 1;
        }
    } else {
        log::error!("Calling register_kstop before kernel ACPI scheme was initialized");
    }

    if waiters_awoken == 0 {
        log::error!("No userspace ACPI handler was notified when trying to shutdown. This is bad.");
        // Let the kernel shutdown without ACPI.
        return false;
    }

    // TODO: Context switch directly to the waiting context, to avoid annoying timeouts.
    true
}

impl AcpiScheme {
    pub fn new(id: SchemeId) -> Self {
        // NOTE: This __must__ be called from the main kernel context, while initializing all
        // schemes. If it is called by any other context, then all ACPI data will probably not even
        // be mapped.

        let mut data_init = false;
        let mut id_init = false;

        DATA.call_once(|| {
            data_init = true;

            let rsdt_or_xsdt = RXSDT_ENUM
                .get()
                .expect("expected RXSDT_ENUM to be initialized before AcpiScheme");

            let table = match rsdt_or_xsdt {
                RxsdtEnum::Rsdt(rsdt) => rsdt.as_slice(),
                RxsdtEnum::Xsdt(xsdt) => xsdt.as_slice(),
            };

            Box::from(table)
        });
        SCHEME_ID.call_once(|| {
            id_init = true;

            id
        });

        if !data_init || !id_init {
            log::error!("AcpiScheme::init called multiple times");
        }

        Self
    }
}

impl Scheme for AcpiScheme {
    fn open(&self, path: &str, flags: usize, opener_uid: u32, _opener_gid: u32) -> Result<usize> {
        let path = path.trim_start_matches('/');

        if opener_uid != 0 {
            return Err(Error::new(EACCES));
        }
        if flags & O_CREAT == O_CREAT {
            return Err(Error::new(EROFS));
        }
        if flags & O_EXCL == O_EXCL || flags & O_SYMLINK == O_SYMLINK {
            return Err(Error::new(EINVAL));
        }
        if flags & O_ACCMODE != O_RDONLY && flags & O_STAT != O_STAT {
            return Err(Error::new(EROFS));
        }
        let handle_kind = match path {
            "" => {
                if flags & O_DIRECTORY != O_DIRECTORY && flags & O_STAT != O_STAT {
                    return Err(Error::new(EISDIR));
                }

                HandleKind::TopLevel
            }
            "rxsdt" => {
                if flags & O_DIRECTORY == O_DIRECTORY && flags & O_STAT != O_STAT {
                    return Err(Error::new(ENOTDIR));
                }
                HandleKind::Rxsdt
            }
            "kstop" => {
                if flags & O_DIRECTORY == O_DIRECTORY && flags & O_STAT != O_STAT {
                    return Err(Error::new(ENOTDIR));
                }
                HandleKind::ShutdownPipe
            }
            _ => return Err(Error::new(ENOENT)),
        };

        let fd = NEXT_FD.fetch_add(1, atomic::Ordering::Relaxed);
        let mut handles_guard = HANDLES.write();

        let _ = handles_guard.insert(fd, Handle {
            offset: 0,
            kind: handle_kind,
            stat: flags & O_STAT == O_STAT,
        });

        Ok(fd)
    }
    fn fstat(&self, id: usize, stat: &mut Stat) -> Result<usize> {
        let handles = HANDLES.read();
        let handle = handles.get(&id).ok_or(Error::new(EBADF))?;

        match handle.kind {
            HandleKind::Rxsdt => {
                let data = DATA.get().ok_or(Error::new(EBADFD))?;

                stat.st_mode = MODE_FILE;
                stat.st_size = data.len().try_into().unwrap_or(u64::max_value());
            }
            HandleKind::TopLevel => {
                stat.st_mode = MODE_DIR;
                stat.st_size = TOPLEVEL_CONTENTS.len().try_into().unwrap_or(u64::max_value());
            }
            HandleKind::ShutdownPipe => {
                stat.st_mode = MODE_CHR;
                stat.st_size = 1;
            }
        }

        Ok(0)
    }
    fn seek(&self, id: usize, pos: isize, whence: usize) -> Result<isize> {
        let mut handles = HANDLES.write();
        let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;

        if handle.stat {
            return Err(Error::new(EBADF));
        }

        let file_len = match handle.kind {
            HandleKind::Rxsdt => DATA.get().ok_or(Error::new(EBADFD))?.len(),
            HandleKind::ShutdownPipe => 1,
            HandleKind::TopLevel => TOPLEVEL_CONTENTS.len(),
        };

        let new_offset = match whence {
            SEEK_SET => pos as usize,
            SEEK_CUR => if pos < 0 {
                handle.offset.checked_sub((-pos) as usize).ok_or(Error::new(EINVAL))?
            } else {
                handle.offset.saturating_add(pos as usize)
            }
            SEEK_END => if pos < 0 {
                file_len.checked_sub((-pos) as usize).ok_or(Error::new(EINVAL))?
            } else {
                file_len
            }
            _ => return Err(Error::new(EINVAL)),
        };

        handle.offset = new_offset;

        Ok(new_offset as isize)
    }
    fn read(&self, id: usize, dst_buf: &mut [u8]) -> Result<usize> {
        let mut handles = HANDLES.write();
        let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;

        if handle.stat {
            return Err(Error::new(EBADF));
        }

        let data = match handle.kind {
            HandleKind::ShutdownPipe => {
                let dst_byte = match dst_buf.first_mut() {
                    None => return Ok(0),
                    Some(dst) => if handle.offset >= 1 {
                        return Ok(0)
                    } else {
                        dst
                    },
                };

                loop {
                    let flag_guard = KSTOP_FLAG.lock();

                    if *flag_guard {
                        break;
                    } else if ! KSTOP_WAITCOND.wait(flag_guard, "waiting for kstop") {
                        return Err(Error::new(EINTR));
                    }
                }

                *dst_byte = 0x42;
                handle.offset = 1;
                return Ok(1);
            }
            HandleKind::Rxsdt => DATA.get().ok_or(Error::new(EBADFD))?,
            HandleKind::TopLevel => TOPLEVEL_CONTENTS,
        };

        let src_offset = core::cmp::min(handle.offset, data.len());
        let src_buf = data
            .get(src_offset..)
            .expect("expected data to be at least data.len() bytes long");

        let bytes_to_copy = core::cmp::min(dst_buf.len(), src_buf.len());

        dst_buf[..bytes_to_copy].copy_from_slice(&src_buf[..bytes_to_copy]);
        handle.offset += bytes_to_copy;

        Ok(bytes_to_copy)
    }
    // TODO
    fn fevent(&self, id: usize, _flags: EventFlags) -> Result<EventFlags> {
        let handles = HANDLES.read();
        let handle = handles.get(&id).ok_or(Error::new(EBADF))?;

        if handle.stat {
            return Err(Error::new(EBADF));
        }

        Ok(EventFlags::empty())
    }
    fn write(&self, _id: usize, _buf: &[u8]) -> Result<usize> {
        Err(Error::new(EBADF))
    }
    fn close(&self, id: usize) -> Result<usize> {
        if HANDLES.write().remove(&id).is_none() {
            return Err(Error::new(EBADF));
        }
        Ok(0)
    }
}
