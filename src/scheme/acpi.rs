use core::{
    convert::TryInto,
    str,
    sync::atomic::{self, AtomicUsize},
};

use alloc::{boxed::Box, collections::BTreeMap};

use spin::{Mutex, Once, RwLock};

use crate::{
    acpi::{RxsdtEnum, RXSDT_ENUM},
    event,
    sync::WaitCondition,
};

use crate::syscall::{
    data::Stat,
    error::{Error, Result, EACCES, EBADF, EBADFD, EINTR, EINVAL, EISDIR, ENOENT, ENOTDIR, EROFS},
    flag::{
        EventFlags, EVENT_READ, MODE_CHR, MODE_DIR, MODE_FILE, O_ACCMODE, O_CREAT, O_DIRECTORY,
        O_EXCL, O_RDONLY, O_STAT, O_SYMLINK, SEEK_CUR, SEEK_END, SEEK_SET,
    },
    usercopy::{UserSliceRo, UserSliceWo},
};

use super::{CallerCtx, GlobalSchemes, KernelScheme, OpenResult};

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

// Using BTreeMap as hashbrown doesn't have a const constructor.
static HANDLES: RwLock<BTreeMap<usize, Handle>> = RwLock::new(BTreeMap::new());
static NEXT_FD: AtomicUsize = AtomicUsize::new(0);

static DATA: Once<Box<[u8]>> = Once::new();

const TOPLEVEL_CONTENTS: &[u8] = b"rxsdt\nkstop\n";

static KSTOP_WAITCOND: WaitCondition = WaitCondition::new();
static KSTOP_FLAG: Mutex<bool> = Mutex::new(false);

pub fn register_kstop() -> bool {
    *KSTOP_FLAG.lock() = true;
    let mut waiters_awoken = KSTOP_WAITCOND.notify();

    let handles = HANDLES.read();

    for (&fd, _) in handles
        .iter()
        .filter(|(_, handle)| handle.kind == HandleKind::ShutdownPipe)
    {
        event::trigger(GlobalSchemes::Acpi.scheme_id(), fd, EVENT_READ);
        waiters_awoken += 1;
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
    pub fn init() {
        // NOTE: This __must__ be called from the main kernel context, while initializing all
        // schemes. If it is called by any other context, then all ACPI data will probably not even
        // be mapped.

        let mut data_init = false;

        DATA.call_once(|| {
            data_init = true;

            let table = match RXSDT_ENUM.get() {
                Some(RxsdtEnum::Rsdt(rsdt)) => rsdt.as_slice(),
                Some(RxsdtEnum::Xsdt(xsdt)) => xsdt.as_slice(),
                None => {
                    log::warn!("expected RXSDT_ENUM to be initialized before AcpiScheme, is ACPI available?");
                    &[]
                }
            };

            Box::from(table)
        });

        if !data_init {
            log::error!("AcpiScheme::init called multiple times");
        }
    }
}

impl KernelScheme for AcpiScheme {
    fn kopen(&self, path: &str, flags: usize, ctx: CallerCtx) -> Result<OpenResult> {
        let path = path.trim_start_matches('/');

        if ctx.uid != 0 {
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

        let _ = handles_guard.insert(
            fd,
            Handle {
                offset: 0,
                kind: handle_kind,
                stat: flags & O_STAT == O_STAT,
            },
        );

        Ok(OpenResult::SchemeLocal(fd))
    }
    fn seek(&self, id: usize, pos: isize, whence: usize) -> Result<usize> {
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

        Ok(new_offset)
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
            HandleKind::ShutdownPipe => {
                if dst_buf.is_empty() {
                    return Ok(0);
                }

                loop {
                    let flag_guard = KSTOP_FLAG.lock();

                    if *flag_guard {
                        break;
                    } else if !KSTOP_WAITCOND.wait(flag_guard, "waiting for kstop") {
                        return Err(Error::new(EINTR));
                    }
                }

                dst_buf.copy_exactly(&[0x42])?;
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

        let bytes_copied = dst_buf.copy_common_bytes_from_slice(src_buf)?;
        handle.offset += bytes_copied;

        Ok(bytes_copied)
    }
    fn kfstat(&self, id: usize, buf: UserSliceWo) -> Result<()> {
        let handles = HANDLES.read();
        let handle = handles.get(&id).ok_or(Error::new(EBADF))?;

        buf.copy_exactly(&match handle.kind {
            HandleKind::Rxsdt => {
                let data = DATA.get().ok_or(Error::new(EBADFD))?;

                Stat {
                    st_mode: MODE_FILE,
                    st_size: data.len().try_into().unwrap_or(u64::max_value()),
                    ..Default::default()
                }
            }
            HandleKind::TopLevel => Stat {
                st_mode: MODE_DIR,
                st_size: TOPLEVEL_CONTENTS
                    .len()
                    .try_into()
                    .unwrap_or(u64::max_value()),
                ..Default::default()
            },
            HandleKind::ShutdownPipe => Stat {
                st_mode: MODE_CHR,
                st_size: 1,
                ..Default::default()
            },
        })?;

        Ok(())
    }
}
