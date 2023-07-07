/// Disk scheme replacement when making live disk

use alloc::sync::Arc;
use alloc::collections::BTreeMap;
use core::{slice, str};
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::RwLock;
use rmm::Flusher;

use syscall::data::Stat;
use syscall::{error::*, CallerCtx};
use syscall::flag::{MODE_DIR, MODE_FILE};
use syscall::scheme::{calc_seek_offset_usize, Scheme};

use crate::memory::Frame;
use crate::paging::{KernelMapper, Page, PageFlags, PhysicalAddress, VirtualAddress};
use crate::paging::mapper::PageFlushAll;
use crate::syscall::usercopy::{UserSliceWo, UserSliceRo};

use super::OpenResult;

static mut LIST: [u8; 2] = [b'0', b'\n'];

struct Handle {
    path: &'static str,
    data: Arc<RwLock<&'static mut [u8]>>,
    mode: u16,
    seek: usize
}

pub struct DiskScheme {
    next_id: AtomicUsize,
    list: Arc<RwLock<&'static mut [u8]>>,
    data: Arc<RwLock<&'static mut [u8]>>,
    handles: RwLock<BTreeMap<usize, Handle>>
}

impl DiskScheme {
    pub fn new() -> Option<DiskScheme> {
        let mut phys = 0;
        let mut size = 0;

        for line in str::from_utf8(crate::init_env()).unwrap_or("").lines() {
            let mut parts = line.splitn(2, '=');
            let name = parts.next().unwrap_or("");
            let value = parts.next().unwrap_or("");

            if name == "DISK_LIVE_ADDR" {
                phys = usize::from_str_radix(value, 16).unwrap_or(0);
            }

            if name == "DISK_LIVE_SIZE" {
                size = usize::from_str_radix(value, 16).unwrap_or(0);
            }
        }

        if phys > 0 && size > 0 {
            // Ensure live disk pages are mapped
            let virt = phys + crate::PHYS_OFFSET;
            unsafe {
                let mut mapper = KernelMapper::lock();

                let mut flush_all = PageFlushAll::new();
                let start_page = Page::containing_address(VirtualAddress::new(virt));
                let end_page = Page::containing_address(VirtualAddress::new(virt + size - 1));
                for page in Page::range_inclusive(start_page, end_page) {
                    if mapper.translate(page.start_address()).is_none() {
                        let frame = Frame::containing_address(PhysicalAddress::new(page.start_address().data() - crate::PHYS_OFFSET));
                        let flags = PageFlags::new().write(true);
                        let result = mapper.get_mut().expect("expected KernelMapper not to be in use while initializing live scheme").map_phys(page.start_address(), frame.start_address(), flags).expect("failed to map live page");
                        flush_all.consume(result);
                    }
                }
                flush_all.flush();
            }
            Some(DiskScheme {
                next_id: AtomicUsize::new(0),
                list: Arc::new(RwLock::new(unsafe { &mut LIST })),
                data: Arc::new(RwLock::new(unsafe {
                    slice::from_raw_parts_mut(virt as *mut u8, size)
                })),
                handles: RwLock::new(BTreeMap::new())
            })
        } else {
            None
        }
    }
}

impl Scheme for DiskScheme {
    fn seek(&self, id: usize, pos: isize, whence: usize) -> Result<isize> {
        let mut handles = self.handles.write();
        let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;
        let data = handle.data.read();
        let new_offset = calc_seek_offset_usize(handle.seek, pos, whence, data.len())?;
        handle.seek = new_offset as usize;
        Ok(new_offset)
    }

    fn fcntl(&self, id: usize, _cmd: usize, _arg: usize) -> Result<usize> {
        let handles = self.handles.read();
        let _handle = handles.get(&id).ok_or(Error::new(EBADF))?;

        Ok(0)
    }

    fn fsync(&self, id: usize) -> Result<usize> {
        let handles = self.handles.read();
        let _handle = handles.get(&id).ok_or(Error::new(EBADF))?;

        Ok(0)
    }

    fn close(&self, id: usize) -> Result<usize> {
        self.handles.write().remove(&id).ok_or(Error::new(EBADF)).and(Ok(0))
    }
}
impl crate::scheme::KernelScheme for DiskScheme {
    fn kopen(&self, path: &str, _flags: usize, _caller: CallerCtx) -> Result<OpenResult> {
        let path_trimmed = path.trim_matches('/');
        match path_trimmed {
            "" => {
                let id = self.next_id.fetch_add(1, Ordering::SeqCst);
                self.handles.write().insert(id, Handle {
                    path: "",
                    data: self.list.clone(),
                    mode: MODE_DIR | 0o755,
                    seek: 0
                });
                Ok(OpenResult::SchemeLocal(id))
            },
            "0" => {
                let id = self.next_id.fetch_add(1, Ordering::SeqCst);
                self.handles.write().insert(id, Handle {
                    path: "0",
                    data: self.data.clone(),
                    mode: MODE_FILE | 0o644,
                    seek: 0
                });
                Ok(OpenResult::SchemeLocal(id))
            }
            _ => Err(Error::new(ENOENT))
        }
    }
    fn kread(&self, id: usize, buffer: UserSliceWo) -> Result<usize> {
        let mut handles = self.handles.write();
        let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;
        let data = handle.data.read();

        let src = data.get(handle.seek..).unwrap_or(&[]);
        let bytes_read = buffer.copy_common_bytes_from_slice(src)?;
        handle.seek += bytes_read;

        Ok(bytes_read)
    }

    fn kwrite(&self, id: usize, buffer: UserSliceRo) -> Result<usize> {
        let mut handles = self.handles.write();
        let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;
        let mut data = handle.data.write();

        let dst = data.get_mut(handle.seek..).unwrap_or(&mut []);
        let bytes_written = buffer.copy_common_bytes_to_slice(dst)?;
        handle.seek += bytes_written;

        Ok(bytes_written)
    }
    fn kfpath(&self, id: usize, buf: UserSliceWo) -> Result<usize> {
        let handles = self.handles.read();
        let handle = handles.get(&id).ok_or(Error::new(EBADF))?;

        let src = format!("disk/live:{}", handle.path);
        let byte_count = buf.copy_common_bytes_from_slice(src.as_bytes())?;

        Ok(byte_count)
    }
    fn kfstat(&self, id: usize, stat_buf: UserSliceWo) -> Result<usize> {
        let stat = {
            let handles = self.handles.read();
            let handle = handles.get(&id).ok_or(Error::new(EBADF))?;
            let data = handle.data.read();

            Stat {
                st_mode: handle.mode,
                st_uid: 0,
                st_gid: 0,
                st_size: data.len() as u64,
                ..Stat::default()
            }
        };
        stat_buf.copy_exactly(&stat)?;

        Ok(0)
    }

}
