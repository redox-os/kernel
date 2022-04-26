/// Disk scheme replacement when making live disk

use alloc::sync::Arc;
use alloc::collections::BTreeMap;
use core::{slice, str};
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::RwLock;

use syscall::data::Stat;
use syscall::error::*;
use syscall::flag::{MODE_DIR, MODE_FILE};
use syscall::scheme::{calc_seek_offset_usize, Scheme};

use crate::memory::Frame;
use crate::paging::{ActivePageTable, Page, PageFlags, PhysicalAddress, TableKind, VirtualAddress};
use crate::paging::mapper::PageFlushAll;

static mut LIST: [u8; 2] = [b'0', b'\n'];

struct Handle {
    path: &'static [u8],
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

        for line in str::from_utf8(unsafe { crate::INIT_ENV }).unwrap_or("").lines() {
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
                let mut active_table = ActivePageTable::new(TableKind::Kernel);
                let flush_all = PageFlushAll::new();
                let start_page = Page::containing_address(VirtualAddress::new(virt));
                let end_page = Page::containing_address(VirtualAddress::new(virt + size - 1));
                for page in Page::range_inclusive(start_page, end_page) {
                    if active_table.translate_page(page).is_none() {
                        let frame = Frame::containing_address(PhysicalAddress::new(page.start_address().data() - crate::PHYS_OFFSET));
                        let flags = PageFlags::new().write(true);
                        let result = active_table.map_to(page, frame, flags);
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
    fn open(&self, path: &str, _flags: usize, _uid: u32, _gid: u32) -> Result<usize> {
        let path_trimmed = path.trim_matches('/');
        match path_trimmed {
            "" => {
                let id = self.next_id.fetch_add(1, Ordering::SeqCst);
                self.handles.write().insert(id, Handle {
                    path: b"",
                    data: self.list.clone(),
                    mode: MODE_DIR | 0o755,
                    seek: 0
                });
                Ok(id)
            },
            "0" => {
                let id = self.next_id.fetch_add(1, Ordering::SeqCst);
                self.handles.write().insert(id, Handle {
                    path: b"0",
                    data: self.data.clone(),
                    mode: MODE_FILE | 0o644,
                    seek: 0
                });
                Ok(id)
            }
            _ => Err(Error::new(ENOENT))
        }
    }

    fn read(&self, id: usize, buffer: &mut [u8]) -> Result<usize> {
        let mut handles = self.handles.write();
        let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;
        let data = handle.data.read();

        let mut i = 0;
        while i < buffer.len() && handle.seek < data.len() {
            buffer[i] = data[handle.seek];
            i += 1;
            handle.seek += 1;
        }

        Ok(i)
    }

    fn write(&self, id: usize, buffer: &[u8]) -> Result<usize> {
        let mut handles = self.handles.write();
        let handle = handles.get_mut(&id).ok_or(Error::new(EBADF))?;
        let mut data = handle.data.write();

        let mut i = 0;
        while i < buffer.len() && handle.seek < data.len() {
            data[handle.seek] = buffer[i];
            i += 1;
            handle.seek += 1;
        }

        Ok(i)
    }

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

    fn fpath(&self, id: usize, buf: &mut [u8]) -> Result<usize> {
        let handles = self.handles.read();
        let handle = handles.get(&id).ok_or(Error::new(EBADF))?;

        //TODO: Copy scheme part in kernel
        let mut i = 0;
        let scheme_path = b"disk/live:";
        while i < buf.len() && i < scheme_path.len() {
            buf[i] = scheme_path[i];
            i += 1;
        }

        let mut j = 0;
        while i < buf.len() && j < handle.path.len() {
            buf[i] = handle.path[j];
            i += 1;
            j += 1;
        }

        Ok(i)
    }

    fn fstat(&self, id: usize, stat: &mut Stat) -> Result<usize> {
        let handles = self.handles.read();
        let handle = handles.get(&id).ok_or(Error::new(EBADF))?;
        let data = handle.data.read();

        stat.st_mode = handle.mode;
        stat.st_uid = 0;
        stat.st_gid = 0;
        stat.st_size = data.len() as u64;

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
