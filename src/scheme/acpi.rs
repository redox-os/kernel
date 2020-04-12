use core::convert::{TryFrom, TryInto};
use core::fmt::Write;
use core::str;
use core::sync::atomic::{self, AtomicUsize};

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use syscall::data::Stat;
use syscall::error::{EACCES, EBADF, EBADFD, EINVAL, EIO, EISDIR, ENOENT, ENOTDIR};
use syscall::flag::{O_ACCMODE, O_DIRECTORY, O_RDWR, O_STAT, O_WRONLY};
use syscall::scheme::Scheme;
use syscall::{Error, Result};
use syscall::{MODE_DIR, MODE_FILE, SEEK_CUR, SEEK_END, SEEK_SET};

use spin::{Mutex, RwLock};

use crate::acpi::sdt::Sdt;
use crate::acpi::SdtSignature;
use crate::paging::ActivePageTable;

#[derive(Clone, Copy)]
struct PhysSlice {
    phys_ptr: usize,
    len: usize,
    /// These appear to be identity mapped, so this is technically not needed.
    virt: usize,
}

/// A scheme used to access ACPI tables needed for some drivers to function (e.g. pcid with the
/// PCIe "MCFG" table).
///
/// # Layout
/// * `/tables`
///   * _can be listed to retrieve the available tables_
///   * e.g. MCFG-<OEM ID in hex>-<OEM TABLE ID in hex>
///   * _maybe_ the MADT, in case some userspace driver takes care of the I/O APIC.
/// * _perhaps_ some interface for e.g. power management.
pub struct AcpiScheme {
    handles: RwLock<BTreeMap<usize, Mutex<Handle>>>,
    tables: Vec<(SdtSignature, PhysSlice)>,
    next_fd: AtomicUsize,
}

const TOPLEVEL_DIR_CONTENTS: &[u8] = b"tables\n";
const ALLOWED_TABLES: &[[u8; 4]] = &[*b"MCFG"];

// XXX: Why can't core also have something like std::io::Take? It's not even real I/O!
/// An internal wrapper struct that limits the number of bytes that can be fmt-written, in order to
/// properly return the length when reading directories etc. The bytes that cannot be written will
/// be discarded.
struct Take<'a> {
    buf: &'a mut [u8],
    offset: usize,
}

impl Take<'_> {
    pub fn write_to_buf<'a>(buf: &'a mut [u8]) -> Take<'a> {
        Take { offset: 0, buf }
    }
    pub fn bytes_currently_written(&self) -> usize {
        self.offset
    }
}

impl<'a> core::fmt::Write for Take<'a> {
    fn write_str(&mut self, string: &str) -> core::fmt::Result {
        if self.offset > self.buf.len() {
            return Ok(());
        }

        let string_bytes = string.as_bytes();
        let max = core::cmp::min(string_bytes.len() + self.offset, self.buf.len()) - self.offset;
        self.buf[self.offset..self.offset + max].copy_from_slice(&string_bytes[..max]);
        self.offset += max;
        Ok(())
    }
}

enum Handle {
    TopLevel(usize), // seek offset
    Tables(usize),   // seek offset

    Table {
        name: [u8; 4],
        oem_id: [u8; 6],
        oem_table_id: [u8; 8],

        offset: usize, // seek offset
    },
}

impl AcpiScheme {
    fn get_tables() -> Vec<(SdtSignature, PhysSlice)> {
        let mut active_table = unsafe { ActivePageTable::new() };

        let mut tables = Vec::new();

        for allowed_tbl_name in ALLOWED_TABLES.iter() {
            use crate::acpi::{find_sdt, get_sdt, get_sdt_signature};

            // it appears that the SDTs are identity mapped, in which case we can just call get_sdt
            // whenever we need to and use the slice as if it was physical.

            let table_name_str =
                str::from_utf8(allowed_tbl_name).expect("ACPI table name wasn't correct UTF-8");

            for sdt in find_sdt(table_name_str) {
                let virt =
                    get_sdt(sdt as *const Sdt as usize, &mut active_table) as *const Sdt as usize;
                let signature = get_sdt_signature(sdt);
                let sdt_pointer = sdt as *const Sdt as usize;
                let len = sdt.length as usize;
                assert_eq!(virt, sdt_pointer);
                tables.push((
                    signature,
                    PhysSlice {
                        phys_ptr: sdt_pointer,
                        len,
                        virt,
                    },
                ));
            }
        }
        tables
    }
    pub fn new() -> Self {
        Self {
            handles: RwLock::new(BTreeMap::new()),
            tables: Self::get_tables(),
            next_fd: AtomicUsize::new(0),
        }
    }
    fn lookup_signature_index(
        &self,
        name: [u8; 4],
        oem_id: [u8; 6],
        oem_table_id: [u8; 8],
    ) -> Option<usize> {
        self.tables
            .iter()
            .position(|((sig_name, sig_oem_id, sig_oem_table_id), _)| {
                sig_name.as_bytes() == &name
                    && sig_oem_id == &oem_id
                    && sig_oem_table_id == &oem_table_id
            })
    }
    fn lookup_signature(
        &self,
        name: [u8; 4],
        oem_id: [u8; 6],
        oem_table_id: [u8; 8],
    ) -> Option<PhysSlice> {
        Some(self.tables[self.lookup_signature_index(name, oem_id, oem_table_id)?].1)
    }
}

fn parse_table_filename(filename: &[u8]) -> Option<([u8; 4], [u8; 6], [u8; 8])> {
    // the table identifier takes the form:
    // 1. a four byte table name, like 'APIC' (MADT) or 'MCFG'.
    // 2. a dash followed by 12 hexadecimal digits (6 bytes when decoded) composing the OEM ID.
    // 3. another dash followed by 16 hex digits (8 bytes), composing the OEM Table ID.
    // hence, the table is 4 + 1 + 12 + 1 + 16 = 34 bytes long.
    if filename.len() != 34 {
        return None;
    }
    let mut table_identifier = [0u8; 34];
    table_identifier.copy_from_slice(filename);

    let table_name = &table_identifier[..4];
    if table_identifier[4] != b'-' {
        return None;
    }
    let oem_id_hex = &table_identifier[5..17];
    if table_identifier[17] != b'-' {
        return None;
    }
    let oem_table_id_hex = &table_identifier[18..34];

    let oem_id_hex_str = str::from_utf8(oem_id_hex).ok()?;
    let oem_table_id_hex_str = str::from_utf8(oem_table_id_hex).ok()?;

    let mut oem_id = [0u8; 6];

    for index in 0..oem_id.len() {
        oem_id[index] = u8::from_str_radix(&oem_id_hex_str[index * 2..(index + 1) * 2], 16).ok()?;
    }

    let mut oem_table_id = [0u8; 8];

    for index in 0..oem_table_id.len() {
        oem_table_id[index] =
            u8::from_str_radix(&oem_table_id_hex_str[index * 2..(index + 1) * 2], 16).ok()?;
    }

    Some((table_name.try_into().unwrap(), oem_id, oem_table_id))
}
fn serialize_table_filename(
    buffer: &mut [u8],
    (table_name, oem_id, oem_table_id): ([u8; 4], [u8; 6], [u8; 8]),
) -> usize {
    let mut wrapper = Take::write_to_buf(buffer);
    write!(
        wrapper,
        "{}-",
        str::from_utf8(&table_name).expect("Acpi table id wasn't valid UTF-8")
    )
    .unwrap();
    for b in &oem_id {
        write!(wrapper, "{:2x}", b).unwrap();
    }
    write!(wrapper, "-").unwrap();
    for b in &oem_table_id {
        write!(wrapper, "{:2x}", b).unwrap();
    }
    wrapper.bytes_currently_written()
}

impl Scheme for AcpiScheme {
    fn open(&self, path: &[u8], flags: usize, opener_uid: u32, _opener_gid: u32) -> Result<usize> {
        if opener_uid != 0 {
            return Err(Error::new(EACCES));
        }

        let path_str = str::from_utf8(path).or(Err(Error::new(ENOENT)))?;
        let path_str = path_str.trim_start_matches('/');

        // TODO: Use some kind of component iterator.

        let new_handle = if path_str.starts_with("tables") {
            let subpath = (&path_str[6..]).trim_start_matches('/');

            if subpath.is_empty() {
                // List of ACPI tables
                if (flags & O_DIRECTORY == 0 && flags & O_STAT == 0)
                    || (flags & O_ACCMODE == O_WRONLY || flags & O_ACCMODE == O_RDWR)
                {
                    return Err(Error::new(EISDIR));
                }
                Handle::Tables(0)
            } else {
                if (flags & O_DIRECTORY != 0 && flags & O_STAT == 0) {
                    return Err(Error::new(ENOTDIR));
                }
                if flags & O_ACCMODE == O_WRONLY || flags & O_ACCMODE == O_RDWR {
                    return Err(Error::new(EINVAL));
                }
                let (name, oem_id, oem_table_id) =
                    parse_table_filename(subpath.as_bytes()).ok_or(Error::new(ENOENT))?;

                if self
                    .lookup_signature_index(name, oem_id, oem_table_id)
                    .is_none()
                {
                    return Err(Error::new(ENOENT));
                }
                Handle::Table {
                    name,
                    oem_id,
                    oem_table_id,
                    offset: 0,
                }
            }
        } else if path.is_empty() {
            // Top-level
            if (flags & O_DIRECTORY == 0 && flags & O_STAT == 0)
                || (flags & O_ACCMODE == O_WRONLY || flags & O_ACCMODE == O_RDWR)
            {
                return Err(Error::new(EISDIR));
            }
            Handle::TopLevel(0)
        } else {
            return Err(Error::new(ENOENT));
        };
        let new_fd = self.next_fd.fetch_add(1, atomic::Ordering::SeqCst);
        self.handles.write().insert(new_fd, Mutex::new(new_handle));
        Ok(new_fd)
    }
    fn fpath(&self, id: usize, buf: &mut [u8]) -> Result<usize> {
        let handles_guard = self.handles.read();
        let handle = handles_guard.get(&id).ok_or(Error::new(EBADF))?.lock();

        Ok(match &*handle {
            &Handle::TopLevel(_) => {
                let path = b"acpi:";
                let max = core::cmp::min(buf.len(), path.len());
                buf[..max].copy_from_slice(&path[..]);
                max
            }
            &Handle::Tables(_) => {
                let path = b"acpi:tables";
                let max = core::cmp::min(buf.len(), path.len());
                buf[..max].copy_from_slice(&path[..]);
                max
            }
            &Handle::Table {
                name,
                oem_id,
                oem_table_id,
                ..
            } => {
                let base_path = b"acpi:tables/";
                let base_max = core::cmp::min(buf.len(), base_path.len());
                buf[..base_max].copy_from_slice(&base_path[..]);
                serialize_table_filename(&mut buf[base_max..], (name, oem_id, oem_table_id))
            }
        })
    }
    fn fstat(&self, id: usize, stat: &mut Stat) -> Result<usize> {
        let handles_guard = self.handles.read();
        let handle = handles_guard.get(&id).ok_or(Error::new(EBADF))?.lock();

        match &*handle {
            &Handle::TopLevel(_) => {
                stat.st_mode = MODE_DIR;
                stat.st_size = TOPLEVEL_DIR_CONTENTS.len() as u64;
            }
            &Handle::Tables(_) => {
                stat.st_mode = MODE_DIR;
                stat.st_size = (self.tables.len() * 35) as u64; // fixed size of 34 bytes for the file names, plus a newline
            }
            &Handle::Table {
                name,
                oem_id,
                oem_table_id,
                ..
            } => {
                let len = self
                    .lookup_signature(name, oem_id, oem_table_id)
                    .ok_or(Error::new(EBADFD))?
                    .len;

                stat.st_mode = MODE_FILE;
                stat.st_size = len as u64;
            }
        }
        Ok(0)
    }
    fn seek(&self, id: usize, pos: usize, whence: usize) -> Result<usize> {
        let handles_guard = self.handles.read();
        let mut handle = handles_guard.get(&id).ok_or(Error::new(EBADF))?.lock();

        let (cur_offset, length) = match &*handle {
            &Handle::TopLevel(offset) => (offset, TOPLEVEL_DIR_CONTENTS.len()),
            &Handle::Tables(offset) => (offset, self.tables.len() * 35),
            &Handle::Table {
                name,
                oem_id,
                oem_table_id,
                offset,
            } => (
                offset,
                self.lookup_signature(name, oem_id, oem_table_id)
                    .ok_or(Error::new(EBADFD))?
                    .len,
            ),
        };
        let new_offset = match whence {
            SEEK_CUR => core::cmp::min(cur_offset + pos, length),
            SEEK_END => core::cmp::min(length + pos, length),
            SEEK_SET => core::cmp::min(length, pos),
            _ => return Err(Error::new(EINVAL)),
        };
        match &mut *handle {
            &mut Handle::Table { ref mut offset, .. }
            | &mut Handle::Tables(ref mut offset)
            | &mut Handle::TopLevel(ref mut offset) => *offset = new_offset,
        }
        Ok(new_offset)
    }
    fn read(&self, id: usize, mut buf: &mut [u8]) -> Result<usize> {
        let handles_guard = self.handles.read();
        let mut handle = handles_guard.get(&id).ok_or(Error::new(EBADF))?.lock();

        match &mut *handle {
            &mut Handle::TopLevel(ref mut offset) => {
                let max_bytes_to_read = core::cmp::min(buf.len(), TOPLEVEL_DIR_CONTENTS.len());
                let bytes_to_read = core::cmp::max(max_bytes_to_read, *offset) - *offset;
                buf[..bytes_to_read]
                    .copy_from_slice(&TOPLEVEL_DIR_CONTENTS[*offset..*offset + bytes_to_read]);
                *offset += bytes_to_read;
                Ok(bytes_to_read)
            }
            &mut Handle::Tables(ref mut offset) => {
                if *offset >= self.tables.len() * 35 {
                    return Ok(0);
                }
                // one really good thing with fixed size filenames, is that no index has to be
                // stored anywhere!
                let base_table_index = *offset / 35;
                let mut bytes_to_skip = *offset % 35;
                let mut bytes_read = 0;

                for index in base_table_index..self.tables.len() {
                    let &(ref name_string, oem_id, oem_table_id) = &self.tables[index].0;
                    let signature = (
                        name_string.as_bytes().try_into().or(Err(Error::new(EIO)))?,
                        oem_id,
                        oem_table_id,
                    );

                    let mut src_buf = [0u8; 35];
                    serialize_table_filename(&mut src_buf[..34], signature);
                    src_buf[34] = b'\n';

                    let max_bytes_to_read = core::cmp::min(buf.len(), src_buf.len());
                    let bytes_to_read =
                        core::cmp::max(max_bytes_to_read, bytes_to_skip) - bytes_to_skip;
                    buf[..bytes_to_read].copy_from_slice(&src_buf[..bytes_to_read]);
                    bytes_read += bytes_to_read;
                    bytes_to_skip = 0;
                    buf = &mut buf[..bytes_to_read];
                }
                *offset += bytes_read;
                Ok(bytes_read)
            }
            &mut Handle::Table {
                name,
                oem_id,
                oem_table_id,
                ref mut offset,
            } => {
                let index = self
                    .lookup_signature_index(name, oem_id, oem_table_id)
                    .ok_or(Error::new(EBADFD))?;
                let (
                    _,
                    PhysSlice {
                        phys_ptr,
                        len,
                        virt: old_virt,
                    },
                ) = self.tables[index];
                assert_eq!(phys_ptr, old_virt);
                let new_virt =
                    crate::acpi::get_sdt(phys_ptr, unsafe { &mut ActivePageTable::new() })
                        as *const Sdt as usize;

                let table_contents =
                    unsafe { core::slice::from_raw_parts(new_virt as *const u8, len) };

                let max_bytes_to_read = core::cmp::min(buf.len(), table_contents.len());
                let bytes_to_read = core::cmp::max(max_bytes_to_read, *offset) - *offset;
                buf[..bytes_to_read]
                    .copy_from_slice(&table_contents[*offset..*offset + bytes_to_read]);
                *offset += bytes_to_read;
                Ok(bytes_to_read)
            }
        }
    }
    fn write(&self, id: usize, buf: &[u8]) -> Result<usize> {
        Err(Error::new(EBADF))
    }
}
