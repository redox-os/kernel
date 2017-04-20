use memory::{free_frames, used_frames};

use syscall::data::StatVfs;
use syscall::error::*;
use syscall::scheme::Scheme;

pub struct MemoryScheme;

impl Scheme for MemoryScheme {
    fn open(&self, _path: &[u8], _flags: usize, _uid: u32, _gid: u32) -> Result<usize> {
        Ok(0)
    }

    fn fstatvfs(&self, _file: usize, stat: &mut StatVfs) -> Result<usize> {
        let used = used_frames() as u64;
        let free = free_frames() as u64;

        stat.f_bsize = 4096;
        stat.f_blocks = used + free;
        stat.f_bfree = free;
        stat.f_bavail = stat.f_bfree;

        Ok(0)
    }

    fn fcntl(&self, _id: usize, _cmd: usize, _arg: usize) -> Result<usize> {
        Ok(0)
    }

    fn fpath(&self, _id: usize, buf: &mut [u8]) -> Result<usize> {
        let mut i = 0;
        let scheme_path = b"memory:";
        while i < buf.len() && i < scheme_path.len() {
            buf[i] = scheme_path[i];
            i += 1;
        }
        Ok(i)
    }

    /// Close the file `number`
    fn close(&self, _file: usize) -> Result<usize> {
        Ok(0)
    }
}
