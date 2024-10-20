use core::result;

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct Error {
    pub errno: i32,
}

pub type Result<T, E = Error> = result::Result<T, E>;

impl Error {
    pub fn new(errno: i32) -> Error {
        Error { errno }
    }
}

pub unsafe fn sbi_svc(eid: u32, fid: u32, arg0: u32, arg1: u32, arg2: u32) -> Result<usize> {
    let error: usize;
    let value: usize;
    core::arch::asm!(
    "ecall",
    in("a7") eid as usize,
    in("a6") fid as usize,
    in("a0") arg0 as usize,
    in("a1") arg1 as usize,
    in("a2") arg2 as usize,
    lateout("a0") error,
    lateout("a1") value,
    options(nostack),
    );
    if error == 0 {
        Ok(value)
    } else {
        Err(Error::new(error as i32))
    }
}

pub struct Sbi {}
pub static SBI: Sbi = Sbi {};

const DEBUG_CONSOLE_EXTENSION: u32 = 0x4442434E;
const TIMER_EXTENSION: u32 = 0x54494D45;

impl Sbi {
    pub fn debug_console_write(self: &Self, buf: &[u8]) -> Result<usize> {
        let addr = buf.as_ptr() as u64;
        unsafe {
            sbi_svc(
                DEBUG_CONSOLE_EXTENSION,
                0,
                buf.len() as u32,
                addr as u32,
                (addr >> 32) as u32,
            )
        }
    }

    pub fn set_timer(self: &Self, stime_value: u64) -> Result<()> {
        unsafe {
            sbi_svc(
                TIMER_EXTENSION,
                0,
                stime_value as u32,
                (stime_value >> 32) as u32,
                0,
            )
        }
        .map(|_x| ())
    }
}
