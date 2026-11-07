use core::{
    mem,
    ops::{Deref, DerefMut},
    slice,
};

use super::schemev2::SqeFlags;

use bitflags::bitflags;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Sqe {
    pub opcode: u8,
    pub sqe_flags: SqeFlags,
    pub _rsvd: u16, // TODO: priority
    pub tag: u32,
    pub caller: u64,
    pub caller_ctx: u64,
    pub args: [u64; 8],
    pub _rsvd2: [u64; 5],
}
impl Deref for Sqe {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self as *const Sqe as *const u8, mem::size_of::<Sqe>()) }
    }
}

impl DerefMut for Sqe {
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self as *mut Sqe as *mut u8, mem::size_of::<Sqe>()) }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Cqe {
    pub flags: u8, // bits 2:0 are CqeOpcode
    pub extra_raw: [u8; 3],
    pub tag: u32,
    pub result: u64,
    pub meta: [u64; 2],
}
impl Deref for Cqe {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self as *const Cqe as *const u8, mem::size_of::<Cqe>()) }
    }
}

impl DerefMut for Cqe {
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self as *mut Cqe as *mut u8, mem::size_of::<Cqe>()) }
    }
}

impl Cqe {
    pub fn extra(&self) -> u32 {
        u32::from_ne_bytes([self.extra_raw[0], self.extra_raw[1], self.extra_raw[2], 0])
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CqeOpcode {
    RespondRegular,
    RespondWithFd,
    SendFevent, // no tag
    ObtainFd,
    RespondWithMultipleFds,
    /// [`SchemeAsync::on_close`] and [`SchemeSync::on_close`] are only called when the last file
    /// descriptor referring to the file description is closed. To implement traditional POSIX
    /// advisory file locking, [`CqeOpcode::RespondAndNotifyOnDetach`] is used to notify the scheme
    /// by sending a [`RequestKind::OnDetach`] request the next time the file description is
    /// "detached" from a file descriptor. Not done by default to avoid unnecessary IPC.
    RespondAndNotifyOnDetach,
    // TODO: ProvideMmap
}

impl CqeOpcode {
    pub fn try_from_raw(raw: u8) -> Option<Self> {
        // TODO: Use a library where this match can be automated.
        Some(match raw {
            0 => Self::RespondRegular,
            1 => Self::RespondWithFd,
            2 => Self::SendFevent,
            3 => Self::ObtainFd,
            4 => Self::RespondWithMultipleFds,
            5 => Self::RespondAndNotifyOnDetach,
            _ => return None,
        })
    }
}
