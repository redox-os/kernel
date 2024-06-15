use alloc::collections::VecDeque;
use spin::Mutex;
use syscall::{EAGAIN, EINTR};

use crate::{
    sync::WaitCondition,
    syscall::{
        error::{Error, Result, EINVAL},
        usercopy::UserSliceWo,
    },
};

#[derive(Debug)]
pub struct WaitQueue<T> {
    pub inner: Mutex<VecDeque<T>>,
    pub condition: WaitCondition,
}

impl<T> WaitQueue<T> {
    pub const fn new() -> WaitQueue<T> {
        WaitQueue {
            inner: Mutex::new(VecDeque::new()),
            condition: WaitCondition::new(),
        }
    }
    pub fn is_currently_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }

    pub fn receive(&self, block: bool, reason: &'static str) -> Result<T> {
        loop {
            let mut inner = self.inner.lock();

            if let Some(t) = inner.pop_front() {
                return Ok(t);
            } else if block {
                if !self.condition.wait(inner, reason) {
                    return Err(Error::new(EINTR));
                }
                continue;
            } else {
                return Err(Error::new(EAGAIN));
            }
        }
    }

    pub fn receive_into_user(
        &self,
        buf: UserSliceWo,
        block: bool,
        reason: &'static str,
    ) -> Result<usize> {
        loop {
            let mut inner = self.inner.lock();

            if inner.is_empty() {
                if block {
                    if !self.condition.wait(inner, reason) {
                        return Err(Error::new(EINTR));
                    }
                    continue;
                } else if buf.is_empty() {
                    return Ok(0);
                } else if buf.len() < core::mem::size_of::<T>() {
                    return Err(Error::new(EINVAL));
                } else {
                    // TODO: EWOULDBLOCK?
                    return Err(Error::new(EAGAIN));
                }
            }

            let (s1, s2) = inner.as_slices();
            let s1_bytes = unsafe {
                core::slice::from_raw_parts(
                    s1.as_ptr().cast::<u8>(),
                    s1.len() * core::mem::size_of::<T>(),
                )
            };
            let s2_bytes = unsafe {
                core::slice::from_raw_parts(
                    s2.as_ptr().cast::<u8>(),
                    s2.len() * core::mem::size_of::<T>(),
                )
            };

            let mut bytes_copied = buf.copy_common_bytes_from_slice(s1_bytes)?;

            if let Some(buf_for_s2) = buf.advance(s1_bytes.len()) {
                bytes_copied += buf_for_s2.copy_common_bytes_from_slice(s2_bytes)?;
            }

            let _ = inner.drain(..bytes_copied / core::mem::size_of::<T>());

            return Ok(bytes_copied);
        }
    }

    pub fn send(&self, value: T) -> usize {
        let len = {
            let mut inner = self.inner.lock();
            inner.push_back(value);
            inner.len()
        };
        self.condition.notify();
        len
    }
}
