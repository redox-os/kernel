use alloc::collections::VecDeque;
use spin::Mutex;
use syscall::{EAGAIN, EINTR};

use crate::sync::WaitCondition;
use crate::syscall::usercopy::UserSliceWo;
use crate::syscall::error::{Error, EINVAL, Result};

#[derive(Debug)]
pub struct WaitQueue<T> {
    pub inner: Mutex<VecDeque<T>>,
    pub condition: WaitCondition,
}

impl<T> WaitQueue<T> {
    pub const fn new() -> WaitQueue<T> {
        WaitQueue {
            inner: Mutex::new(VecDeque::new()),
            condition: WaitCondition::new()
        }
    }

    pub fn clone(&self) -> WaitQueue<T> where T: Clone {
        WaitQueue {
            inner: Mutex::new(self.inner.lock().clone()),
            condition: WaitCondition::new()
        }
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }

    pub fn receive(&self, reason: &'static str) -> Option<T> {
        loop {
            let mut inner = self.inner.lock();
            if let Some(value) = inner.pop_front() {
                return Some(value);
            }
            if ! self.condition.wait(inner, reason) {
                return None;
            }
        }
    }

    pub fn receive_into_user(&self, buf: UserSliceWo, block: bool, reason: &'static str) -> Result<usize> {
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
            let s1_bytes = unsafe { core::slice::from_raw_parts(s1.as_ptr().cast::<u8>(), s1.len() * core::mem::size_of::<T>()) };
            let s2_bytes = unsafe { core::slice::from_raw_parts(s2.as_ptr().cast::<u8>(), s2.len() * core::mem::size_of::<T>()) };

            let mut bytes_copied = buf.copy_common_bytes_from_slice(s1_bytes)?;

            if let Some(buf_for_s2) = buf.advance(s1_bytes.len()) {
                bytes_copied += buf_for_s2.copy_common_bytes_from_slice(s2_bytes)?;
            }

            let _ = inner.drain(..bytes_copied / core::mem::size_of::<T>());

            return Ok(bytes_copied);
        }
    }

    pub fn receive_into(&self, buf: &mut [T], block: bool, reason: &'static str) -> Option<usize> {
        let mut i = 0;

        if i < buf.len() && block {
            buf[i] = self.receive(reason)?;
            i += 1;
        }

        {
            let mut inner = self.inner.lock();
            while i < buf.len() {
                if let Some(value) = inner.pop_front() {
                    buf[i] = value;
                    i += 1;
                } else {
                    break;
                }
            }
        }

        Some(i)
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

    pub fn send_from(&self, buf: &[T]) -> usize where T: Copy {
        let len = {
            let mut inner = self.inner.lock();
            inner.extend(buf.iter());
            inner.len()
        };
        self.condition.notify();
        len
    }
}
