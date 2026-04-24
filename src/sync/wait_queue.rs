use alloc::collections::VecDeque;
use syscall::{EAGAIN, EINTR};

use crate::{
    sync::{CleanLockToken, LockToken, Mutex, WaitCondition, L1, L2},
    syscall::{
        error::{Error, Result, EINVAL},
        usercopy::UserSliceWo,
    },
};

#[derive(Debug)]
pub struct WaitQueue<T> {
    incoming: Mutex<L2, VecDeque<T>>,
    outgoing: Mutex<L2, VecDeque<T>>,
    pub condition: WaitCondition,
}

impl<T> WaitQueue<T> {
    pub const fn new() -> WaitQueue<T> {
        WaitQueue {
            incoming: Mutex::new(VecDeque::new()),
            outgoing: Mutex::new(VecDeque::new()),
            condition: WaitCondition::new(),
        }
    }

    pub fn is_currently_empty(&self, token: &mut CleanLockToken) -> bool {
        self.incoming.lock(token.token()).is_empty() && self.outgoing.lock(token.token()).is_empty()
    }

    pub fn receive_into_user(
        &self,
        buf: UserSliceWo,
        block: bool,
        reason: &'static str,
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        loop {
            let mut tmp_queue = VecDeque::new();
            {
                let mut out = self.outgoing.lock(token.token());
                if !out.is_empty() {
                    let (s1, s2) = out.as_slices();
                    let s1_bytes = unsafe {
                        core::slice::from_raw_parts(s1.as_ptr().cast::<u8>(), size_of_val(s1))
                    };
                    let s2_bytes = unsafe {
                        core::slice::from_raw_parts(s2.as_ptr().cast::<u8>(), size_of_val(s2))
                    };

                    let mut bytes_copied = buf.copy_common_bytes_from_slice(s1_bytes)?;

                    if let Some(buf_for_s2) = buf.advance(s1_bytes.len()) {
                        bytes_copied += buf_for_s2.copy_common_bytes_from_slice(s2_bytes)?;
                    }

                    let _ = out.drain(..bytes_copied / size_of::<T>());
                    return Ok(bytes_copied);
                }

                // Act as outgoing.drain(..), but much faster
                core::mem::swap(&mut *out, &mut tmp_queue);
            }

            let incoming_guard = self.incoming.lock(token.token());
            let (mut incoming, mut split_token) = incoming_guard.into_split();

            if incoming.is_empty() {
                if block {
                    // SAFETY: Uses wait_inner because this inner is L2. It's guaranteed there's no other
                    // lock held at this point because clean token is provided from caller.
                    if !self
                        .condition
                        .wait_inner(incoming, reason, &mut split_token)
                    {
                        return Err(Error::new(EINTR));
                    }
                    continue;
                } else if buf.is_empty() {
                    return Ok(0);
                } else if buf.len() < size_of::<T>() {
                    return Err(Error::new(EINVAL));
                } else {
                    // TODO: EWOULDBLOCK?
                    return Err(Error::new(EAGAIN));
                }
            }

            // Act as incoming.drain(..), but much faster
            core::mem::swap(&mut *incoming, &mut tmp_queue);
            drop(incoming);

            {
                let mut out = self.outgoing.lock(token.token());
                // outgoing = incoming
                *out = tmp_queue;
            }
        }
    }

    pub fn send(&self, value: T, token: &mut CleanLockToken) -> usize {
        self.send_locked(value, token.token().downgrade())
    }

    pub fn send_locked(&self, value: T, mut token: LockToken<'_, L1>) -> usize {
        let len = {
            let mut inner = self.incoming.lock(token.token());
            inner.push_back(value);
            inner.len()
        };
        self.condition.notify_locked(token);
        len
    }
}
