use syscall::{EAGAIN, EINTR};
use crate::{
    sync::{CleanLockToken, L1, L2, LockToken, Mutex, WaitCondition, priority_queue::PriorityQueue}, syscall::{
        error::{EINVAL, Error, Result}, usercopy::UserSliceWo,
    },
};

#[derive(Debug)]
pub struct WaitQueue<T, const PRIORITY_CAPACITY: usize = 0> {
    inner: Mutex<L2, PriorityQueue<T, PRIORITY_CAPACITY>>,
    pub condition: WaitCondition,
}

impl<T, const PRIORITY_CAPACITY: usize> WaitQueue<T, PRIORITY_CAPACITY> {
    pub const fn new() -> WaitQueue<T, PRIORITY_CAPACITY> {
        WaitQueue {
            inner: Mutex::new(PriorityQueue::new()),
            condition: WaitCondition::new(),
        }
    }
    pub fn is_currently_empty(&self, token: &mut CleanLockToken) -> bool {
        self.inner.lock(token.token()).is_empty()
    }
    pub fn receive_into_user(
        &self,
        buf: UserSliceWo,
        block: bool,
        reason: &'static str,
        token: &mut CleanLockToken,
    ) -> Result<usize> {
        loop {
            let inner = self.inner.lock(token.token());
            let (mut inner, mut token) = inner.into_split();

            if inner.is_empty() {
                if block {
                    // SAFETY: Uses wait_inner because this inner is L2. It's guaranteed there's no other
                    // lock held at this point because clean token is provided from caller.
                    if !self.condition.wait_inner(inner, reason, &mut token) {
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

            // If the buffer is not empty and too small to even hold one 'T', we reject it.
            if !buf.is_empty() && buf.len() < size_of::<T>() {
                return Err(Error::new(EINVAL));
            }

            // Borrow only first contiguous FIFO segment for simplicity. The second segment will be handled in
            // the next call. This means we handle less entries then the implementation before.
            // TODO: Check if we want to handle both segments as once like before.
            let batch = inner.front();

            // Count how many complete entries fit in batch.
            let count = batch.len().min(buf.len() / size_of::<T>());

            // Copy entries as bytes.
            let bytes = unsafe {
                core::slice::from_raw_parts(batch.as_ptr().cast::<u8>(), count * size_of::<T>())
            };

            // Copy to userspace.
            let bytes_copied = buf.copy_common_bytes_from_slice(bytes)?;

            let _ = inner.consume(count);

            return Ok(bytes_copied);
        }
    }

    pub fn send(&self, value: T, token: &mut CleanLockToken) -> usize {
        self.send_locked(value, token.token().downgrade())
    }

    pub fn send_locked(&self, value: T, mut token: LockToken<'_, L1>) -> usize {
        let len = {
            let mut inner = self.inner.lock(token.token());
            inner.push_default(value);
            inner.len()
        };
        self.condition.notify_locked(token);
        len
    }

    pub fn try_send_priority(&self, value: T, token: &mut CleanLockToken) -> Result<usize, T> {
        let len = {
            let mut inner = self.inner.lock(token.token());
            inner.try_push_priority(value)?;
            inner.len()
        };

        self.condition.notify(token);

        Ok(len)
    }
}
