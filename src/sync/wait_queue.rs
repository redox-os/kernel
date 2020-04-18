use alloc::collections::VecDeque;
use spin::Mutex;

use crate::sync::WaitCondition;

#[derive(Debug)]
pub struct WaitQueue<T> {
    pub inner: Mutex<VecDeque<T>>,
    pub condition: WaitCondition,
}

impl<T> WaitQueue<T> {
    pub fn new() -> WaitQueue<T> {
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
