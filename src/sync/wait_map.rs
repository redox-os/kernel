use alloc::collections::BTreeMap;
use core::mem;
use spin::Mutex;

use crate::sync::WaitCondition;

#[derive(Debug)]
pub struct WaitMap<K, V> {
    pub inner: Mutex<BTreeMap<K, V>>,
    pub condition: WaitCondition
}

impl<K, V> WaitMap<K, V> where K: Clone + Ord {
    pub fn new() -> WaitMap<K, V> {
        WaitMap {
            inner: Mutex::new(BTreeMap::new()),
            condition: WaitCondition::new()
        }
    }

    pub fn receive_nonblock(&self, key: &K) -> Option<V> {
        self.inner.lock().remove(key)
    }

    pub fn receive(&self, key: &K, reason: &'static str) -> V {
        loop {
            let mut inner = self.inner.lock();
            if let Some(value) = inner.remove(key) {
                return value;
            }
            //TODO: use false from wait condition to indicate EINTR
            let _ = self.condition.wait(inner, reason);
        }
    }

    pub fn receive_any_nonblock(&self) -> Option<(K, V)> {
        let mut inner = self.inner.lock();
        if let Some(key) = inner.keys().next().cloned() {
            inner.remove(&key).map(|value| (key, value))
        } else {
            None
        }
    }

    pub fn receive_any(&self, reason: &'static str) -> (K, V) {
        loop {
            let mut inner = self.inner.lock();
            if let Some(key) = inner.keys().next().cloned() {
                if let Some(entry) = inner.remove(&key).map(|value| (key, value)) {
                    return entry;
                }
            }
            let _ = self.condition.wait(inner, reason);
        }
    }

    pub fn receive_all(&self) -> BTreeMap<K, V> {
        let mut ret = BTreeMap::new();
        mem::swap(&mut ret, &mut *self.inner.lock());
        ret
    }

    pub fn send(&self, key: K, value: V) {
        self.inner.lock().insert(key, value);
        self.condition.notify();
    }
}
