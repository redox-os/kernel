use alloc::arc::Arc;
use alloc::Vec;
use spin::{Mutex, RwLock};

use context::{self, Context, SwitchResult};

#[derive(Debug)]
pub struct WaitCondition {
    contexts: Mutex<Vec<Arc<RwLock<Context>>>>
}

impl WaitCondition {
    pub fn new() -> WaitCondition {
        WaitCondition {
            contexts: Mutex::new(Vec::new())
        }
    }

    pub fn notify(&self) -> usize {
        let mut contexts = self.contexts.lock();
        let len = contexts.len();
        while let Some(context_lock) = contexts.pop() {
            context_lock.write().unblock();
        }
        len
    }

    pub fn wait(&self) -> SwitchResult {
        {
            let context_lock = {
                let contexts = context::contexts();
                let context_lock = contexts.current().expect("WaitCondition::wait: no context");
                context_lock.clone()
            };

            context_lock.write().block();

            self.contexts.lock().push(context_lock);
        }

        unsafe { context::switch() }
    }
}

impl Drop for WaitCondition {
    fn drop(&mut self){
        self.notify();
    }
}
