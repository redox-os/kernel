use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::{Mutex, RwLock};

use crate::context::{self, Context};

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

    // Notify all waiters
    pub fn notify(&self) -> usize {
        let mut contexts = self.contexts.lock();
        let len = contexts.len();
        while let Some(context_lock) = contexts.pop() {
            context_lock.write().unblock();
        }
        len
    }

    // Notify as though a signal woke the waiters
    pub unsafe fn notify_signal(&self) -> usize {
        let contexts = self.contexts.lock();
        let len = contexts.len();
        for context_lock in contexts.iter() {
            context_lock.write().unblock();
        }
        len
    }

    // Wait until notified. Returns false if resumed by a signal or the notify_signal function
    pub fn wait(&self) -> bool {
        let id;
        {
            let context_lock = {
                let contexts = context::contexts();
                let context_lock = contexts.current().expect("WaitCondition::wait: no context");
                Arc::clone(&context_lock)
            };

            {
                let mut context = context_lock.write();
                id = context.id;
                context.block();
            }

            self.contexts.lock().push(context_lock);
        }

        unsafe { context::switch(); }

        let mut waited = true;

        {
            let mut contexts = self.contexts.lock();

            let mut i = 0;
            while i < contexts.len() {
                let remove = {
                    let context = contexts[i].read();
                    context.id == id
                };

                if remove {
                    contexts.remove(i);
                    waited = false;
                    break;
                } else {
                    i += 1;
                }
            }
        }

        waited
    }
}

impl Drop for WaitCondition {
    fn drop(&mut self){
        unsafe { self.notify_signal() };
    }
}
