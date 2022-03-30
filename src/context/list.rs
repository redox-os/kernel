use alloc::sync::Arc;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use core::alloc::{GlobalAlloc, Layout};
use core::{iter, mem};
use core::sync::atomic::Ordering;
use crate::paging::{ActivePageTable, TableKind};
use spin::RwLock;

use crate::syscall::error::{Result, Error, EAGAIN};
use super::context::{Context, ContextId};

/// Context list type
pub struct ContextList {
    map: BTreeMap<ContextId, Arc<RwLock<Context>>>,
    next_id: usize
}

impl ContextList {
    /// Create a new context list.
    pub const fn new() -> Self {
        ContextList {
            map: BTreeMap::new(),
            next_id: 1
        }
    }

    /// Get the nth context.
    pub fn get(&self, id: ContextId) -> Option<&Arc<RwLock<Context>>> {
        self.map.get(&id)
    }

    /// Get an iterator of all parents
    pub fn ancestors(&'_ self, id: ContextId) -> impl Iterator<Item = (ContextId, &Arc<RwLock<Context>>)> + '_ {
        iter::successors(self.get(id).map(|context| (id, context)), move |(_id, context)| {
            let context = context.read();
            let id = context.ppid;
            self.get(id).map(|context| (id, context))
        })
    }

    /// Get the current context.
    pub fn current(&self) -> Option<&Arc<RwLock<Context>>> {
        self.map.get(&super::CONTEXT_ID.load(Ordering::SeqCst))
    }

    pub fn iter(&self) -> ::alloc::collections::btree_map::Iter<ContextId, Arc<RwLock<Context>>> {
        self.map.iter()
    }

    pub fn range(&self, range: impl core::ops::RangeBounds<ContextId>) -> ::alloc::collections::btree_map::Range<'_, ContextId, Arc<RwLock<Context>>> {
        self.map.range(range)
    }

    /// Create a new context.
    pub fn new_context(&mut self) -> Result<&Arc<RwLock<Context>>> {
        if self.next_id >= super::CONTEXT_MAX_CONTEXTS {
            self.next_id = 1;
        }

        while self.map.contains_key(&ContextId::from(self.next_id)) {
            self.next_id += 1;
        }

        if self.next_id >= super::CONTEXT_MAX_CONTEXTS {
            return Err(Error::new(EAGAIN));
        }

        let id = ContextId::from(self.next_id);
        self.next_id += 1;

        assert!(self.map.insert(id, Arc::new(RwLock::new(Context::new(id)?))).is_none());

        Ok(self.map.get(&id).expect("Failed to insert new context. ID is out of bounds."))
    }

    /// Spawn a context from a function.
    pub fn spawn(&mut self, func: extern fn()) -> Result<&Arc<RwLock<Context>>> {
        let context_lock = self.new_context()?;
        {
            let mut context = context_lock.write();
            let mut fx = unsafe { Box::from_raw(crate::ALLOCATOR.alloc(Layout::from_size_align_unchecked(1024, 16)) as *mut [u8; 1024]) };
            for b in fx.iter_mut() {
                *b = 0;
            }
            let mut stack = vec![0; 65_536].into_boxed_slice();
            let offset = stack.len() - mem::size_of::<usize>();

            #[cfg(target_arch = "x86_64")]
            unsafe {
                let offset = stack.len() - mem::size_of::<usize>();
                let func_ptr = stack.as_mut_ptr().add(offset);
                *(func_ptr as *mut usize) = func as usize;
            }

            #[cfg(target_arch = "aarch64")]
            {
                let context_id = context.id.into();
                context.arch.set_lr(func as usize);
                context.arch.set_context_handle();
            }

            context.arch.set_page_utable(unsafe { ActivePageTable::new(TableKind::User).address() });
            #[cfg(target_arch = "aarch64")]
            context.arch.set_page_ktable(unsafe { ActivePageTable::new(TableKind::Kernel).address() });
            context.arch.set_fx(fx.as_ptr() as usize);
            context.arch.set_stack(stack.as_ptr() as usize + offset);
            context.kfx = Some(fx);
            context.kstack = Some(stack);
        }
        Ok(context_lock)
    }

    pub fn remove(&mut self, id: ContextId) -> Option<Arc<RwLock<Context>>> {
        self.map.remove(&id)
    }
}
