use alloc::{collections::BTreeMap, sync::Arc};
use spin::RwLock;

use spinning_top::RwSpinlock;

use super::{
    context::{Context, ContextId, Kstack},
    memory::AddrSpaceWrapper,
    process::{new_process, Process, ProcessId, ProcessInfo},
};
use crate::{
    interrupt::InterruptStack,
    scheme::SchemeNamespace,
    syscall::error::{Error, Result, EAGAIN},
};

/// Context list type
pub struct ContextList {
    // Using a BTreeMap for it's range method
    map: BTreeMap<ContextId, Arc<RwSpinlock<Context>>>,
    next_id: usize,
}

impl ContextList {
    /// Create a new context list.
    pub const fn new() -> Self {
        ContextList {
            map: BTreeMap::new(),
            next_id: 1,
        }
    }

    /// Get the nth context.
    pub fn get(&self, id: ContextId) -> Option<&Arc<RwSpinlock<Context>>> {
        self.map.get(&id)
    }

    /// Get the current context.
    pub fn current(&self) -> Option<&Arc<RwSpinlock<Context>>> {
        self.map.get(&super::current_cid())
    }

    pub fn iter(
        &self,
    ) -> ::alloc::collections::btree_map::Iter<ContextId, Arc<RwSpinlock<Context>>> {
        self.map.iter()
    }

    pub fn range(
        &self,
        range: impl core::ops::RangeBounds<ContextId>,
    ) -> ::alloc::collections::btree_map::Range<'_, ContextId, Arc<RwSpinlock<Context>>> {
        self.map.range(range)
    }

    pub(crate) fn insert_context_raw(
        &mut self,
        cid: ContextId,
        pid: ProcessId,
        process: Arc<RwLock<Process>>,
    ) -> Result<&Arc<RwSpinlock<Context>>> {
        assert!(self
            .map
            // TODO
            .insert(
                cid,
                Arc::new(RwSpinlock::new(Context::new(cid, pid, process)?))
            )
            .is_none());

        Ok(self
            .map
            .get(&cid)
            .expect("Failed to insert new context. ID is out of bounds."))
    }

    /// Create a new context.
    pub fn new_context(
        &mut self,
        process: Arc<RwLock<Process>>,
    ) -> Result<&Arc<RwSpinlock<Context>>> {
        let pid = process.read().pid;

        // Zero is not a valid context ID, therefore add 1.
        //
        // FIXME: Ensure the number of CPUs can't switch between new_context calls.
        let min = crate::cpu_count() as usize + 1;

        self.next_id = core::cmp::max(self.next_id, min);

        if self.next_id >= super::CONTEXT_MAX_CONTEXTS {
            self.next_id = min;
        }

        while self.map.contains_key(&ContextId::from(self.next_id)) {
            self.next_id += 1;
        }

        if self.next_id >= super::CONTEXT_MAX_CONTEXTS {
            return Err(Error::new(EAGAIN));
        }

        let id = ContextId::from(self.next_id);
        self.next_id += 1;

        self.insert_context_raw(id, pid, process)
    }

    /// Spawn a context from a function.
    pub fn spawn(
        &mut self,
        userspace_allowed: bool,
        process: Arc<RwLock<Process>>,
        func: extern "C" fn(),
    ) -> Result<&Arc<RwSpinlock<Context>>> {
        let stack = Kstack::new()?;

        let context_lock = self.new_context(Arc::clone(&process))?;
        process.write().threads.push(Arc::downgrade(&context_lock));
        {
            let mut context = context_lock.write();
            let _ = context.set_addr_space(Some(AddrSpaceWrapper::new()?));

            let mut stack_top = stack.initial_top();

            const INT_REGS_SIZE: usize = core::mem::size_of::<crate::interrupt::InterruptStack>();

            if userspace_allowed {
                unsafe {
                    // Zero-initialize InterruptStack registers.
                    stack_top = stack_top.sub(INT_REGS_SIZE);
                    stack_top.write_bytes(0_u8, INT_REGS_SIZE);
                    (&mut *stack_top.cast::<InterruptStack>()).init();
                }
            }
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            unsafe {
                if userspace_allowed {
                    stack_top = stack_top.sub(core::mem::size_of::<usize>());
                    stack_top
                        .cast::<usize>()
                        .write(crate::interrupt::syscall::enter_usermode as usize);
                }

                stack_top = stack_top.sub(core::mem::size_of::<usize>());
                stack_top.cast::<usize>().write(func as usize);
            }

            #[cfg(target_arch = "aarch64")]
            unsafe {
                context
                    .arch
                    .set_lr(crate::interrupt::syscall::enter_usermode as usize);
                context.arch.set_x28(func as usize);
                context.arch.set_context_handle();
            }

            context.arch.set_stack(stack_top as usize);

            context.kstack = Some(stack);
            context.userspace = userspace_allowed;
        }
        Ok(context_lock)
    }

    pub fn remove(&mut self, id: ContextId) -> Option<Arc<RwSpinlock<Context>>> {
        self.map.remove(&id)
    }
}
