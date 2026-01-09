use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicUsize, Ordering};
use hashbrown::{HashMap, HashSet};
use spin::Once;

use crate::{
    context,
    scheme::{self, GlobalSchemes, SchemeId},
    sync::{
        CleanLockToken, LockToken, RwLock, RwLockReadGuard, RwLockWriteGuard, WaitQueue, L0, L1,
    },
    syscall::{
        data::Event,
        error::{Error, Result, EBADF},
        flag::EventFlags,
        usercopy::UserSliceWo,
    },
};

int_like!(EventQueueId, AtomicEventQueueId, usize, AtomicUsize);

pub struct EventQueue {
    id: EventQueueId,
    queue: WaitQueue<Event>,
}

impl EventQueue {
    pub fn new(id: EventQueueId) -> EventQueue {
        EventQueue {
            id,
            queue: WaitQueue::new(),
        }
    }

    pub fn is_currently_empty(&self) -> bool {
        self.queue.is_currently_empty()
    }

    pub fn read(&self, buf: UserSliceWo, block: bool, token: &mut CleanLockToken) -> Result<usize> {
        self.queue
            .receive_into_user(buf, block, "EventQueue::read", token)
    }

    pub fn write(&self, events: &[Event], token: &mut CleanLockToken) -> Result<usize> {
        for event in events {
            let file = {
                let context_ref = context::current();
                let context = context_ref.read(token.token());

                let files = context.files.read();
                match files.get(event.id).ok_or(Error::new(EBADF))? {
                    Some(file) => file.clone(),
                    None => return Err(Error::new(EBADF)),
                }
            };

            let (scheme, number) = {
                let description = file.description.read();
                (description.scheme, description.number)
            };

            if scheme == GlobalSchemes::Event.scheme_id() && number == self.id.into() {
                // Do not allow recursively registering the same event queue
                //TODO: should we also disallow event queues that contain this event queue?
                return Err(Error::new(EBADF));
            }

            register(
                RegKey { scheme, number },
                QueueKey {
                    queue: self.id,
                    id: event.id,
                    data: event.data,
                },
                event.flags,
            );

            let flags = sync(RegKey { scheme, number }, token)?;
            if !flags.is_empty() {
                trigger(scheme, number, flags);
            }
        }

        Ok(events.len())
    }
}

pub type EventQueueList = HashMap<EventQueueId, Arc<EventQueue>>;

// Next queue id
static NEXT_QUEUE_ID: AtomicUsize = AtomicUsize::new(0);

/// Get next queue id
pub fn next_queue_id() -> EventQueueId {
    EventQueueId::from(NEXT_QUEUE_ID.fetch_add(1, Ordering::SeqCst))
}

// Current event queues
static QUEUES: Once<RwLock<L1, EventQueueList>> = Once::new();

/// Initialize queues, called if needed
fn init_queues() -> RwLock<L1, EventQueueList> {
    RwLock::new(HashMap::new())
}

/// Get the event queues list, const
pub fn queues(token: LockToken<'_, L0>) -> RwLockReadGuard<'_, L1, EventQueueList> {
    QUEUES.call_once(init_queues).read(token)
}

/// Get the event queues list, mutable
pub fn queues_mut(token: LockToken<'_, L0>) -> RwLockWriteGuard<'_, L1, EventQueueList> {
    QUEUES.call_once(init_queues).write(token)
}

#[derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RegKey {
    pub scheme: SchemeId,
    pub number: usize,
}

#[derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct QueueKey {
    pub queue: EventQueueId,
    pub id: usize,
    pub data: usize,
}

type Registry = HashMap<RegKey, HashMap<QueueKey, EventFlags>>;

static REGISTRY: Once<spin::RwLock<Registry>> = Once::new();

/// Initialize registry, called if needed
fn init_registry() -> spin::RwLock<Registry> {
    spin::RwLock::new(Registry::new())
}

/// Get the global schemes list, const
fn registry() -> spin::RwLockReadGuard<'static, Registry> {
    REGISTRY.call_once(init_registry).read()
}

/// Get the global schemes list, mutable
pub fn registry_mut() -> spin::RwLockWriteGuard<'static, Registry> {
    REGISTRY.call_once(init_registry).write()
}

pub fn register(reg_key: RegKey, queue_key: QueueKey, flags: EventFlags) {
    let mut registry = registry_mut();

    let entry = registry.entry(reg_key).or_default();

    if flags.is_empty() {
        entry.remove(&queue_key);
    } else {
        entry.insert(queue_key, flags);
    }
}

pub fn sync(reg_key: RegKey, token: &mut CleanLockToken) -> Result<EventFlags> {
    let mut flags = EventFlags::empty();

    {
        let registry = registry();

        if let Some(queue_list) = registry.get(&reg_key) {
            for (_queue_key, &queue_flags) in queue_list.iter() {
                flags |= queue_flags;
            }
        }
    }

    let scheme = scheme::schemes(token.token())
        .get(reg_key.scheme)
        .ok_or(Error::new(EBADF))?
        .clone();

    scheme.fevent(reg_key.number, flags, token)
}

pub fn unregister_file(scheme: SchemeId, number: usize) {
    let mut registry = registry_mut();

    registry.remove(&RegKey { scheme, number });
}

//TODO: Implement unregister_queue
// pub fn unregister_queue(scheme: SchemeId, number: usize) {
//
// }

fn trigger_inner(
    scheme: SchemeId,
    number: usize,
    flags: EventFlags,
    todo: &mut Vec<EventQueueId>,
    token: &mut CleanLockToken,
) {
    let registry = registry();
    if let Some(queue_list) = registry.get(&RegKey { scheme, number }) {
        for (queue_key, &queue_flags) in queue_list.iter() {
            let common_flags = flags & queue_flags;
            if !common_flags.is_empty() {
                let queue_opt = {
                    let queues = queues(token.token());
                    queues.get(&queue_key.queue).cloned()
                };
                if let Some(queue) = queue_opt {
                    queue.queue.send(
                        Event {
                            id: queue_key.id,
                            flags: common_flags,
                            data: queue_key.data,
                        },
                        token,
                    );
                    todo.push(queue_key.queue);
                }
            }
        }
    }
}

pub fn trigger(scheme: SchemeId, number: usize, flags: EventFlags) {
    //TODO: propogate this lock token
    let mut token = unsafe { CleanLockToken::new() };

    // First trigger with the original file
    let mut todo = Vec::new();
    trigger_inner(scheme, number, flags, &mut todo, &mut token);

    // Handle triggers on queues
    //TODO: can this be done with limited allocations?
    let mut done = HashSet::new();
    while let Some(queue_id) = todo.pop() {
        if !done.contains(&queue_id) {
            trigger_inner(
                GlobalSchemes::Event.scheme_id(),
                queue_id.into(),
                EventFlags::EVENT_READ,
                &mut todo,
                &mut token,
            );
            done.insert(queue_id);
        }
    }
}
