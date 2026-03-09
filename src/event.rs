use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};
use hashbrown::{hash_map::DefaultHashBuilder, HashMap};
use smallvec::SmallVec;
use spin::Once;
use syscall::data::GlobalSchemes;

use crate::{
    context,
    scheme::{self, SchemeExt, SchemeId},
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

    pub fn is_currently_empty(&self, token: &mut CleanLockToken) -> bool {
        self.queue.is_currently_empty(token)
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

                let files = context.files.read(token.token());
                match files.get(event.id).ok_or(Error::new(EBADF))? {
                    Some(file) => file.clone(),
                    None => return Err(Error::new(EBADF)),
                }
            };

            let (scheme, number) = {
                let description = file.description.read(token.token());
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
                token,
            );

            let flags = sync(RegKey { scheme, number }, token)?;
            if !flags.is_empty() {
                trigger(scheme, number, flags, token);
            }
        }

        Ok(events.len())
    }

    pub fn into_drop(self, token: &mut CleanLockToken) {
        self.queue.condition.into_drop(token);
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
static QUEUES: RwLock<L1, EventQueueList> =
    RwLock::new(EventQueueList::with_hasher(DefaultHashBuilder::new()));

/// Get the event queues list, const
pub fn queues(token: LockToken<'_, L0>) -> RwLockReadGuard<'_, L1, EventQueueList> {
    QUEUES.read(token)
}

/// Get the event queues list, mutable
pub fn queues_mut(token: LockToken<'_, L0>) -> RwLockWriteGuard<'_, L1, EventQueueList> {
    QUEUES.write(token)
}

#[derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RegKey {
    pub scheme: SchemeId,
    pub number: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct QueueKey {
    pub queue: EventQueueId,
    pub id: usize,
    pub data: usize,
}

type Registry = HashMap<RegKey, HashMap<QueueKey, EventFlags>>;

static REGISTRY: Once<RwLock<L1, Registry>> = Once::new();

/// Initialize registry, called if needed
fn init_registry() -> RwLock<L1, Registry> {
    RwLock::new(Registry::new())
}

/// Get the global schemes list, const
fn registry(token: &'_ mut CleanLockToken) -> RwLockReadGuard<'_, L1, Registry> {
    REGISTRY.call_once(init_registry).read(token.token())
}

/// Get the global schemes list, mutable
pub fn registry_mut(token: &'_ mut CleanLockToken) -> RwLockWriteGuard<'_, L1, Registry> {
    REGISTRY.call_once(init_registry).write(token.token())
}

pub fn register(
    reg_key: RegKey,
    queue_key: QueueKey,
    flags: EventFlags,
    token: &mut CleanLockToken,
) {
    let mut registry = registry_mut(token);

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
        let registry = registry(token);

        if let Some(queue_list) = registry.get(&reg_key) {
            for (_queue_key, &queue_flags) in queue_list.iter() {
                flags |= queue_flags;
            }
        }
    }

    let scheme = scheme::get_scheme(token.token(), reg_key.scheme)?;

    scheme.fevent(reg_key.number, flags, token)
}

pub fn unregister_file(scheme: SchemeId, number: usize, token: &mut CleanLockToken) {
    let mut registry = registry_mut(token);

    registry.remove(&RegKey { scheme, number });
}

//TODO: Implement unregister_queue
// pub fn unregister_queue(scheme: SchemeId, number: usize) {
//
// }

const MAX_EVENT: usize = 8;

#[must_use]
fn trigger_inner(
    scheme: SchemeId,
    number: usize,
    flags: EventFlags,
    todo: &mut SmallVec<[EventQueueId; MAX_EVENT]>,
    offset: &mut usize,
    token: &mut CleanLockToken,
) -> bool {
    let mut matching_keys: SmallVec<[(QueueKey, EventFlags); MAX_EVENT]> = SmallVec::new();
    let mut full = false;

    {
        let registry = registry(token);
        if let Some(queue_list) = registry.get(&RegKey { scheme, number }) {
            for (queue_key, &queue_flags) in queue_list.iter().skip(*offset) {
                let common_flags = flags & queue_flags;
                if !common_flags.is_empty() {
                    if matching_keys.len() == matching_keys.inline_size() {
                        full = true;
                        break;
                    }
                    matching_keys.push((queue_key.clone(), common_flags));
                }
                *offset += 1;
            }
        }
    }

    while let Some((queue_key, common_flags)) = matching_keys.pop() {
        let Some(queue) = queues(token.token()).get(&queue_key.queue).cloned() else {
            continue;
        };

        let event = Event {
            id: queue_key.id,
            flags: common_flags,
            data: queue_key.data,
        };

        todo.push(queue_key.queue);
        queue.queue.send(event, token);
        if let Some(queue) = Arc::into_inner(queue) {
            queue.into_drop(token);
        }
    }

    full
}

pub fn trigger(scheme: SchemeId, number: usize, flags: EventFlags, token: &mut CleanLockToken) {
    let mut todo = SmallVec::<[EventQueueId; MAX_EVENT]>::new();
    let mut done = SmallVec::<[EventQueueId; MAX_EVENT]>::new();

    // First trigger with the original file
    let mut offset = 0;
    while trigger_inner(scheme, number, flags, &mut todo, &mut offset, token) {}

    // Handle triggers on queues
    while let Some(queue_id) = todo.pop() {
        if let Err(insert_idx) = done.binary_search(&queue_id) {
            done.insert(insert_idx, queue_id);
            let mut offset = 0;
            while trigger_inner(
                GlobalSchemes::Event.scheme_id(),
                queue_id.into(),
                EventFlags::EVENT_READ,
                &mut todo,
                &mut offset,
                token,
            ) {}
        }
    }
}
