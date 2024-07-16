//! The backend of the "proc:" scheme. Most internal breakpoint
//! handling should go here, unless they closely depend on the design
//! of the scheme.

use crate::{
    context::{self, process::ProcessId},
    event,
    percpu::PercpuBlock,
    scheme::GlobalSchemes,
    sync::WaitCondition,
    syscall::{data::PtraceEvent, error::*, flag::*, ptrace_event},
};

use alloc::{collections::VecDeque, sync::Arc};
use core::cmp;
use hashbrown::hash_map::{Entry, HashMap};
use spin::{Mutex, Once, RwLock, RwLockReadGuard, RwLockWriteGuard};

//  ____                _
// / ___|  ___  ___ ___(_) ___  _ __  ___
// \___ \ / _ \/ __/ __| |/ _ \| '_ \/ __|
//  ___) |  __/\__ \__ \ | (_) | | | \__ \
// |____/ \___||___/___/_|\___/|_| |_|___/

#[derive(Debug)]
pub struct SessionData {
    pub(crate) breakpoint: Option<Breakpoint>,
    events: VecDeque<PtraceEvent>,
    file_id: usize,
}
impl SessionData {
    fn add_event(&mut self, event: PtraceEvent) {
        self.events.push_back(event);

        // Notify nonblocking tracers
        if self.events.len() == 1 {
            // If the list of events was previously empty, alert now
            proc_trigger_event(self.file_id, EVENT_READ);
        }
    }

    /// Override the breakpoint for the specified tracee. Pass `None` to clear
    /// breakpoint.
    pub fn set_breakpoint(&mut self, flags: Option<PtraceFlags>) {
        self.breakpoint = flags.map(|flags| Breakpoint {
            reached: false,
            flags,
        });
    }

    /// Returns true if the breakpoint is reached, or if there isn't a
    /// breakpoint
    pub fn is_reached(&self) -> bool {
        self.breakpoint.as_ref().map(|b| b.reached).unwrap_or(false)
    }

    /// Used for getting the flags in fevent
    pub fn session_fevent_flags(&self) -> EventFlags {
        let mut flags = EventFlags::empty();

        if !self.events.is_empty() {
            flags |= EVENT_READ;
        }

        flags
    }

    /// Poll events, return the amount read. This drains events from the queue.
    pub fn recv_events(&mut self, out: &mut [PtraceEvent]) -> usize {
        let len = cmp::min(out.len(), self.events.len());
        for (dst, src) in out.iter_mut().zip(self.events.drain(..len)) {
            *dst = src;
        }
        len
    }
}

#[derive(Debug)]
pub struct Session {
    pub data: Mutex<SessionData>,
    pub tracee: WaitCondition,
    pub tracer: WaitCondition,
}
impl Session {
    pub fn with_session<F, T>(pid: ProcessId, callback: F) -> Result<T>
    where
        F: FnOnce(&Session) -> Result<T>,
    {
        let sessions = sessions();
        let session = sessions.get(&pid).ok_or_else(|| {
            println!("session doesn't exist - returning ENODEV.");
            println!("can this ever happen?");
            Error::new(ENODEV)
        })?;

        callback(session)
    }
}

type SessionMap = HashMap<ProcessId, Arc<Session>>;

static SESSIONS: Once<RwLock<SessionMap>> = Once::new();

fn init_sessions() -> RwLock<SessionMap> {
    RwLock::new(HashMap::new())
}
pub(crate) fn sessions() -> RwLockReadGuard<'static, SessionMap> {
    SESSIONS.call_once(init_sessions).read()
}
fn sessions_mut() -> RwLockWriteGuard<'static, SessionMap> {
    SESSIONS.call_once(init_sessions).write()
}

/// Try to create a new session, but fail if one already exists for this
/// process
pub fn try_new_session(pid: ProcessId, file_id: usize) -> bool {
    let mut sessions = sessions_mut();

    match sessions.entry(pid) {
        Entry::Occupied(_) => false,
        Entry::Vacant(vacant) => {
            vacant.insert(Arc::new(Session {
                data: Mutex::new(SessionData {
                    breakpoint: None,
                    events: VecDeque::new(),
                    file_id,
                }),
                tracee: WaitCondition::new(),
                tracer: WaitCondition::new(),
            }));
            true
        }
    }
}

/// Remove the session from the list of open sessions and notify any
/// waiting processes
pub fn close_session(pid: ProcessId) {
    if let Some(session) = sessions_mut().remove(&pid) {
        session.tracer.notify();
        session.tracee.notify();
    }
}

/// Wake up the tracer to make sure it catches on that the tracee is dead. This
/// is different from `close_session` in that it doesn't actually close the
/// session, and instead waits for the file handle to be closed, where the
/// session will *actually* be closed. This is partly to ensure ENOSRCH is
/// returned rather than ENODEV (which occurs when there's no session - should
/// never really happen).
pub fn close_tracee(pid: ProcessId) {
    if let Some(session) = sessions().get(&pid) {
        session.tracer.notify();

        let data = session.data.lock();
        proc_trigger_event(data.file_id, EVENT_READ);
    }
}

/// Returns true if a session is attached to this process
pub fn is_traced(pid: ProcessId) -> bool {
    sessions().contains_key(&pid)
}

/// Trigger a notification to the event: scheme
fn proc_trigger_event(file_id: usize, flags: EventFlags) {
    event::trigger(GlobalSchemes::ProcFull.scheme_id(), file_id, flags);
}

/// Dispatch an event to any tracer tracing `self`. This will cause
/// the tracer to wake up and poll for events. Returns Some(()) if an
/// event was sent.
pub fn send_event(event: PtraceEvent) -> Option<()> {
    let id = context::current().read().pid;

    let sessions = sessions();
    let session = sessions.get(&id)?;
    let mut data = session.data.lock();
    let breakpoint = data.breakpoint.as_ref()?;

    if event.cause & breakpoint.flags != event.cause {
        return None;
    }

    // Add event to queue
    data.add_event(event);
    // Notify tracer
    session.tracer.notify();

    Some(())
}

//  ____                 _                _       _
// | __ ) _ __ ___  __ _| | ___ __   ___ (_)_ __ | |_ ___
// |  _ \| '__/ _ \/ _` | |/ / '_ \ / _ \| | '_ \| __/ __|
// | |_) | | |  __/ (_| |   <| |_) | (_) | | | | | |_\__ \
// |____/|_|  \___|\__,_|_|\_\ .__/ \___/|_|_| |_|\__|___/
//                           |_|

#[derive(Debug, Clone, Copy)]
pub(crate) struct Breakpoint {
    reached: bool,
    pub(crate) flags: PtraceFlags,
}

/// Wait for the tracee to stop, or return immediately if there's an unread
/// event.
///
/// Note: Don't call while holding any locks or allocated data, this will
/// switch contexts and may in fact just never terminate.
pub fn wait(pid: ProcessId) -> Result<()> {
    loop {
        let session = {
            let sessions = sessions();

            match sessions.get(&pid) {
                Some(session) => Arc::clone(session),
                _ => return Ok(()),
            }
        };

        // Lock the data, to make sure we're reading the final value before going
        // to sleep.
        let data = session.data.lock();

        // Wake up if a breakpoint is already reached or there's an unread event
        if data.breakpoint.as_ref().map(|b| b.reached).unwrap_or(false) || !data.events.is_empty() {
            break;
        }

        // Go to sleep, and drop the lock on our data, which will allow other the
        // tracer to wake us up.
        if session.tracer.wait(data, "ptrace::wait") {
            // We successfully waited, wake up!
            break;
        }
    }

    Ok(())
}

/// Notify the tracer and await green flag to continue. If the breakpoint was
/// set and reached, return the flags which the user waited for. Otherwise,
/// None.
///
/// Note: Don't call while holding any locks or allocated data, this
/// will switch contexts and may in fact just never terminate.
pub fn breakpoint_callback(
    match_flags: PtraceFlags,
    event: Option<PtraceEvent>,
) -> Option<PtraceFlags> {
    loop {
        let percpu = PercpuBlock::current();

        // TODO: Some or all flags?
        // Only stop if the tracer have asked for this breakpoint
        if percpu.ptrace_flags.get().contains(match_flags) {
            return None;
        }

        let session = percpu.ptrace_session.borrow().as_ref()?.upgrade()?;

        let mut data = session.data.lock();
        let breakpoint = data.breakpoint?; // only go to sleep if there's a breakpoint

        // In case no tracer is waiting, make sure the next one gets the memo
        data.breakpoint
            .as_mut()
            .expect("already checked that breakpoint isn't None")
            .reached = true;

        // Add event to queue
        data.add_event(event.unwrap_or(ptrace_event!(match_flags)));

        // Wake up sleeping tracer
        session.tracer.notify();

        if session.tracee.wait(data, "ptrace::breakpoint_callback") {
            // We successfully waited, wake up!
            break Some(breakpoint.flags);
        }
    }
}

/// Obtain the next breakpoint flags for the current process. This is used for
/// detecting whether or not the tracer decided to use sysemu mode.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn next_breakpoint() -> Option<PtraceFlags> {
    let context_lock = context::current();
    let context = context_lock.read();

    let sessions = sessions();
    let session = sessions.get(&context.pid)?;
    let data = session.data.lock();
    let breakpoint = data.breakpoint?;

    Some(breakpoint.flags)
}
