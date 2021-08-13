//! The backend of the "proc:" scheme. Most internal breakpoint
//! handling should go here, unless they closely depend on the design
//! of the scheme.

use crate::{
    arch::{
        interrupt::InterruptStack,
        paging::{
            mapper::PageFlushAll,
            ActivePageTable, InactivePageTable, Page, PAGE_SIZE, TableKind, VirtualAddress
        }
    },
    common::unique::Unique,
    context::{self, signal, Context, ContextId},
    event,
    scheme::proc,
    sync::WaitCondition,
    syscall::{
        data::PtraceEvent,
        error::*,
        flag::*,
        ptrace_event
    },
};

use alloc::{
    boxed::Box,
    collections::{
        BTreeMap,
        VecDeque,
        btree_map::Entry
    },
    sync::Arc,
    vec::Vec
};
use core::{
    cmp,
    sync::atomic::Ordering
};
use spin::{Mutex, Once, RwLock, RwLockReadGuard, RwLockWriteGuard};

//  ____                _
// / ___|  ___  ___ ___(_) ___  _ __  ___
// \___ \ / _ \/ __/ __| |/ _ \| '_ \/ __|
//  ___) |  __/\__ \__ \ | (_) | | | \__ \
// |____/ \___||___/___/_|\___/|_| |_|___/

#[derive(Debug)]
pub struct SessionData {
    breakpoint: Option<Breakpoint>,
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
            flags
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
    pub fn with_session<F, T>(pid: ContextId, callback: F) -> Result<T>
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

type SessionMap = BTreeMap<ContextId, Arc<Session>>;

static SESSIONS: Once<RwLock<SessionMap>> = Once::new();

fn init_sessions() -> RwLock<SessionMap> {
    RwLock::new(BTreeMap::new())
}
fn sessions() -> RwLockReadGuard<'static, SessionMap> {
    SESSIONS.call_once(init_sessions).read()
}
fn sessions_mut() -> RwLockWriteGuard<'static, SessionMap> {
    SESSIONS.call_once(init_sessions).write()
}

/// Try to create a new session, but fail if one already exists for this
/// process
pub fn try_new_session(pid: ContextId, file_id: usize) -> bool {
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
pub fn close_session(pid: ContextId) {
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
pub fn close_tracee(pid: ContextId) {
    if let Some(session) = sessions().get(&pid) {
        session.tracer.notify();

        let data = session.data.lock();
        proc_trigger_event(data.file_id, EVENT_READ);
    }
}

/// Returns true if a session is attached to this process
pub fn is_traced(pid: ContextId) -> bool {
    sessions().contains_key(&pid)
}

/// Trigger a notification to the event: scheme
fn proc_trigger_event(file_id: usize, flags: EventFlags) {
    event::trigger(proc::PROC_SCHEME_ID.load(Ordering::SeqCst), file_id, flags);
}

/// Dispatch an event to any tracer tracing `self`. This will cause
/// the tracer to wake up and poll for events. Returns Some(()) if an
/// event was sent.
pub fn send_event(event: PtraceEvent) -> Option<()> {
    let id = {
        let contexts = context::contexts();
        let context = contexts.current()?;
        let context = context.read();
        context.id
    };

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
struct Breakpoint {
    reached: bool,
    flags: PtraceFlags
}

/// Wait for the tracee to stop, or return immediately if there's an unread
/// event.
///
/// Note: Don't call while holding any locks or allocated data, this will
/// switch contexts and may in fact just never terminate.
pub fn wait(pid: ContextId) -> Result<()> {
    loop {
        let session = {
            let sessions = sessions();

            match sessions.get(&pid) {
                Some(session) => Arc::clone(&session),
                _ => return Ok(())
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
pub fn breakpoint_callback(match_flags: PtraceFlags, event: Option<PtraceEvent>) -> Option<PtraceFlags> {
    loop {
        let session = {
            let contexts = context::contexts();
            let context = contexts.current()?;
            let context = context.read();

            let sessions = sessions();
            let session = sessions.get(&context.id)?;

            Arc::clone(&session)
        };

        let mut data = session.data.lock();
        let breakpoint = data.breakpoint?; // only go to sleep if there's a breakpoint

        // Only stop if the tracer have asked for this breakpoint
        if breakpoint.flags & match_flags != match_flags {
            return None;
        }

        // In case no tracer is waiting, make sure the next one gets the memo
        data.breakpoint.as_mut()
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
pub fn next_breakpoint() -> Option<PtraceFlags> {
    let contexts = context::contexts();
    let context = contexts.current()?;
    let context = context.read();

    let sessions = sessions();
    let session = sessions.get(&context.id)?;
    let data = session.data.lock();
    let breakpoint = data.breakpoint?;

    Some(breakpoint.flags)
}

//  ____            _     _
// |  _ \ ___  __ _(_)___| |_ ___ _ __ ___
// | |_) / _ \/ _` | / __| __/ _ \ '__/ __|
// |  _ <  __/ (_| | \__ \ ||  __/ |  \__ \
// |_| \_\___|\__, |_|___/\__\___|_|  |___/
//            |___/

pub struct ProcessRegsGuard;

/// Make all registers available to e.g. the proc: scheme
/// ---
/// For use inside arch-specific code to assign the pointer of the
/// interupt stack to the current process. Meant to reduce the amount
/// of ptrace-related code that has to lie in arch-specific bits.
/// ```rust,ignore
/// let _guard = ptrace::set_process_regs(pointer);
/// ...
/// // (_guard implicitly dropped)
/// ```
pub fn set_process_regs(pointer: *mut InterruptStack) -> Option<ProcessRegsGuard> {
    let contexts = context::contexts();
    let context = contexts.current()?;
    let mut context = context.write();

    let kstack = context.kstack.as_mut()?;

    context.regs = Some((kstack.as_mut_ptr() as usize, Unique::new(pointer)));
    Some(ProcessRegsGuard)
}

impl Drop for ProcessRegsGuard {
    fn drop(&mut self) {
        fn clear_process_regs() -> Option<()> {
            let contexts = context::contexts();
            let context = contexts.current()?;
            let mut context = context.write();

            context.regs = None;
            Some(())
        }
        clear_process_regs();
    }
}

/// Return the InterruptStack pointer, but relative to the specified
/// stack instead of the original.
pub unsafe fn rebase_regs_ptr(
    regs: Option<(usize, Unique<InterruptStack>)>,
    kstack: Option<&Box<[u8]>>
) -> Option<*const InterruptStack> {
    let (old_base, ptr) = regs?;
    let new_base = kstack?.as_ptr() as usize;
    Some((ptr.as_ptr() as usize - old_base + new_base) as *const _)
}
/// Return the InterruptStack pointer, but relative to the specified
/// stack instead of the original.
pub unsafe fn rebase_regs_ptr_mut(
    regs: Option<(usize, Unique<InterruptStack>)>,
    kstack: Option<&mut Box<[u8]>>
) -> Option<*mut InterruptStack> {
    let (old_base, ptr) = regs?;
    let new_base = kstack?.as_mut_ptr() as usize;
    Some((ptr.as_ptr() as usize - old_base + new_base) as *mut _)
}

/// Return a reference to the InterruptStack struct in memory. If the
/// kernel stack has been backed up by a signal handler, this instead
/// returns the struct inside that memory, as that will later be
/// restored and otherwise undo all your changes. See `update(...)` in
/// context/switch.rs.
pub unsafe fn regs_for(context: &Context) -> Option<&InterruptStack> {
    let signal_backup_regs = match context.ksig {
        None => None,
        Some((_, _, ref kstack, signum)) => {
            let is_user_handled = {
                let actions = context.actions.read();
                signal::is_user_handled(actions[signum as usize].0.sa_handler)
            };
            if is_user_handled {
                None
            } else {
                Some(rebase_regs_ptr(context.regs, kstack.as_ref())?)
            }
        }
    };
    signal_backup_regs
        .or_else(|| context.regs.map(|regs| regs.1.as_ptr() as *const _))
        .map(|ptr| &*ptr)
}

/// Mutable version of `regs_for`
pub unsafe fn regs_for_mut(context: &mut Context) -> Option<&mut InterruptStack> {
    let signal_backup_regs = match context.ksig {
        None => None,
        Some((_, _, ref mut kstack, signum)) => {
            let is_user_handled = {
                let actions = context.actions.read();
                signal::is_user_handled(actions[signum as usize].0.sa_handler)
            };
            if is_user_handled {
                None
            } else {
                Some(rebase_regs_ptr_mut(context.regs, kstack.as_mut())?)
            }
        }
    };
    signal_backup_regs
        .or_else(|| context.regs.map(|regs| regs.1.as_ptr()))
        .map(|ptr| &mut *ptr)
}

//  __  __
// |  \/  | ___ _ __ ___   ___  _ __ _   _
// | |\/| |/ _ \ '_ ` _ \ / _ \| '__| | | |
// | |  | |  __/ | | | | | (_) | |  | |_| |
// |_|  |_|\___|_| |_| |_|\___/|_|   \__, |
//                                   |___/

pub fn with_context_memory<F>(context: &mut Context, offset: VirtualAddress, len: usize, f: F) -> Result<()>
where F: FnOnce(*mut u8) -> Result<()>
{
    // As far as I understand, mapping any regions following
    // USER_TMP_MISC_OFFSET is safe because no other memory location
    // is used after it. In the future it might be necessary to define
    // a maximum amount of pages that can be mapped in one batch,
    // which could be used to either internally retry `read`/`write`
    // in `proc:<pid>/mem`, or return a partial read/write.
    let start = Page::containing_address(VirtualAddress::new(crate::USER_TMP_MISC_OFFSET));

    let mut active_page_table = unsafe { ActivePageTable::new(TableKind::User) };
    let mut target_page_table = unsafe {
        InactivePageTable::from_address(context.arch.get_page_utable())
    };

    // Find the physical frames for all pages
    let mut frames = Vec::new();

    {
        let mapper = target_page_table.mapper();

        let mut inner = || -> Result<()> {
            let start = Page::containing_address(offset);
            let end = Page::containing_address(VirtualAddress::new(offset.data() + len - 1));
            for page in Page::range_inclusive(start, end) {
                frames.push((
                    mapper.translate_page(page).ok_or(Error::new(EFAULT))?,
                    mapper.translate_page_flags(page).ok_or(Error::new(EFAULT))?
                ));
            }
            Ok(())
        };
        inner()?;
    }

    // Map all the physical frames into linear pages
    let pages = frames.len();
    let mut page = start;
    let flush_all = PageFlushAll::new();
    for (frame, mut flags) in frames {
        flags = flags.execute(false).write(true);
        flush_all.consume(active_page_table.map_to(page, frame, flags));

        page = page.next();
    }

    flush_all.flush();

    let res = f((start.start_address().data() + offset.data() % PAGE_SIZE) as *mut u8);

    // Unmap all the pages (but allow no deallocation!)
    let mut page = start;
    let flush_all = PageFlushAll::new();
    for _ in 0..pages {
        flush_all.consume(active_page_table.unmap_return(page, true).0);
        page = page.next();
    }

    flush_all.flush();

    res
}
