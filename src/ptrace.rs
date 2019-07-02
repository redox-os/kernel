use crate::{
    arch::macros::InterruptStack,
    common::unique::Unique,
    context::{self, Context, ContextId, Status},
    sync::WaitCondition
};

use alloc::{
    boxed::Box,
    collections::BTreeMap,
    sync::Arc
};
use spin::{Once, RwLock, RwLockReadGuard, RwLockWriteGuard};
use syscall::error::*;

//  ____                 _                _       _
// | __ ) _ __ ___  __ _| | ___ __   ___ (_)_ __ | |_ ___
// |  _ \| '__/ _ \/ _` | |/ / '_ \ / _ \| | '_ \| __/ __|
// | |_) | | |  __/ (_| |   <| |_) | (_) | | | | | |_\__ \
// |____/|_|  \___|\__,_|_|\_\ .__/ \___/|_|_| |_|\__|___/
//                           |_|

struct Handle {
    tracee: Arc<WaitCondition>,
    tracer: Arc<WaitCondition>,
    reached: bool,

    sysemu: bool,
    singlestep: bool
}

static BREAKPOINTS: Once<RwLock<BTreeMap<ContextId, Handle>>> = Once::new();

fn init_breakpoints() -> RwLock<BTreeMap<ContextId, Handle>> {
    RwLock::new(BTreeMap::new())
}
fn breakpoints() -> RwLockReadGuard<'static, BTreeMap<ContextId, Handle>> {
    BREAKPOINTS.call_once(init_breakpoints).read()
}
fn breakpoints_mut() -> RwLockWriteGuard<'static, BTreeMap<ContextId, Handle>> {
    BREAKPOINTS.call_once(init_breakpoints).write()
}

fn inner_cont(pid: ContextId) -> Option<Handle> {
    // Remove the breakpoint to both save space and also make sure any
    // yet unreached but obsolete breakpoints don't stop the program.
    let handle = breakpoints_mut().remove(&pid)?;
    handle.tracee.notify();
    Some(handle)
}

/// Continue the process with the specified ID
pub fn cont(pid: ContextId) {
    inner_cont(pid);
}

/// Create a new breakpoint for the specified tracee, optionally with a sysemu flag
pub fn set_breakpoint(pid: ContextId, sysemu: bool, singlestep: bool) {
    let (tracee, tracer) = match inner_cont(pid) {
        Some(breakpoint) => (breakpoint.tracee, breakpoint.tracer),
        None => (
            Arc::new(WaitCondition::new()),
            Arc::new(WaitCondition::new())
        )
    };

    breakpoints_mut().insert(pid, Handle {
        tracee,
        tracer,
        reached: false,
        sysemu,
        singlestep
    });
}

/// Wait for the tracee to stop.
/// Note: Don't call while holding any locks, this will switch contexts
pub fn wait_breakpoint(pid: ContextId) -> Result<()> {
    let tracer = {
        let breakpoints = breakpoints();
        match breakpoints.get(&pid) {
            Some(breakpoint) if !breakpoint.reached => Arc::clone(&breakpoint.tracer),
            _ => return Ok(())
        }
    };
    while !tracer.wait() {}

    let contexts = context::contexts();
    let context = contexts.get(pid).ok_or(Error::new(ESRCH))?;
    let context = context.read();
    if let Status::Exited(_) = context.status {
        return Err(Error::new(ESRCH));
    }
    Ok(())
}

/// Returns the same value as breakpoint_callback would do, but
/// doesn't actually perform the action. You should not rely too
/// heavily on this value, as the lock *is* released between this call
/// and another.
pub fn breakpoint_callback_dryrun(singlestep: bool) -> Option<bool> {
    let contexts = context::contexts();
    let context = contexts.current()?;
    let context = context.read();

    let breakpoints = breakpoints();
    let breakpoint = breakpoints.get(&context.id)?;
    if breakpoint.singlestep != singlestep {
        return None;
    }
    Some(breakpoint.sysemu)
}

/// Notify the tracer and await green flag to continue.
/// Note: Don't call while holding any locks, this will switch contexts
pub fn breakpoint_callback(singlestep: bool) -> Option<bool> {
    // Can't hold any locks when executing wait()
    let (tracee, sysemu) = {
        let contexts = context::contexts();
        let context = contexts.current()?;
        let context = context.read();

        let mut breakpoints = breakpoints_mut();
        let breakpoint = breakpoints.get_mut(&context.id)?;

        // TODO: How should singlesteps interact with syscalls? How
        // does Linux handle this?

        // if singlestep && !breakpoint.singlestep {
        if breakpoint.singlestep != singlestep {
            return None;
        }

        breakpoint.tracer.notify();
        // In case no tracer is waiting, make sure the next one gets
        // the memo
        breakpoint.reached = true;

        (
            Arc::clone(&breakpoint.tracee),
            breakpoint.sysemu
        )
    };

    while !tracee.wait() {}

    Some(sysemu)
}

/// Call when a context is closed to alert any tracers
pub fn close(pid: ContextId) {
    {
        let breakpoints = breakpoints();
        if let Some(breakpoint) = breakpoints.get(&pid) {
            breakpoint.tracer.notify();
        }
    }

    breakpoints_mut().remove(&pid);
}

//  ____            _     _
// |  _ \ ___  __ _(_)___| |_ ___ _ __ ___
// | |_) / _ \/ _` | / __| __/ _ \ '__/ __|
// |  _ <  __/ (_| | \__ \ ||  __/ |  \__ \
// |_| \_\___|\__, |_|___/\__\___|_|  |___/
//            |___/

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
    Some(&*match context.ksig {
        Some((_, _, ref kstack)) => rebase_regs_ptr(context.regs, kstack.as_ref())?,
        None => context.regs?.1.as_ptr()
    })
}

/// Mutable version of `regs_for`
pub unsafe fn regs_for_mut(context: &mut Context) -> Option<&mut InterruptStack> {
    Some(&mut *match context.ksig {
        Some((_, _, ref mut kstack)) => rebase_regs_ptr_mut(context.regs, kstack.as_mut())?,
        None => context.regs?.1.as_ptr()
    })
}
