use crate::{
    arch::{
        macros::InterruptStack,
        paging::{
            entry::EntryFlags,
            mapper::MapperFlushAll,
            temporary_page::TemporaryPage,
            ActivePageTable, InactivePageTable, Page, PAGE_SIZE, VirtualAddress
        }
    },
    common::unique::Unique,
    context::{self, Context, ContextId, Status},
    sync::WaitCondition
};

use alloc::{
    boxed::Box,
    collections::BTreeMap,
    sync::Arc,
    vec::Vec
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

//  __  __
// |  \/  | ___ _ __ ___   ___  _ __ _   _
// | |\/| |/ _ \ '_ ` _ \ / _ \| '__| | | |
// | |  | |  __/ | | | | | (_) | |  | |_| |
// |_|  |_|\___|_| |_| |_|\___/|_|   \__, |
//                                   |___/

pub fn with_context_memory<F>(context: &Context, offset: VirtualAddress, len: usize, f: F) -> Result<()>
    where F: FnOnce(*mut u8) -> Result<()>
{
    // TODO: Is using USER_TMP_MISC_OFFSET safe? I guess make sure
    // it's not too large.
    let start = Page::containing_address(VirtualAddress::new(crate::USER_TMP_MISC_OFFSET));

    let mut active_page_table = unsafe { ActivePageTable::new() };
    let mut target_page_table = unsafe {
        InactivePageTable::from_address(context.arch.get_page_table())
    };

    // Find the physical frames for all pages
    let mut frames = Vec::new();

    let mut result = None;
    active_page_table.with(&mut target_page_table, &mut TemporaryPage::new(start), |mapper| {
        let mut inner = || -> Result<()> {
            let start = Page::containing_address(offset);
            let end = Page::containing_address(VirtualAddress::new(offset.get() + len - 1));
            for page in Page::range_inclusive(start, end) {
                frames.push((
                    mapper.translate_page(page).ok_or(Error::new(EFAULT))?,
                    mapper.translate_page_flags(page).ok_or(Error::new(EFAULT))?
                ));
            }
            Ok(())
        };
        result = Some(inner());
    });
    result.expect("with(...) callback should always be called")?;

    // Map all the physical frames into linear pages
    let pages = frames.len();
    let mut page = start;
    let mut flusher = MapperFlushAll::new();
    for (frame, mut flags) in frames {
        flags |= EntryFlags::NO_EXECUTE | EntryFlags::WRITABLE;
        flusher.consume(active_page_table.map_to(page, frame, flags));

        page = page.next();
    }

    flusher.flush(&mut active_page_table);

    let res = f((start.start_address().get() + offset.get() % PAGE_SIZE) as *mut u8);

    // Unmap all the pages (but allow no deallocation!)
    let mut page = start;
    let mut flusher = MapperFlushAll::new();
    for _ in 0..pages {
        flusher.consume(active_page_table.unmap_return(page, true).0);
        page = page.next();
    }

    flusher.flush(&mut active_page_table);

    res
}
