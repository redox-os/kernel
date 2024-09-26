use core::{
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicUsize, Ordering},
};

// TODO: move all this code to userspace
use alloc::{
    collections::BTreeMap,
    sync::{Arc, Weak},
    vec::Vec,
};

use spin::RwLock;
use spinning_top::RwSpinlock;

use syscall::{Error, Result, ENOMEM, ESRCH};

use crate::{
    scheme::{CallerCtx, SchemeNamespace},
    sync::WaitMap,
};

use crate::context::{self, Context, WaitpidKey};

int_like!(ProcessId, AtomicProcessId, usize, AtomicUsize);

#[derive(Debug)]
pub struct Process {
    pub info: ProcessInfo,
    /// Context is being waited on
    pub waitpid: Arc<WaitMap<WaitpidKey, (ProcessId, usize)>>,
    pub status: ProcessStatus,
    pub threads: Vec<Weak<RwSpinlock<Context>>>,
}
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessInfo {
    /// The process ID of this process
    pub pid: ProcessId,
    /// The group ID of this process
    pub pgid: ProcessId,
    /// The ID of the parent process
    pub ppid: ProcessId,
    /// The ID of the session
    pub session_id: ProcessId,
    /// The real user id
    pub ruid: u32,
    /// The real group id
    pub rgid: u32,
    /// The real namespace id
    pub rns: SchemeNamespace,
    /// The effective user id
    pub euid: u32,
    /// The effective group id
    pub egid: u32,
    /// The effective namespace id
    pub ens: SchemeNamespace,
}
impl Deref for Process {
    type Target = ProcessInfo;

    fn deref(&self) -> &Self::Target {
        &self.info
    }
}
impl DerefMut for Process {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.info
    }
}
#[derive(Debug, Clone, Copy)]
pub enum ProcessStatus {
    PossiblyRunnable,
    Stopped(usize),
    Exiting,
    Exited(usize),
}

pub const INIT: ProcessId = ProcessId::new(1);
static NEXT_PID: AtomicProcessId = AtomicProcessId::new(INIT);
pub static PROCESSES: RwLock<BTreeMap<ProcessId, Arc<RwLock<Process>>>> =
    RwLock::new(BTreeMap::new());

/// Get an iterator of all parents
pub fn ancestors(
    list: &BTreeMap<ProcessId, Arc<RwLock<Process>>>,
    id: ProcessId,
) -> impl Iterator<Item = (ProcessId, &Arc<RwLock<Process>>)> + '_ {
    core::iter::successors(
        list.get(&id).map(|process| (id, process)),
        move |(_id, process)| {
            let process = process.read();
            let id = process.ppid;
            list.get(&id).map(|process| (id, process))
        },
    )
}

pub fn current() -> Result<Arc<RwLock<Process>>> {
    let pid = context::current().read().pid;
    Ok(Arc::clone(
        PROCESSES.read().get(&pid).ok_or(Error::new(ESRCH))?,
    ))
}
impl Process {
    pub fn caller_ctx(&self) -> CallerCtx {
        CallerCtx {
            pid: self.pid.into(),
            uid: self.euid,
            gid: self.egid,
        }
    }
}
pub fn new_process(info: impl FnOnce(ProcessId) -> ProcessInfo) -> Result<Arc<RwLock<Process>>> {
    let pid = NEXT_PID.fetch_add(ProcessId::new(1), Ordering::Relaxed);
    let proc = Arc::try_new(RwLock::new(Process {
        waitpid: Arc::try_new(WaitMap::new()).map_err(|_| Error::new(ENOMEM))?,
        threads: Vec::new(),
        status: ProcessStatus::PossiblyRunnable,
        info: info(pid),
    }))
    .map_err(|_| Error::new(ENOMEM))?;
    PROCESSES.write().insert(pid, Arc::clone(&proc));
    Ok(proc)
}
