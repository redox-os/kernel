// TODO: move all this code to userspace
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use spin::RwLock;
use spinning_top::RwSpinlock;

use syscall::{Error, Result, ESRCH};

use crate::scheme::SchemeNamespace;
use crate::sync::WaitMap;

use crate::context::{self, Context, WaitpidKey};

int_like!(ProcessId, usize);

#[derive(Debug)]
pub struct Process {
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
    /// Process umask
    pub umask: usize,
    /// Context is being waited on
    pub waitpid: WaitMap<WaitpidKey, (ProcessId, usize)>,
    pub threads: Vec<Weak<RwSpinlock<Context>>>,
}

pub static PROCESSES: RwLock<BTreeMap<ProcessId, Arc<RwLock<Process>>>> = RwLock::new(BTreeMap::new());

/// Get an iterator of all parents
pub fn ancestors(
    list: &BTreeSet<Process>,
    id: ProcessId,
) -> impl Iterator<Item = (ProcessId, &Arc<RwSpinlock<Context>>)> + '_ {
    core::iter::successors(
        list.get(&id).map(|process| (id, process)),
        move |(_id, process)| {
            let context = process.read();
            let id = process.ppid;
            list.get(&id).map(|context| (id, context))
        },
    )
}

impl Ord for Process {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        Ord::cmp(&self.pid, &other.pid)
    }
}
impl PartialOrd for Process {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(Ord::cmp(&self.pid, &other.pid))
    }
}

pub fn current() -> Result<Arc<RwLock<Process>>> {
    let pid = context::current()?.read().pid;
    PROCESSES.read().get(&pid).ok_or(Error::new(ESRCH))
}
impl PartialEq for Process {
    fn eq(&self, other: &Self) -> bool {
        Ord::cmp(self, other) == core::cmp::Ordering::Equal
    }
}
impl Eq for Process {}
