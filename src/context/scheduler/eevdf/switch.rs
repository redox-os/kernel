#![allow(dead_code, unused_imports)]

use core::sync::atomic::{AtomicU64, Ordering};

use alloc::sync::Arc;
use spin::{Lazy, RwLock};
use spinning_top::RwSpinlock;

use crate::{
    context::{scheduler::SwitchResult, Context, ContextRef},
    cpu_set::LogicalCpuId,
    percpu::PercpuBlock,
};

use super::request_tree::RequestTree;

static REQUEST_TREE: Lazy<Arc<RwLock<RequestTree<ContextRef>>>> =
    Lazy::new(|| Arc::new(RwLock::new(RequestTree::new())));
static VIRTUAL_TIME: AtomicU64 = AtomicU64::new(0);

pub fn switch() -> SwitchResult {
    SwitchResult::AllContextsIdle
}
