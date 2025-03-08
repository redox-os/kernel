use core::{cmp::Ordering, fmt::Debug, mem::swap};

use alloc::{
    string::String,
    sync::{Arc, Weak},
    vec::Vec,
};
use spin::RwLock;

use crate::cpu_set::{parts, LogicalCpuId, LogicalCpuSet, RawMask};

use super::virtual_time::VirtualTime;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RequestTimings {
    pub eligible: VirtualTime,
    pub deadline: VirtualTime,
    pub affinity: RawMask,
}

#[cfg(test)]
impl RequestTimings {
    pub fn new(eligible: f64, deadline: f64) -> Self {
        Self {
            eligible: VirtualTime::new(eligible),
            deadline: VirtualTime::new(deadline),
            affinity: LogicalCpuSet::all().to_raw(),
        }
    }

    pub fn new_with_affinity(eligible: f64, deadline: f64, affinity: [usize; 2]) -> Self {
        Self {
            affinity,
            ..Self::new(eligible, deadline)
        }
    }
}

impl Default for RequestTimings {
    fn default() -> Self {
        Self {
            eligible: VirtualTime::new(0.0),
            deadline: VirtualTime::new(0.0),
            affinity: LogicalCpuSet::all().to_raw(),
        }
    }
}

impl PartialOrd for RequestTimings {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RequestTimings {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.eligible.cmp(&other.eligible) {
            Ordering::Equal => self.deadline.cmp(&other.deadline).reverse(),
            res => res,
        }
    }
}

pub struct RequestNode<T> {
    pub contexts: Vec<T>,
    timings: RequestTimings,
    height: u8,
    left: Option<NodeHandle<T>>,
    right: Option<NodeHandle<T>>,
    min_deadline: Vec<(RawMask, VirtualTime)>,
}
pub type NodeHandle<T> = Arc<RwLock<RequestNode<T>>>;
pub type NodeHandleRef<T> = Weak<RwLock<RequestNode<T>>>;

impl<T> RequestNode<T> {
    pub fn new(data: T, timings: RequestTimings) -> NodeHandle<T> {
        Arc::new(RwLock::new(Self {
            contexts: vec![data],
            timings,
            height: 1,
            left: None,
            right: None,
            min_deadline: vec![(timings.affinity, timings.deadline)],
        }))
    }
}

impl<T> Debug for RequestNode<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Node: eligible: {}, deadline: {}, height: {}",
            self.timings.eligible, self.timings.deadline, self.height
        )
    }
}

pub trait NodeExt<T> {
    fn affinity(&self) -> Option<RawMask>;
    fn append_context(&self, data: T);
    fn balance(&self) -> i8;
    fn deadline(&self) -> Option<VirtualTime>;
    fn eligible(&self) -> Option<VirtualTime>;
    fn height(&self) -> u8;
    fn is_eligible(&self, cpu_id: LogicalCpuId, current_time: VirtualTime) -> bool;
    fn left(&self) -> Option<NodeHandle<T>>;
    fn min_deadline(&self, cpu_id: LogicalCpuId) -> Option<VirtualTime>;
    fn min_eligible(&self) -> Option<VirtualTime>;
    fn nb_nodes(&self) -> u64;
    fn num_contexts(&self) -> usize;
    fn right(&self) -> Option<NodeHandle<T>>;
    fn set_left(&self, left: Option<NodeHandle<T>>);
    fn set_right(&self, right: Option<NodeHandle<T>>);
    fn shrink_data(&self);
    fn timings(&self) -> Option<RequestTimings>;
    fn to_string(&self, depth: usize) -> String;
    fn update_deadline(&self);
    fn update_height(&self);
}

impl<T> NodeExt<T> for &NodeHandle<T> {
    fn affinity(&self) -> Option<RawMask> {
        Some(self.read().timings.affinity)
    }

    fn append_context(&self, data: T) {
        self.write().contexts.push(data);
    }

    fn balance(&self) -> i8 {
        let left_height = self
            .read()
            .left
            .as_ref()
            .map_or(0, |left| left.read().height);
        let right_height = self
            .read()
            .right
            .as_ref()
            .map_or(0, |right| right.read().height);

        if left_height >= right_height {
            (left_height - right_height) as i8
        } else {
            -((right_height - left_height) as i8)
        }
    }

    fn deadline(&self) -> Option<VirtualTime> {
        Some(self.read().timings.deadline)
    }

    fn eligible(&self) -> Option<VirtualTime> {
        Some(self.read().timings.eligible)
    }

    fn height(&self) -> u8 {
        self.read().height
    }

    fn is_eligible(&self, cpu_id: LogicalCpuId, current_time: VirtualTime) -> bool {
        let (word, bit) = parts(cpu_id);
        let affinity = self.read().timings.affinity;
        affinity[word] & (1 << bit) != 0 && current_time >= self.read().timings.eligible
    }

    fn left(&self) -> Option<NodeHandle<T>> {
        self.read().left.clone()
    }

    fn min_deadline(&self, cpu_id: LogicalCpuId) -> Option<VirtualTime> {
        let mut res = VirtualTime::new(f64::MAX);
        let (word, bit) = parts(cpu_id);
        for (affinity, min_deadline) in self.write().min_deadline.iter() {
            if affinity[word] & (1 << bit) != 0 && *min_deadline < res {
                res = *min_deadline;
            }
        }
        Some(res)
    }

    fn min_eligible(&self) -> Option<VirtualTime> {
        Some(
            match (
                self.read().timings.eligible,
                self.left().min_eligible(),
                self.right().min_eligible(),
            ) {
                (s, None, None) => s,
                (s, Some(l), Some(r)) => {
                    if s < l && s < r {
                        s
                    } else if l < r {
                        l
                    } else {
                        r
                    }
                }
                (s, None, Some(r)) => {
                    if s < r {
                        s
                    } else {
                        r
                    }
                }
                (s, Some(l), None) => {
                    if s < l {
                        s
                    } else {
                        l
                    }
                }
            },
        )
    }

    fn nb_nodes(&self) -> u64 {
        1 + self.left().nb_nodes() + self.right().nb_nodes()
    }

    fn num_contexts(&self) -> usize {
        self.read().contexts.len()
    }

    fn right(&self) -> Option<NodeHandle<T>> {
        self.read().right.clone()
    }

    fn set_left(&self, left: Option<NodeHandle<T>>) {
        self.write().left = left;
    }

    fn set_right(&self, right: Option<NodeHandle<T>>) {
        self.write().right = right;
    }

    fn shrink_data(&self) {
        self.write().contexts.remove(0);
    }

    fn timings(&self) -> Option<RequestTimings> {
        Some(self.read().timings)
    }

    fn to_string(&self, depth: usize) -> String {
        let tab = vec!["  "; depth + 1].join("");
        let mut res = format!(
            "Request: eligible: {}, deadline: {}, height: {}, contexts: {} (min deadline: {})",
            self.eligible().unwrap_or_default(),
            self.deadline().unwrap_or_default(),
            self.height(),
            self.num_contexts(),
            self.read()
                .min_deadline
                .iter()
                .map(|(set, deadline)| {
                    let mut affinity = LogicalCpuSet::empty();
                    affinity.override_from(set);
                    format!("{affinity:?} => {deadline}")
                })
                .collect::<Vec<_>>()
                .join(", "),
        );
        if let Some(left) = &self.left() {
            res = format!("{res}\n{tab}- Left: {}", left.to_string(depth + 1));
        }
        if let Some(right) = &self.right() {
            res = format!("{res}\n{tab}- Right: {}", right.to_string(depth + 1));
        }
        res
    }

    fn update_deadline(&self) {
        let mut res = vec![(self.read().timings.affinity, self.read().timings.deadline)];
        if let Some(right_md) = self.right().map(|node| node.read().min_deadline.clone()) {
            for (mask, deadline) in right_md {
                if res[0].0 == mask {
                    if deadline < res[0].1 {
                        res[0].1 = deadline;
                    }
                } else {
                    res.push((mask, deadline));
                }
            }
        }

        if let Some(left_md) = self.left().map(|node| node.read().min_deadline.clone()) {
            for (mask, deadline) in left_md {
                if let Some(idx) = res.iter().position(|(mask2, _deadline)| mask == *mask2) {
                    if deadline < res[idx].1 {
                        res[idx].1 = deadline;
                    }
                } else {
                    res.push((mask, deadline));
                }
            }
        }
        self.write().min_deadline = res;
    }

    fn update_height(&self) {
        let height = 1 + u8::max(
            self.read()
                .right
                .as_ref()
                .map_or(0, |node| node.read().height),
            self.read()
                .left
                .as_ref()
                .map_or(0, |node| node.read().height),
        );
        self.write().height = height;
    }
}

impl<T> NodeExt<T> for Option<&NodeHandle<T>> {
    fn affinity(&self) -> Option<RawMask> {
        self.and_then(|node| node.affinity())
    }

    fn append_context(&self, data: T) {
        if let Some(node) = self {
            node.append_context(data);
        }
    }

    fn balance(&self) -> i8 {
        self.map_or(0, |node| node.balance())
    }

    fn deadline(&self) -> Option<VirtualTime> {
        self.and_then(|node| node.deadline())
    }

    fn eligible(&self) -> Option<VirtualTime> {
        self.and_then(|node| node.eligible())
    }

    fn height(&self) -> u8 {
        self.map_or(0, |node| node.height())
    }

    fn is_eligible(&self, cpu_id: LogicalCpuId, current_time: VirtualTime) -> bool {
        self.map_or(false, |node| node.is_eligible(cpu_id, current_time))
    }

    fn left(&self) -> Option<NodeHandle<T>> {
        self.and_then(|node| node.left())
    }

    fn min_eligible(&self) -> Option<VirtualTime> {
        self.and_then(|node| node.min_eligible())
    }

    fn min_deadline(&self, cpu_id: LogicalCpuId) -> Option<VirtualTime> {
        self.and_then(|node| node.min_deadline(cpu_id))
    }

    fn nb_nodes(&self) -> u64 {
        self.map_or(0, |node| node.nb_nodes())
    }

    fn num_contexts(&self) -> usize {
        self.map_or(0, |node| node.num_contexts())
    }

    fn right(&self) -> Option<NodeHandle<T>> {
        self.and_then(|node| node.right())
    }

    fn set_left(&self, left: Option<NodeHandle<T>>) {
        if let Some(node) = self {
            node.set_left(left);
        }
    }

    fn set_right(&self, right: Option<NodeHandle<T>>) {
        if let Some(node) = self {
            node.set_right(right);
        }
    }

    fn shrink_data(&self) {
        if let Some(node) = self {
            node.shrink_data();
        }
    }

    fn timings(&self) -> Option<RequestTimings> {
        self.and_then(|node| node.timings())
    }

    fn to_string(&self, depth: usize) -> String {
        self.map_or_else(|| String::new(), |node| node.to_string(depth))
    }

    fn update_deadline(&self) {
        if let Some(node) = self {
            node.update_deadline();
        }
    }

    fn update_height(&self) {
        if let Some(node) = self {
            node.update_height();
        }
    }
}

impl<T> NodeExt<T> for Option<NodeHandle<T>> {
    fn affinity(&self) -> Option<RawMask> {
        self.as_ref().and_then(|node| node.affinity())
    }

    fn append_context(&self, data: T) {
        if let Some(node) = self {
            node.append_context(data);
        }
    }

    fn balance(&self) -> i8 {
        self.as_ref().map_or(0, |node| node.balance())
    }

    fn deadline(&self) -> Option<VirtualTime> {
        self.as_ref().and_then(|node| node.deadline())
    }

    fn eligible(&self) -> Option<VirtualTime> {
        self.as_ref().and_then(|node| node.eligible())
    }

    fn height(&self) -> u8 {
        self.as_ref().map_or(0, |node| node.height())
    }

    fn is_eligible(&self, cpu_id: LogicalCpuId, current_time: VirtualTime) -> bool {
        self.as_ref()
            .map_or(false, |node| node.is_eligible(cpu_id, current_time))
    }

    fn left(&self) -> Option<NodeHandle<T>> {
        self.as_ref().and_then(|node| node.left())
    }

    fn min_eligible(&self) -> Option<VirtualTime> {
        self.as_ref().and_then(|node| node.min_eligible())
    }

    fn min_deadline(&self, cpu_id: LogicalCpuId) -> Option<VirtualTime> {
        self.as_ref().and_then(|node| node.min_deadline(cpu_id))
    }

    fn nb_nodes(&self) -> u64 {
        self.as_ref().map_or(0, |node| node.nb_nodes())
    }

    fn num_contexts(&self) -> usize {
        self.as_ref().map_or(0, |node| node.num_contexts())
    }

    fn right(&self) -> Option<NodeHandle<T>> {
        self.as_ref().and_then(|node| node.right())
    }

    fn set_left(&self, left: Option<NodeHandle<T>>) {
        if let Some(node) = self {
            node.set_left(left);
        }
    }

    fn set_right(&self, right: Option<NodeHandle<T>>) {
        if let Some(node) = self {
            node.set_right(right);
        }
    }

    fn shrink_data(&self) {
        if let Some(node) = self {
            node.shrink_data();
        }
    }

    fn timings(&self) -> Option<RequestTimings> {
        self.as_ref().and_then(|node| node.timings())
    }

    fn to_string(&self, depth: usize) -> String {
        self.as_ref()
            .map_or_else(|| String::new(), |node| node.to_string(depth))
    }

    fn update_deadline(&self) {
        if let Some(node) = self {
            node.update_deadline();
        }
    }

    fn update_height(&self) {
        if let Some(node) = self {
            node.update_height();
        }
    }
}

pub fn swap_nodes<T>(node1: &NodeHandle<T>, node2: &NodeHandle<T>) {
    swap(
        &mut node1.as_ref().write().contexts,
        &mut node2.as_ref().write().contexts,
    );
    swap(
        &mut node1.as_ref().write().timings,
        &mut node2.as_ref().write().timings,
    );
    swap(
        &mut node1.as_ref().write().min_deadline,
        &mut node2.as_ref().write().min_deadline,
    );
}
