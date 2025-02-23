use core::{cmp::Ordering, fmt::Debug, mem::swap};

use alloc::{
    string::String,
    sync::{Arc, Weak},
    vec::Vec,
};
use spin::RwLock;

use crate::cpu_set::{parts, LogicalCpuId, LogicalCpuSet, RawMask};

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RequestTimings {
    pub eligible: u64,
    pub deadline: u64,
    pub affinity: RawMask,
}

impl RequestTimings {
    pub fn new(eligible: u64, deadline: u64) -> Self {
        Self {
            eligible,
            deadline,
            affinity: LogicalCpuSet::all().to_raw(),
        }
    }

    pub fn new_with_affinity(eligible: u64, deadline: u64, affinity: &LogicalCpuSet) -> Self {
        Self {
            affinity: affinity.to_raw(),
            ..Self::new(eligible, deadline)
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
    pub data: Vec<T>,
    timings: RequestTimings,
    height: u8,
    left: Option<NodeHandle<T>>,
    right: Option<NodeHandle<T>>,
    min_deadline: Vec<(RawMask, u64)>,
}
pub type NodeHandle<T> = Arc<RwLock<RequestNode<T>>>;
pub type NodeHandleRef<T> = Weak<RwLock<RequestNode<T>>>;

impl<T> RequestNode<T> {
    pub fn new(data: T, timings: RequestTimings) -> NodeHandle<T> {
        Arc::new(RwLock::new(Self {
            data: vec![data],
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
    fn append_data(&self, data: T);
    fn balance(&self) -> i8;
    fn data_len(&self) -> usize;
    fn deadline(&self) -> Option<u64>;
    fn eligible(&self) -> Option<u64>;
    fn height(&self) -> u8;
    fn is_eligible(&self, cpu_id: LogicalCpuId, current_time: u64) -> bool;
    fn left(&self) -> Option<NodeHandle<T>>;
    fn min_deadline(&self, cpu_id: LogicalCpuId) -> Option<u64>;
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

    fn append_data(&self, data: T) {
        self.write().data.push(data);
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

    fn data_len(&self) -> usize {
        self.read().data.len()
    }

    fn deadline(&self) -> Option<u64> {
        Some(self.read().timings.deadline)
    }

    fn eligible(&self) -> Option<u64> {
        Some(self.read().timings.eligible)
    }

    fn height(&self) -> u8 {
        self.read().height
    }

    fn is_eligible(&self, cpu_id: LogicalCpuId, current_time: u64) -> bool {
        let (word, bit) = parts(cpu_id);
        let affinity = self.read().timings.affinity;
        affinity[word] & (1 << bit) != 0 && current_time >= self.read().timings.eligible
    }

    fn left(&self) -> Option<NodeHandle<T>> {
        self.read().left.clone()
    }

    fn min_deadline(&self, cpu_id: LogicalCpuId) -> Option<u64> {
        let mut res = u64::MAX;
        let (word, bit) = parts(cpu_id);
        for (affinity, min_deadline) in self.write().min_deadline.iter_mut() {
            if affinity[word] & (1 << bit) != 0 && *min_deadline < res {
                res = *min_deadline;
            }
        }
        Some(res)
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
        self.write().data.remove(0);
    }

    fn timings(&self) -> Option<RequestTimings> {
        Some(self.read().timings)
    }

    fn to_string(&self, depth: usize) -> String {
        let tab = vec!["  "; depth + 1].join("");
        let mut res = format!(
            "Request: eligible: {}, deadline: {}, height: {} (min deadline: {})",
            self.eligible().unwrap_or_default(),
            self.deadline().unwrap_or_default(),
            self.height(),
            self.read()
                .min_deadline
                .iter()
                .map(|(set, deadline)| {
                    let mut affinity = LogicalCpuSet::empty();
                    affinity.override_from(set);
                    format!("{} => {deadline}", affinity.to_string())
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

    fn append_data(&self, data: T) {
        if let Some(node) = self {
            node.append_data(data);
        }
    }

    fn balance(&self) -> i8 {
        self.map_or(0, |node| node.balance())
    }

    fn data_len(&self) -> usize {
        self.map_or(0, |node| node.data_len())
    }

    fn deadline(&self) -> Option<u64> {
        self.and_then(|node| node.deadline())
    }

    fn eligible(&self) -> Option<u64> {
        self.and_then(|node| node.eligible())
    }

    fn height(&self) -> u8 {
        self.map_or(0, |node| node.height())
    }

    fn is_eligible(&self, cpu_id: LogicalCpuId, current_time: u64) -> bool {
        self.map_or(false, |node| node.is_eligible(cpu_id, current_time))
    }

    fn left(&self) -> Option<NodeHandle<T>> {
        self.and_then(|node| node.left())
    }

    fn min_deadline(&self, cpu_id: LogicalCpuId) -> Option<u64> {
        self.and_then(|node| node.min_deadline(cpu_id))
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

    fn append_data(&self, data: T) {
        if let Some(node) = self {
            node.append_data(data);
        }
    }

    fn balance(&self) -> i8 {
        self.as_ref().map_or(0, |node| node.balance())
    }

    fn data_len(&self) -> usize {
        self.as_ref().map_or(0, |node| node.data_len())
    }

    fn deadline(&self) -> Option<u64> {
        self.as_ref().and_then(|node| node.deadline())
    }

    fn eligible(&self) -> Option<u64> {
        self.as_ref().and_then(|node| node.eligible())
    }

    fn height(&self) -> u8 {
        self.as_ref().map_or(0, |node| node.height())
    }

    fn is_eligible(&self, cpu_id: LogicalCpuId, current_time: u64) -> bool {
        self.as_ref()
            .map_or(false, |node| node.is_eligible(cpu_id, current_time))
    }

    fn left(&self) -> Option<NodeHandle<T>> {
        self.as_ref().and_then(|node| node.left())
    }

    fn min_deadline(&self, cpu_id: LogicalCpuId) -> Option<u64> {
        self.as_ref().and_then(|node| node.min_deadline(cpu_id))
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
        &mut node1.as_ref().write().data,
        &mut node2.as_ref().write().data,
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
