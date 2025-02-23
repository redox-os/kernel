//! Implementation of the EEVDF Request Tree.
//!
//! The EEVDF algorithm has been introduced in "Earliest Eligible Virtual
//! Deadline First: A Flexible and Accurate Mechanism for Proportional Share Resource Allocation"
//! by Ion Stoica and Hussein Abled-Wahab which can be found here:
//! https://citeseerx.ist.psu.edu/document?repid=rep1&type=pdf&doi=805acf7726282721504c8f00575d91ebfd750564
//!
//! The implementation has been slightly modified to allow multiple contexts to
//! have the same eligible and deadline

use core::{
    cmp::Ordering,
    fmt::{self, Debug, Formatter},
};

use alloc::sync::{Arc, Weak};

use crate::cpu_set::LogicalCpuId;

use super::{
    request_node::{swap_nodes, NodeExt, NodeHandle, RequestNode, RequestTimings},
    NodeHandleRef,
};

pub struct RequestTree<T: Ord + Clone> {
    root: Option<NodeHandle<T>>,
}

impl<T: Ord + Clone> RequestTree<T> {
    pub const fn new() -> Self {
        Self { root: None }
    }

    pub fn min_deadline(&self, cpu_id: LogicalCpuId) -> Option<u64> {
        self.root.as_ref().min_deadline(cpu_id)
    }

    pub fn get_first_eligible(&self, cpu_id: LogicalCpuId, current_time: u64) -> Option<T> {
        log::debug!("looking at time {current_time} for CPU {}", cpu_id.get());
        let Some(target) = self.root.min_deadline(cpu_id) else {
            return None;
        };
        get_first_eligible(self.root.as_ref(), cpu_id, current_time, target)
            .and_then(|t| t.read().data.first().cloned())
    }

    pub fn insert(&mut self, data: T, timings: RequestTimings) -> NodeHandleRef<T> {
        log::debug!("inserting {timings:?}");
        let mut data_node = Weak::new();
        self.root = Some(insert(self.root.as_ref(), data, timings, &mut data_node));
        data_node
    }

    pub fn remove(&mut self, node: &NodeHandle<T>, data: T) {
        let empty = {
            let mut node = node.write();
            let Some(idx) = node
                .data
                .iter()
                .position(|ctx| ctx.cmp(&data) == Ordering::Equal)
            else {
                log::warn!("data not found in node, can’t remove");
                return;
            };
            node.data.remove(idx);
            node.data.is_empty()
        };
        if empty {
            self.remove_node(node);
        }
    }

    fn remove_node(&mut self, target: &NodeHandle<T>) {
        let root = self.root.clone();
        remove(root.as_ref(), target);
    }
}

fn get_first_eligible<T>(
    root: Option<&NodeHandle<T>>,
    cpu_id: LogicalCpuId,
    current_time: u64,
    target: u64,
) -> Option<NodeHandle<T>> {
    log::debug!("searching through {root:?} (target = {target})");
    if root.is_none() {
        return None;
    }
    if root.is_eligible(cpu_id, current_time) && Some(target) == root.eligible() {
        log::debug!("found the min target: {root:?}");
        return root.cloned();
    }

    let mut selection = if root.is_eligible(cpu_id, current_time) {
        log::debug!(".. root is eligible, we’ll take it if nothing better");
        root.cloned()
    } else {
        log::debug!(".. root is not eligible don’t keep it");
        None
    };

    if selection.min_deadline(cpu_id) <= root.left().min_deadline(cpu_id) {
        let best_left = get_first_eligible(root.left().as_ref(), cpu_id, current_time, target);
        log::debug!(".. best_left: {best_left:?}");
        if best_left.is_some() {
            if selection.is_none() || best_left.deadline() < root.deadline() {
                log::debug!("left node {best_left:?} is better than {root:?}");
                selection = best_left;
            }
        }
    }

    if root.eligible() <= Some(current_time)
        && root.right().min_deadline(cpu_id) >= selection.min_deadline(cpu_id)
    {
        let best_right = get_first_eligible(root.right().as_ref(), cpu_id, current_time, target);
        log::debug!(".. best_right: {best_right:?}");
        if best_right.is_some() {
            if selection.is_none() || best_right.deadline() < root.deadline() {
                log::debug!("right node {best_right:?} is better than {root:?}");
                selection = best_right;
            }
        }
    }

    log::debug!("best child of {root:?} is {selection:?}");
    selection
}

fn insert<T>(
    root: Option<&NodeHandle<T>>,
    data: T,
    timings: RequestTimings,
    data_node: &mut NodeHandleRef<T>,
) -> NodeHandle<T> {
    log::debug!("current node: {root:?}");
    let Some(root) = root else {
        let new_node = RequestNode::new(data, timings);
        *data_node = Arc::downgrade(&new_node);
        return new_node;
    };

    let node_timings = root.timings().unwrap();
    if timings < node_timings {
        root.set_left(Some(insert(root.left().as_ref(), data, timings, data_node)));
    } else if timings > node_timings {
        root.set_right(Some(insert(
            root.right().as_ref(),
            data,
            timings,
            data_node,
        )));
    } else {
        *data_node = Arc::downgrade(&root);
        root.append_data(data);
        return root.clone();
    }

    root.update_height();
    root.update_deadline();
    balance(Some(root)).unwrap()
}

fn remove<T>(root: Option<&NodeHandle<T>>, target: &NodeHandle<T>) -> Option<NodeHandle<T>> {
    if root.is_none() {
        return None;
    }

    if target.timings() < root.timings() {
        root.set_left(remove(root.left().as_ref(), target));
    } else if target.eligible() > root.eligible() {
        root.set_right(remove(root.right().as_ref(), target));
    } else {
        if root.data_len() > 1 {
            root.shrink_data();
            return root.cloned();
        }
        if root.left().is_none() {
            return root.right();
        }
        if root.right().is_none() {
            return root.left();
        }
        let successor = get_min(root.right().as_ref());
        swap_nodes(&root.unwrap(), &successor);
        root.set_right(remove(root.right().as_ref(), &successor));
    }

    if root.is_none() {
        return root.cloned();
    }

    root.update_height();
    root.update_deadline();
    balance(root)
}

fn balance<T>(node: Option<&NodeHandle<T>>) -> Option<NodeHandle<T>> {
    let equilibrium = node.balance();
    if equilibrium > 1 {
        if node.left().balance() >= 0 {
            return right_rotation(node);
        } else {
            node.set_left(balance(node.left().as_ref()));
            return right_rotation(node);
        }
    }
    if equilibrium < -1 {
        if node.right().balance() <= 0 {
            return left_rotation(node);
        } else {
            node.set_right(balance(node.right().as_ref()));
            return left_rotation(node);
        }
    }
    node.cloned()
}

fn get_min<T>(node: Option<&NodeHandle<T>>) -> NodeHandle<T> {
    let mut node = node.cloned();
    while let Some(left) = node.as_ref().left() {
        node = Some(left);
    }
    node.unwrap()
}

fn left_rotation<T>(node: Option<&NodeHandle<T>>) -> Option<NodeHandle<T>> {
    let old_right = node.right();
    let old_right_left = old_right.left();

    old_right.set_left(node.cloned());
    node.set_right(old_right_left);

    node.update_deadline();
    old_right.update_deadline();
    node.update_height();
    old_right.update_height();

    old_right
}

fn right_rotation<T>(node: Option<&NodeHandle<T>>) -> Option<NodeHandle<T>> {
    let old_left = node.left();
    let old_left_right = old_left.right();

    old_left.set_right(node.cloned());
    node.set_left(old_left_right);

    node.update_deadline();
    old_left.update_deadline();
    node.update_height();
    old_left.update_height();

    old_left
}

impl<T: Ord + Clone> Debug for RequestTree<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "tree:\n{}", self.root.to_string(0))
    }
}

#[cfg(test)]
mod tests {
    use test_log::test;

    use crate::{
        context::scheduler::eevdf::request_node::RequestTimings,
        cpu_set::{LogicalCpuId, LogicalCpuSet},
    };

    use super::*;

    #[test]
    fn create_tree() {
        // Given
        let request1 = RequestTimings::new(10, 25);

        let mut tree = RequestTree::<()>::new();

        // When
        tree.insert((), request1);

        // Then
        assert_eq!(tree.root.timings(), Some(request1));
        assert_eq!(tree.min_deadline(LogicalCpuId::new(0)), Some(25));
    }

    #[test]
    fn insert_one_node_updates_min_deadline() {
        // Given
        let root = RequestTimings::new(10, 25);
        let request2 = RequestTimings::new(7, 18);

        let mut tree = RequestTree::<()>::new();
        tree.insert((), root);

        // When
        tree.insert((), request2);

        // Then
        assert_eq!(tree.min_deadline(LogicalCpuId::new(0)), Some(18));
        assert_eq!(
            tree.root.left().min_deadline(LogicalCpuId::new(0)),
            Some(18)
        );
        assert_eq!(tree.root.left().timings(), Some(request2));
    }

    #[test]
    fn insert_two_nodes_updates_min_deadline() {
        // Given
        let request1 = RequestTimings::new(10, 25);
        let request2 = RequestTimings::new(7, 18);
        let request3 = RequestTimings::new(14, 15);

        let mut tree = RequestTree::<()>::new();
        tree.insert((), request1);

        // When
        tree.insert((), request2);
        tree.insert((), request3);

        log::info!("{tree:?}");

        // Then
        assert_eq!(tree.root.min_deadline(LogicalCpuId::new(0)), Some(15));
        assert_eq!(
            tree.root.left().min_deadline(LogicalCpuId::new(0)),
            Some(18)
        );
        assert_eq!(tree.root.left().timings(), Some(request2));
        assert_eq!(tree.root.right().timings(), Some(request3));
    }

    #[test]
    fn get_first_eligible() {
        // Given
        let request1 = RequestTimings::new(3, 20);
        let request2 = RequestTimings::new(7, 18);
        let request3 = RequestTimings::new(8, 15);
        let request4 = RequestTimings::new(10, 25);
        let request5 = RequestTimings::new(11, 17);
        let request6 = RequestTimings::new(14, 20);

        let mut tree = RequestTree::<RequestTimings>::new();

        tree.insert(request1, request1);
        tree.insert(request2, request2);
        tree.insert(request3, request3);
        tree.insert(request4, request4);
        tree.insert(request5, request5);
        tree.insert(request6, request6);

        log::info!("{:?}", tree);

        // When
        let selected = tree.get_first_eligible(LogicalCpuId::new(0), 7);
        let selected_late = tree.get_first_eligible(LogicalCpuId::new(0), 10);
        let selected_early = tree.get_first_eligible(LogicalCpuId::new(0), 5);

        // Then
        assert_eq!(selected, Some(request2));
        assert_eq!(selected_late, Some(request3));
        assert_eq!(selected_early, Some(request1));
    }

    #[test]
    fn empty_tree() {
        // Given
        let tree = RequestTree::<()>::new();

        // When
        let selected = tree.get_first_eligible(LogicalCpuId::new(0), 8);

        // Then
        assert!(selected.is_none());
    }

    #[test]
    fn timings_after_remove() {
        // Given
        let request1 = RequestTimings::new(10, 25);
        let request2 = RequestTimings::new(7, 18);
        let request3 = RequestTimings::new(14, 20);
        let request4 = RequestTimings::new(3, 20);
        let request5 = RequestTimings::new(8, 15);
        let request6 = RequestTimings::new(11, 17);

        let mut tree = RequestTree::<()>::new();

        tree.insert((), request1);
        tree.insert((), request2);
        tree.insert((), request3);
        tree.insert((), request4);
        tree.insert((), request5);
        tree.insert((), request6);

        log::warn!("tree: {tree:?}");

        // When
        tree.remove(&tree.root.left().right().unwrap(), ());
        log::warn!("post remove: {:?}", tree);
        // Then
        assert_eq!(tree.root.min_deadline(LogicalCpuId::new(0)), Some(17));
    }

    #[test]
    fn delete_request_with_two_children() {
        // Given
        let request1 = RequestTimings::new(10, 25);
        let request2 = RequestTimings::new(7, 18);
        let request3 = RequestTimings::new(14, 20);
        let request4 = RequestTimings::new(3, 20);
        let request5 = RequestTimings::new(8, 15);
        let request6 = RequestTimings::new(11, 17);

        let mut tree = RequestTree::<()>::new();

        tree.insert((), request1);
        tree.insert((), request2);
        tree.insert((), request3);
        tree.insert((), request4);
        tree.insert((), request5);
        tree.insert((), request6);
        log::warn!("tree: {:?}", tree);

        // When
        tree.remove(&tree.root.left().unwrap(), ());
        log::warn!("post remove: {:?}", tree);

        // Then
        assert_eq!(tree.root.min_deadline(LogicalCpuId::new(0)), Some(15));
        assert_eq!(tree.root.left().timings(), Some(request5));
        assert_eq!(tree.root.left().left().timings(), Some(request4));
        // right side is not touched
        assert_eq!(tree.root.right().timings(), Some(request3));
    }

    #[test]
    fn delete_two_requests() {
        // Given
        let request1 = RequestTimings::new(10, 25);
        let request2 = RequestTimings::new(7, 18);
        let request3 = RequestTimings::new(14, 20);
        let request4 = RequestTimings::new(3, 20);
        let request5 = RequestTimings::new(8, 15);
        let request6 = RequestTimings::new(11, 17);

        let mut tree = RequestTree::<()>::new();

        tree.insert((), request1);
        tree.insert((), request2);
        tree.insert((), request3);
        tree.insert((), request4);
        tree.insert((), request5);
        tree.insert((), request6);
        log::warn!("tree: {:?}", tree);
        tree.remove(&tree.root.left().unwrap(), ());
        log::warn!("First remove: {:?}", tree);

        // When
        tree.remove(&tree.root.left().unwrap(), ());
        log::warn!("Second remove: {:?}", tree);

        // Then
        assert_eq!(tree.root.min_deadline(LogicalCpuId::new(0)), Some(17));
        assert_eq!(tree.root.left().timings(), Some(request4));
        // right side is not touched
        assert_eq!(tree.root.right().timings(), Some(request3));

        // Check heights
        assert_eq!(tree.root.height(), 3);
        assert_eq!(tree.root.left().height(), 1);
        assert_eq!(tree.root.right().height(), 2);
    }

    #[test]
    fn delete_root() {
        // Given
        let request1 = RequestTimings::new(10, 25);
        let request2 = RequestTimings::new(7, 8);
        let request3 = RequestTimings::new(14, 20);
        let request4 = RequestTimings::new(3, 0);
        let request5 = RequestTimings::new(8, 5);
        let request6 = RequestTimings::new(11, 17);

        let mut tree = RequestTree::<()>::new();

        tree.insert((), request1);
        tree.insert((), request2);
        tree.insert((), request3);
        tree.insert((), request4);
        tree.insert((), request5);
        tree.insert((), request6);

        // When
        tree.remove(&tree.root.clone().unwrap(), ());
        log::warn!("After remove: {:?}", tree);

        // Then
        assert_eq!(tree.root.timings(), Some(request6));
        assert_eq!(tree.root.right().timings(), Some(request3));
        assert_eq!(tree.root.left().timings(), Some(request2));
    }

    #[test]
    fn check_height() {
        // Given
        let request1 = RequestTimings::new(10, 25);
        let request2 = RequestTimings::new(7, 18);
        let request3 = RequestTimings::new(14, 20);
        let request4 = RequestTimings::new(3, 20);
        let request5 = RequestTimings::new(8, 15);
        let request6 = RequestTimings::new(11, 17);

        // When
        let mut tree = RequestTree::<()>::new();
        tree.insert((), request1);
        tree.insert((), request2);
        tree.insert((), request3);
        tree.insert((), request4);
        tree.insert((), request5);
        tree.insert((), request6);

        // Then
        assert_eq!(tree.root.height(), 3);
        assert_eq!(tree.root.left().height(), 2);
        assert_eq!(tree.root.left().left().height(), 1);
        assert_eq!(tree.root.left().right().height(), 1);
        assert_eq!(tree.root.right().height(), 2);
        assert_eq!(tree.root.right().left().height(), 1);
    }

    #[test]
    fn get_first_with_affinity() {
        // Given

        // request 5 is reserved to CPU1, others can run anywhere
        let affinity1 = LogicalCpuSet::all();
        let affinity2 = LogicalCpuSet::all();
        let affinity3 = LogicalCpuSet::all();
        let affinity4 = LogicalCpuSet::all();
        let affinity5 = LogicalCpuSet::empty();
        affinity5.atomic_set(LogicalCpuId::new(1));
        let affinity6 = LogicalCpuSet::all();

        let request1 = RequestTimings::new_with_affinity(10, 25, &affinity1);
        let request2 = RequestTimings::new_with_affinity(7, 18, &affinity2);
        let request3 = RequestTimings::new_with_affinity(14, 20, &affinity3);
        let request4 = RequestTimings::new_with_affinity(3, 20, &affinity4);
        let request5 = RequestTimings::new_with_affinity(8, 15, &affinity5);
        let request6 = RequestTimings::new_with_affinity(11, 17, &affinity6);

        let mut tree = RequestTree::<RequestTimings>::new();
        tree.insert(request1, request1);
        tree.insert(request2, request2);
        tree.insert(request3, request3);
        tree.insert(request4, request4);
        tree.insert(request5, request5);
        tree.insert(request6, request6);
        log::info!("{tree:?}");

        // When
        let eligible_cpu0 = tree.get_first_eligible(LogicalCpuId::new(0), 9);
        let eligible_cpu1 = tree.get_first_eligible(LogicalCpuId::new(1), 9);

        // Then
        assert_eq!(eligible_cpu0, Some(request2));
        assert_eq!(eligible_cpu1, Some(request5));
    }
}
