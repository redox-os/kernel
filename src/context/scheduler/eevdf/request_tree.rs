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
    virtual_time::VirtualTime,
    NodeHandleRef,
};

pub struct RequestTree<T: Ord + Clone> {
    root: Option<NodeHandle<T>>,
}

impl<T: Ord + Clone> RequestTree<T> {
    /// Create a new empty tree.
    pub const fn new() -> Self {
        Self { root: None }
    }

    /// Get the overall minimal deadline on a given CPU
    ///
    /// # Parameters
    /// * `cpu_id` - The CPU for which to get the minimal deadline.
    #[cfg(test)]
    pub fn min_deadline(&self, cpu_id: LogicalCpuId) -> Option<VirtualTime> {
        self.root.as_ref().min_deadline(cpu_id)
    }

    /// Get the virtual time of the first eligible context.
    ///
    /// Only use that for debugging / logging.
    pub fn min_eligible(&self) -> Option<VirtualTime> {
        self.root.as_ref().min_eligible()
    }

    /// Get the number of nodes in the tree.
    ///
    /// Only use that for debugging / logging.
    pub fn nb_nodes(&self) -> u64 {
        self.root.nb_nodes()
    }

    /// Find the node containing a context.
    ///
    /// This is done by looking for the context’s timings
    /// instead of the context itself, since the later would
    /// require to have the [`ContextRef`] which is not
    /// necessarily available.
    ///
    /// # Parameters
    /// * `Target` - The timings of the context to look for.
    fn find(&self, target: RequestTimings) -> Option<NodeHandle<T>> {
        find(self.root.as_ref(), target)
    }

    /// Get the context with the nearest deadline and with an eligible time past the current time.
    ///
    /// # Parameters
    /// * `cpu_id` - The CPU on which the context should be able to run,
    /// * `current_time` - The current virtual time.
    pub fn get_first_eligible(&self, cpu_id: LogicalCpuId, current_time: VirtualTime) -> Option<T> {
        log::debug!("looking at time {current_time} for CPU {}", cpu_id.get());
        let Some(target) = self.root.min_deadline(cpu_id) else {
            log::debug!("target is none!");
            return None;
        };
        get_first_eligible(self.root.as_ref(), cpu_id, current_time, target)
            .inspect(|node| log::debug!("found node {node:?}"))
            .and_then(|t| {
                log::debug!(
                    "target node found, with {} elements",
                    t.read().contexts.len()
                );
                t.read().contexts.first().cloned()
            })
    }

    /// Inserts a context into the tree.
    ///
    /// # Parameters
    /// * `context` - The [`ContextRef`] of the node to insert,
    /// * `timings` - The elisible and deadline of the context.
    pub fn insert(&mut self, context: T, timings: RequestTimings) -> NodeHandleRef<T> {
        log::debug!("inserting {timings:?}");
        let mut data_node = Weak::new();
        self.root = Some(insert(self.root.as_ref(), context, timings, &mut data_node));
        data_node
    }

    /// Remove a context from the tree.
    ///
    /// # Parameters
    /// * `context` - The [`ContextRef`] of the context to remove,
    /// * `timings` - The context’s timings.
    pub fn remove(&mut self, context: T, timings: RequestTimings) {
        let Some(node) = self.find(timings) else {
            log::warn!("couldn’t find a node with timings {timings:?}");
            return;
        };
        let empty = {
            let mut node = node.write();
            log::debug!("there are {} contexts in the node", node.contexts.len());
            let Some(idx) = node
                .contexts
                .iter()
                .position(|ctx| ctx.cmp(&context) == Ordering::Equal)
            else {
                log::debug!("data not found in node, can’t remove");
                return;
            };
            node.contexts.remove(idx);
            node.contexts.is_empty()
        };
        if empty {
            self.remove_node(&node);
        }
    }

    fn remove_node(&mut self, target: &NodeHandle<T>) {
        log::debug!("removing the node {target:?}");
        let root = self.root.clone();
        self.root = remove(root.as_ref(), target);
    }
}

fn find<T>(root: Option<&NodeHandle<T>>, target: RequestTimings) -> Option<NodeHandle<T>> {
    log::debug!("looking for {target:?} in {root:?}");
    if root.is_none() || root.timings() == Some(target) {
        return root.cloned();
    }

    if target < root.timings().unwrap() {
        find(root.left().as_ref(), target)
    } else {
        find(root.right().as_ref(), target)
    }
}

fn get_first_eligible<T>(
    root: Option<&NodeHandle<T>>,
    cpu_id: LogicalCpuId,
    current_time: VirtualTime,
    target: VirtualTime,
) -> Option<NodeHandle<T>> {
    log::debug!("searching through {root:?} (current_time = {current_time}, target = {target})");
    if root.is_none() {
        log::debug!("root is none, returning");
        return None;
    }
    if root.is_eligible(cpu_id, current_time) && Some(target) == root.deadline() {
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
        root.append_context(data);
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
    } else if target.timings() > root.timings() {
        root.set_right(remove(root.right().as_ref(), target));
    } else {
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
        return None;
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
        let request1 = RequestTimings::new(10.0, 25.0);

        let mut tree = RequestTree::<()>::new();

        // When
        tree.insert((), request1);

        // Then
        assert_eq!(tree.root.timings(), Some(request1));
        assert_eq!(
            tree.min_deadline(LogicalCpuId::new(0)),
            Some(VirtualTime::new(25.0))
        );
    }

    #[test]
    fn insert_one_node_updates_min_deadline() {
        // Given
        let root = RequestTimings::new(10.0, 25.0);
        let request2 = RequestTimings::new(7.0, 18.0);

        let mut tree = RequestTree::<()>::new();
        tree.insert((), root);

        // When
        tree.insert((), request2);

        // Then
        assert_eq!(
            tree.min_deadline(LogicalCpuId::new(0)),
            Some(VirtualTime::new(18.0))
        );
        assert_eq!(
            tree.root.left().min_deadline(LogicalCpuId::new(0)),
            Some(VirtualTime::new(18.0))
        );
        assert_eq!(tree.root.left().timings(), Some(request2));
    }

    #[test]
    fn insert_two_nodes_updates_min_deadline() {
        // Given
        let request1 = RequestTimings::new(10.0, 25.0);
        let request2 = RequestTimings::new(7.0, 18.0);
        let request3 = RequestTimings::new(14.0, 15.0);

        let mut tree = RequestTree::<()>::new();
        tree.insert((), request1);

        // When
        tree.insert((), request2);
        tree.insert((), request3);

        log::info!("{tree:?}");

        // Then
        assert_eq!(
            tree.root.min_deadline(LogicalCpuId::new(0)),
            Some(VirtualTime::new(15.0))
        );
        assert_eq!(
            tree.root.left().min_deadline(LogicalCpuId::new(0)),
            Some(VirtualTime::new(18.0))
        );
        assert_eq!(tree.root.left().timings(), Some(request2));
        assert_eq!(tree.root.right().timings(), Some(request3));
    }

    #[test]
    fn get_first_eligible() {
        // Given
        let request1 = RequestTimings::new(3.0, 20.0);
        let request2 = RequestTimings::new(7.0, 18.0);
        let request3 = RequestTimings::new(8.0, 15.0);
        let request4 = RequestTimings::new(10.0, 25.0);
        let request5 = RequestTimings::new(11.0, 17.0);
        let request6 = RequestTimings::new(14.0, 20.0);

        let mut tree = RequestTree::<RequestTimings>::new();

        tree.insert(request1, request1);
        tree.insert(request2, request2);
        tree.insert(request3, request3);
        tree.insert(request4, request4);
        tree.insert(request5, request5);
        tree.insert(request6, request6);

        log::info!("{:?}", tree);

        // When
        let selected = tree.get_first_eligible(LogicalCpuId::new(0), VirtualTime::new(7.0));
        let selected_late = tree.get_first_eligible(LogicalCpuId::new(0), VirtualTime::new(10.0));
        let selected_early = tree.get_first_eligible(LogicalCpuId::new(0), VirtualTime::new(5.0));

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
        let selected = tree.get_first_eligible(LogicalCpuId::new(0), VirtualTime::new(8.0));

        // Then
        assert!(selected.is_none());
    }

    #[test]
    fn timings_after_remove() {
        // Given
        let request1 = RequestTimings::new(10.0, 25.0);
        let request2 = RequestTimings::new(7.0, 18.0);
        let request3 = RequestTimings::new(14.0, 20.0);
        let request4 = RequestTimings::new(3.0, 20.0);
        let request5 = RequestTimings::new(8.0, 15.0);
        let request6 = RequestTimings::new(11.0, 17.0);

        let mut tree = RequestTree::<()>::new();

        tree.insert((), request1);
        tree.insert((), request2);
        tree.insert((), request3);
        tree.insert((), request4);
        tree.insert((), request5);
        tree.insert((), request6);

        log::warn!("tree: {tree:?}");

        // When
        tree.remove((), request5);
        log::warn!("post remove: {:?}", tree);
        // Then
        assert_eq!(
            tree.root.min_deadline(LogicalCpuId::new(0)),
            Some(VirtualTime::new(17.0))
        );
    }

    #[test]
    fn delete_request_with_two_children() {
        // Given
        let request1 = RequestTimings::new(10.0, 25.0);
        let request2 = RequestTimings::new(7.0, 18.0);
        let request3 = RequestTimings::new(14.0, 20.0);
        let request4 = RequestTimings::new(3.0, 20.0);
        let request5 = RequestTimings::new(8.0, 15.0);
        let request6 = RequestTimings::new(11.0, 17.0);

        let mut tree = RequestTree::<()>::new();

        tree.insert((), request1);
        tree.insert((), request2);
        tree.insert((), request3);
        tree.insert((), request4);
        tree.insert((), request5);
        tree.insert((), request6);
        log::warn!("tree: {:?}", tree);

        // When
        tree.remove((), request2);
        log::warn!("post remove: {:?}", tree);

        // Then
        assert_eq!(
            tree.root.min_deadline(LogicalCpuId::new(0)),
            Some(VirtualTime::new(15.0))
        );
        assert_eq!(tree.root.left().timings(), Some(request5));
        assert_eq!(tree.root.left().left().timings(), Some(request4));
        // right side is not touched
        assert_eq!(tree.root.right().timings(), Some(request3));
    }

    #[test]
    fn delete_two_requests() {
        // Given
        let request1 = RequestTimings::new(10.0, 25.0);
        let request2 = RequestTimings::new(7.0, 18.0);
        let request3 = RequestTimings::new(14.0, 20.0);
        let request4 = RequestTimings::new(3.0, 20.0);
        let request5 = RequestTimings::new(8.0, 15.0);
        let request6 = RequestTimings::new(11.0, 17.0);

        let mut tree = RequestTree::<()>::new();

        tree.insert((), request1);
        tree.insert((), request2);
        tree.insert((), request3);
        tree.insert((), request4);
        tree.insert((), request5);
        tree.insert((), request6);
        log::warn!("tree: {:?}", tree);
        tree.remove((), request2);
        log::warn!("First remove: {:?}", tree);

        // When
        tree.remove((), request5);
        log::warn!("Second remove: {:?}", tree);

        // Then
        assert_eq!(
            tree.root.min_deadline(LogicalCpuId::new(0)),
            Some(VirtualTime::new(17.0))
        );
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
        let request1 = RequestTimings::new(10.0, 25.0);
        let request2 = RequestTimings::new(7.0, 8.0);
        let request3 = RequestTimings::new(14.0, 20.0);
        let request4 = RequestTimings::new(3.0, 0.0);
        let request5 = RequestTimings::new(8.0, 5.0);
        let request6 = RequestTimings::new(11.0, 17.0);

        let mut tree = RequestTree::<()>::new();

        tree.insert((), request1);
        tree.insert((), request2);
        tree.insert((), request3);
        tree.insert((), request4);
        tree.insert((), request5);
        tree.insert((), request6);

        // When
        tree.remove((), request1);
        log::warn!("After remove: {:?}", tree);

        // Then
        assert_eq!(tree.root.timings(), Some(request6));
        assert_eq!(tree.root.right().timings(), Some(request3));
        assert_eq!(tree.root.left().timings(), Some(request2));
    }

    #[test]
    fn check_height() {
        // Given
        let request1 = RequestTimings::new(10.0, 25.0);
        let request2 = RequestTimings::new(7.0, 18.0);
        let request3 = RequestTimings::new(14.0, 20.0);
        let request4 = RequestTimings::new(3.0, 20.0);
        let request5 = RequestTimings::new(8.0, 15.0);
        let request6 = RequestTimings::new(11.0, 17.0);

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
        let all_affinity = LogicalCpuSet::all().to_raw();
        let one_affinity = {
            let affinity = LogicalCpuSet::empty();
            affinity.atomic_set(LogicalCpuId::new(1));
            affinity.to_raw()
        };

        let request1 = RequestTimings::new_with_affinity(10.0, 25.0, all_affinity);
        let request2 = RequestTimings::new_with_affinity(7.0, 18.0, all_affinity);
        let request3 = RequestTimings::new_with_affinity(14.0, 20.0, all_affinity);
        let request4 = RequestTimings::new_with_affinity(3.0, 20.0, all_affinity);
        let request5 = RequestTimings::new_with_affinity(8.0, 15.0, one_affinity);
        let request6 = RequestTimings::new_with_affinity(11.0, 17.0, all_affinity);

        let mut tree = RequestTree::<RequestTimings>::new();
        tree.insert(request1, request1);
        tree.insert(request2, request2);
        tree.insert(request3, request3);
        tree.insert(request4, request4);
        tree.insert(request5, request5);
        tree.insert(request6, request6);
        log::info!("{tree:?}");

        // When
        let eligible_cpu0 = tree.get_first_eligible(LogicalCpuId::new(0), VirtualTime::new(9.0));
        let eligible_cpu1 = tree.get_first_eligible(LogicalCpuId::new(1), VirtualTime::new(9.0));

        // Then
        assert_eq!(eligible_cpu0, Some(request2));
        assert_eq!(eligible_cpu1, Some(request5));
    }

    #[test]
    fn find_request() {
        // Given

        // request 5 is reserved to CPU1, others can run anywhere
        let request1 = RequestTimings::new(10.0, 25.0);
        let request2 = RequestTimings::new(7.0, 18.0);
        let request3 = RequestTimings::new(14.0, 20.0);
        let request4 = RequestTimings::new(3.0, 20.0);
        let request5 = RequestTimings::new(8.0, 15.0);
        let request6 = RequestTimings::new(11.0, 17.0);

        let mut tree = RequestTree::<RequestTimings>::new();
        tree.insert(request1, request1);
        tree.insert(request2, request2);
        tree.insert(request3, request3);
        tree.insert(request4, request4);
        tree.insert(request5, request5);
        tree.insert(request6, request6);
        log::info!("{tree:?}");

        // When
        let found1 = tree.find(request1);
        let found3 = tree.find(request3);
        let found4 = tree.find(request4);
        let found_none = tree.find(RequestTimings::new(28.0, 983.0));

        // Then
        assert_eq!(found1.timings(), Some(request1));
        assert_eq!(found3.timings(), Some(request3));
        assert_eq!(found4.timings(), Some(request4));
        assert!(found_none.is_none());
    }
}
