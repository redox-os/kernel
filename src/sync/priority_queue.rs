// We keep using VecDeque for the original FIFO behavior of the default IPC queue.
use alloc::collections::VecDeque;
// ArrayVec for priority queue. Reserving N slots the default queue cannot use.
use arrayvec::ArrayVec;

#[derive(Debug)]
pub struct PriorityQueue<T, const N: usize> {
    // The default IPC queue.
    default: VecDeque<T>,
    // Queue for prioritized calls.
    priority: ArrayVec<T, N>,
}

impl<T, const N: usize> PriorityQueue<T, N> {
    pub const fn new() -> Self {
        Self {
            default: VecDeque::new(),
            priority: ArrayVec::new_const(),
        }
    }

    pub fn len(&self) -> usize {
        self.default.len() + self.priority.len()
    }

    pub fn is_empty(&self) -> bool {
        self.default.is_empty() && self.priority.is_empty()
    }

    pub fn push_default(&mut self, value: T) {
        self.default.push_back(value);
    }

    pub fn try_push_priority(&mut self, value: T) -> Result<(), T> {
        self.priority.try_push(value).map_err(|e| e.element())
    }

    pub fn front(&self) -> &[T] {
        if !self.priority.is_empty() {
            &self.priority
        } else {
            &self.default.as_slices().0
        }
    }

    pub fn consume(&mut self, count: usize) {
        assert!(count <= self.front().len(), "Can't consume more than inspected segment.");

        if !self.priority.is_empty() {
            self.priority.drain(..count);
        } else {
            self.default.drain(..count);
        }
    }
}
