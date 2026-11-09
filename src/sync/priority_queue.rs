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
