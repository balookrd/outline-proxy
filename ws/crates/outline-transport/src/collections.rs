use std::collections::{HashMap, VecDeque};
use std::hash::{BuildHasher, Hash};

const SHRINK_MIN_CAPACITY: usize = 256;

pub fn maybe_shrink_hash_map<K, V, S>(map: &mut HashMap<K, V, S>)
where
    K: Eq + Hash,
    S: BuildHasher,
{
    if should_shrink(map.len(), map.capacity()) {
        map.shrink_to_fit();
    }
}

pub fn maybe_shrink_vecdeque<T>(deque: &mut VecDeque<T>) {
    if should_shrink(deque.len(), deque.capacity()) {
        deque.shrink_to_fit();
    }
}

fn should_shrink(len: usize, capacity: usize) -> bool {
    capacity >= SHRINK_MIN_CAPACITY && len.saturating_mul(4) <= capacity
}
