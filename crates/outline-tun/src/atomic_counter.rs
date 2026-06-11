#[cfg(not(target_has_atomic = "64"))]
use std::sync::atomic::Ordering;

#[cfg(target_has_atomic = "64")]
pub(crate) type CounterU64 = std::sync::atomic::AtomicU64;

#[cfg(not(target_has_atomic = "64"))]
pub(crate) struct CounterU64(parking_lot::Mutex<u64>);

#[cfg(not(target_has_atomic = "64"))]
impl CounterU64 {
    pub(crate) fn new(value: u64) -> Self {
        Self(parking_lot::Mutex::new(value))
    }

    pub(crate) fn fetch_add(&self, value: u64, _ordering: Ordering) -> u64 {
        let mut guard = self.0.lock();
        let previous = *guard;
        *guard = previous.wrapping_add(value);
        previous
    }
}
