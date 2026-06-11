//! Tiny duration converters shared across snapshot serialization.

use std::time::Duration;

pub(crate) fn duration_to_millis_option(value: Option<Duration>) -> Option<u128> {
    value.map(|v| v.as_millis())
}
