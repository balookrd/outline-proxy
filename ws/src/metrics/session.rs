use super::{METRICS, Metrics, SESSION_RECENT_MAX_SAMPLES, SESSION_RECENT_WINDOW};
use std::collections::VecDeque;
use std::time::Instant;

pub struct SessionTracker {
    protocol: &'static str,
    started_at: Instant,
}

#[derive(Default)]
pub(super) struct RecentSessionWindow {
    pub(super) samples: VecDeque<(Instant, f64)>,
}

impl Metrics {
    fn record_session_sample(&self, protocol: &'static str, duration_seconds: f64) {
        let now = Instant::now();
        let mut windows = self
            .session_recent_windows
            .lock()
            .expect("session_recent_windows lock poisoned");
        let window = windows.entry(protocol).or_default();
        window.samples.push_back((now, duration_seconds));
        prune_session_window(window, now);
        while window.samples.len() > SESSION_RECENT_MAX_SAMPLES {
            window.samples.pop_front();
        }

        self.session_recent_samples
            .with_label_values(&[protocol])
            .set(i64::try_from(window.samples.len()).unwrap_or(i64::MAX));
        self.session_recent_p95_seconds
            .with_label_values(&[protocol])
            .set(session_window_p95(window));
    }
}

pub fn track_session(protocol: &'static str) -> SessionTracker {
    METRICS.sessions_active.with_label_values(&[protocol]).inc();
    SessionTracker {
        protocol,
        started_at: Instant::now(),
    }
}

impl SessionTracker {
    pub fn finish(self, success: bool) {
        let elapsed = self.started_at.elapsed().as_secs_f64();
        METRICS
            .sessions_active
            .with_label_values(&[self.protocol])
            .dec();
        METRICS
            .session_duration_seconds
            .with_label_values(&[self.protocol, if success { "success" } else { "error" }])
            .observe(elapsed);
        METRICS.record_session_sample(self.protocol, elapsed);
    }
}

pub(super) fn prune_session_window(window: &mut RecentSessionWindow, now: Instant) {
    while let Some((recorded_at, _)) = window.samples.front() {
        if now.duration_since(*recorded_at) <= SESSION_RECENT_WINDOW {
            break;
        }
        window.samples.pop_front();
    }
}

pub(super) fn session_window_p95(window: &RecentSessionWindow) -> f64 {
    if window.samples.is_empty() {
        return 0.0;
    }

    let mut values: Vec<f64> = window.samples.iter().map(|(_, value)| *value).collect();
    values.sort_by(f64::total_cmp);
    let rank = ((values.len() as f64) * 0.95).ceil() as usize;
    values[rank.saturating_sub(1).min(values.len() - 1)]
}
