use super::METRICS;
use std::time::Instant;

pub struct SessionTracker {
    protocol: &'static str,
    started_at: Instant,
}

pub fn track_session(protocol: &'static str) -> SessionTracker {
    METRICS.sessions_active.with_label_values(&[protocol]).inc();
    SessionTracker { protocol, started_at: Instant::now() }
}

impl SessionTracker {
    pub fn finish(self, success: bool) {
        let elapsed = self.started_at.elapsed().as_secs_f64();
        METRICS.sessions_active.with_label_values(&[self.protocol]).dec();
        METRICS
            .session_duration_seconds
            .with_label_values(&[self.protocol, if success { "success" } else { "error" }])
            .observe(elapsed);
    }
}
