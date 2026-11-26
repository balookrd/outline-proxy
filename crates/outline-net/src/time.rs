//! Jittered timers and cover-traffic scheduling shared across outline crates.

use std::{pin::Pin, time::Duration};

use bytes::Bytes;
use outline_wire::padding_frames::CoverParams;
use tokio::time::{Instant, Sleep, sleep, sleep_until};

/// Shortens `period` by a fresh random share of up to 30 % (see
/// [`outline_wire::jitter::jitter_down`]).
///
/// Every loop that puts something on the wire on a timer — keepalive pings,
/// probes — sleeps for this instead of the bare interval, so the gaps between
/// its packets are not constant.
pub fn jittered_period(period: Duration) -> Duration {
    outline_wire::jitter::jitter_down(period, rand::random())
}

/// A periodic timer whose every period is shortened by a fresh random share.
///
/// The relay loops send a WebSocket Ping on a timer. `tokio::time::interval`
/// fires at an exact period, which an on-path observer can pick out of an
/// otherwise idle connection; this ticker draws each gap with
/// [`outline_wire::jitter::jitter_down`] instead. A gap is never longer than
/// the configured period, so the pong deadline and the client's read-idle
/// timeout derived from it keep their margins.
pub struct JitteredTicker {
    period: Duration,
    sleep: Pin<Box<Sleep>>,
}

impl JitteredTicker {
    /// The first tick fires after one jittered period, not immediately.
    pub fn new(period: Duration) -> Self {
        Self {
            period,
            sleep: Box::pin(sleep(jittered_period(period))),
        }
    }

    /// Completes when the current gap elapses, then arms the next one from
    /// that moment (a late poll delays the following ticks rather than
    /// bursting them). Cancel-safe: dropping the future before it completes
    /// leaves the armed deadline untouched.
    pub async fn tick(&mut self) {
        self.sleep.as_mut().await;
        self.sleep
            .as_mut()
            .reset(Instant::now() + jittered_period(self.period));
    }
}

struct CoverTimerInner {
    params: CoverParams,
    sleep: Pin<Box<Sleep>>,
}

/// Optional cover-traffic timer for WebSocket writer loops.
///
/// When cover traffic is disabled (`None`), no Tokio `Sleep` is allocated or
/// registered in the timer wheel; [`CoverTimer::wait`] simply pends forever.
pub struct CoverTimer {
    inner: Option<CoverTimerInner>,
}

impl CoverTimer {
    /// Creates a new cover timer, arming the first deadline immediately if
    /// `params` is `Some`.
    pub fn new(params: Option<CoverParams>) -> Self {
        let inner = params.map(|params| {
            let gap = params.next_gap(&mut rand::rng());
            CoverTimerInner {
                params,
                sleep: Box::pin(sleep_until(Instant::now() + gap)),
            }
        });
        Self { inner }
    }

    /// Returns `true` when cover traffic is enabled.
    pub const fn is_enabled(&self) -> bool {
        self.inner.is_some()
    }

    /// Waits until the next cover-frame deadline (or pends forever when
    /// disabled). Cancel-safe: dropping the future before completion leaves the
    /// armed deadline untouched.
    pub async fn wait(&mut self) {
        match self.inner.as_mut() {
            Some(inner) => inner.sleep.as_mut().await,
            None => std::future::pending::<()>().await,
        }
    }

    /// Rearms the deadline from `Instant::now()` using a fresh random gap.
    /// No-op when cover traffic is disabled.
    pub fn rearm(&mut self) {
        if let Some(inner) = self.inner.as_mut() {
            let gap = inner.params.next_gap(&mut rand::rng());
            inner.sleep.as_mut().reset(Instant::now() + gap);
        }
    }

    /// Generates one cover frame (`real_len = 0`), or `None` when disabled.
    pub fn frame(&self) -> Option<Bytes> {
        self.inner.as_ref().map(|inner| inner.params.frame(&mut rand::rng()))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use outline_wire::padding::{PaddingDecoder, PaddingScheme};
    use outline_wire::padding_frames::CoverParams;
    use tokio::time::Instant;

    use super::{CoverTimer, JitteredTicker};

    #[tokio::test(start_paused = true)]
    async fn gaps_stay_within_the_jitter_range_and_vary() {
        let period = Duration::from_secs(60);
        let mut ticker = JitteredTicker::new(period);
        let mut gaps = Vec::new();
        let mut last = Instant::now();
        for _ in 0..64 {
            ticker.tick().await;
            let now = Instant::now();
            gaps.push(now - last);
            last = now;
        }
        for gap in &gaps {
            assert!(*gap <= period + Duration::from_millis(1), "gap {gap:?} exceeds the period");
            assert!(*gap >= period.mul_f64(0.7), "gap {gap:?} is below the jitter floor");
        }
        gaps.sort();
        gaps.dedup();
        assert!(gaps.len() > 8, "64 ticks produced only {} distinct gaps", gaps.len());
    }

    #[tokio::test(start_paused = true)]
    async fn a_cancelled_tick_does_not_rearm_the_deadline() {
        let period = Duration::from_secs(60);
        let mut ticker = JitteredTicker::new(period);
        let start = Instant::now();
        // Poll and drop `tick()` repeatedly, as a `select!` with busier branches does.
        for _ in 0..10 {
            let _ = tokio::time::timeout(Duration::from_secs(1), ticker.tick()).await;
        }
        ticker.tick().await;
        assert!(Instant::now() - start <= period + Duration::from_millis(1));
    }

    #[tokio::test(start_paused = true)]
    async fn disabled_cover_timer_never_fires_and_emits_no_frame() {
        let mut timer = CoverTimer::new(None);
        assert!(!timer.is_enabled());
        assert!(timer.frame().is_none());
        timer.rearm();
        assert!(
            tokio::time::timeout(Duration::from_secs(3600), timer.wait())
                .await
                .is_err(),
            "disabled CoverTimer must pend forever"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn enabled_cover_timer_emits_valid_cover_frame_and_rearms() {
        let scheme = PaddingScheme::new(64, 256);
        let params = CoverParams::new(scheme, true, 100, 200).expect("cover enabled");
        let mut timer = CoverTimer::new(Some(params));
        assert!(timer.is_enabled());

        let start = Instant::now();
        timer.wait().await;
        let first_elapsed = Instant::now() - start;
        assert!(
            first_elapsed >= Duration::from_millis(100)
                && first_elapsed <= Duration::from_millis(200),
            "unexpected initial cover gap: {first_elapsed:?}"
        );

        let frame = timer.frame().expect("enabled timer should produce a frame");
        assert!(!frame.is_empty());
        let mut dec = PaddingDecoder::new();
        let mut decoded = Vec::new();
        dec.push(&frame, &mut decoded);
        assert!(decoded.is_empty(), "cover frame must carry zero real bytes");

        // Rearm after advancing time and verify the next deadline moves forward.
        tokio::time::advance(Duration::from_millis(50)).await;
        let before_rearm = Instant::now();
        timer.rearm();
        timer.wait().await;
        let second_elapsed = Instant::now() - before_rearm;
        assert!(
            second_elapsed >= Duration::from_millis(100)
                && second_elapsed <= Duration::from_millis(200),
            "unexpected rearmed cover gap: {second_elapsed:?}"
        );
    }
}
