# Carrier loss as an uplink-selection input (design)

Date: 2026-08-03
Status: design approved by owner (chat); revised after implementation to match
what shipped — the ownership model, the metric names and the loss-driven
failover all changed under review pressure, and the revisions are marked where
they matter.

## Problem

On 2026-08-02 the `.102` gateway sat on the `senko` uplink from 03:30 to 10:00
after a scheduled soft reselect. Throughput-sensitive traffic (Instagram,
Telegram video) degraded; a manual switch to `aeza` fixed it. Selection never
reacted, because every input it has looked healthy:

- `outline_ws_uplink_rtt_ewma_seconds{uplink="senko"}` — 0.21–0.32 s (normal),
- `outline_ws_uplink_score_seconds{uplink="senko"}` — 0.207–0.276, best or
  second best, while `aeza` scored 1.125 (worse) in the same hours,
- `outline_ws_uplink_health{uplink="senko"}` — 1 every hour,
- `outline_ws_uplink_runtime_failures_total{uplink="senko"}` — never incremented.

The path was lossy, and loss is invisible to selection. A path can drop packets
while its RTT stays low, so a latency-only score ranks it best exactly when it
is broken.

### Why the existing TUN counters do not solve this

`retransmit_budget_exhausted`, `timeout_retransmit` and `window_stall` rise on a
degraded uplink, but they cannot be wired into selection as-is, for two separate
reasons.

First, they measure the wrong leg. `retransmit_budget_exhausted`
(`crates/outline-tun/src/tcp/state_machine/send/buffer.rs`) walks
`unacked_server_segments` — segments this userspace stack already **wrote to the
TUN device** and is waiting for the *client* to ACK (`ServerDataPacket` is "one
downlink packet to write to the TUN device"). `window_stall` is the client's
receive window closing. All three describe the last mile between the gateway and
the LAN device, not the leg between the client and the server. A packet lost on
the way to the server does not retransmit on that leg — it only shows up
indirectly, as bursty delivery overrunning the LAN queue. Attributing those
counters to an uplink would penalise a healthy uplink for a client's Wi-Fi, and
would produce no signal at all for SOCKS5 traffic, which never enters the TUN
stack.

Second, that path never reports anything anyway. In TUN TCP,
`report_tcp_runtime_failure` has exactly four call sites: `connect.rs` (dial),
`pump.rs` (carrier write), `reader.rs` (carrier read) and `backlog.rs`, whose
reason is `server_backlog_limit`. The retransmit budget aborts through
`maintenance.rs` → `FlowMaintenancePlan::Abort` → `abort_flow_with_rst` and
through `engine/packet.rs` → `abort_flow_with_rst`; that function emits an RST
and a metric and tells the manager nothing.

### What is missing

Nothing in the workspace observes loss on the carrier itself. `quinn`'s
`Connection::stats()`, `lost_packets`, `TCP_INFO` and `tcpi_*` have zero hits
outside of vendored code — although both carrier families already count exactly
this and hand it over for free.

## Goal

Measure loss on the carrier socket, per uplink and per wire; accumulate it as
uplink state so every link's coefficient is readable from metrics and the
control snapshot without ad-hoc analysis; and let it inflate the latency the
selection ranks by, off by default until the field numbers are in.

A second goal, added once the first was implemented and reviewed against the
motivating incident: give a pinned strict active uplink a way to actually
*yield* on loss, not just rank lower. `active_passive` with `auto_failback =
false` — the fleet's own configuration — never consults `score` for a
probe-healthy pinned active, so the ranking penalty above is provably inert
against the 2026-08-02 incident on its own; see "Loss-driven failover for a
pinned active uplink" below.

## Non-goals

- The false `retransmit_budget_exhausted` RST after ~97 ms
  (`tun-sack-fast-retransmit-budget-bug`) is a separate defect. It amplifies the
  symptom; it is not touched here.
- No change to how `health`, cooldown or `runtime_failures` work. A lossy but
  working uplink must keep carrying traffic when it is the only live one.
- No new probe traffic. The signal comes from sessions that already exist.
- No explanation of why `.102` shows far more TUN retransmits than `.104` on the
  same uplink. Both hosts dial over identical routes (verified with `ip route
  get` for all three uplinks; `direct_fwmark` marks direct traffic only), so the
  asymmetry is unexplained and out of scope.

## Signal source

Per carrier connection, cumulative counters, sampled on a timer.

**QUIC (`ws_h3`, `xhttp_h3`).** `quinn::Connection::stats().path` gives
`sent_packets`, `lost_packets`, `congestion_events` and `black_holes_detected`
(all present in quinn-proto 0.11.14). A `quinn::Connection` clone is cheap — it
is `Arc`-backed.

**TCP (`ws`, `h2`, `xhttp` over TLS/TCP).** Linux `TCP_INFO` via `getsockopt`
gives `tcpi_segs_out` and `tcpi_total_retrans`. The struct is declared locally
as a `#[repr(C)]` prefix of the kernel's rather than taken from `libc`:
`libc::tcp_info` stops at `tcpi_total_retrans` under `linux-gnu` and has no
`tcpi_segs_out`, while under musl it has both — and the fleet builds musl while
CI builds gnu, so the `libc` type compiles in one and breaks the other. The
kernel only appends to this struct and reports how many bytes it wrote, so
reading a validated prefix is the forward-compatible contract. The fd is `dup`ed rather than
borrowed: without that, once the carrier closes, the fd number is recycled by an
unrelated socket and the sampler silently reads a stranger's statistics. Carrier
death is observed as `tcpi_state != ESTABLISHED`, which is when the duplicate is
closed and dropped from the registry. `libc` is already a dependency of
`outline-transport`; the single `unsafe` block carries a concrete `// SAFETY:`
comment for the `undocumented_unsafe_blocks` gate. Non-Linux targets yield
`None` — the client builds there for development only.

Retransmits are not strictly identical to loss (spurious retransmits count too),
but the quantity being compared is *relative pressure between candidate paths*,
and for that they are the right measure.

## Components

### `crates/outline-transport/src/carrier_loss.rs`

```rust
/// A carrier that can report its own loss counters. Implemented by the
/// connection wrappers themselves (`SharedH3Connection`, the XHTTP-over-H3
/// carrier), so a probe can read a carrier without keeping it alive.
pub trait CarrierLossCounters: Send + Sync {
    fn loss_counters(&self) -> Option<CarrierLossSample>;
}

pub enum CarrierLossProbe {
    /// A `Weak` handle onto the connection wrapper that owns the real
    /// `quinn::Connection` — upgrading it fails, rather than reading stale
    /// data, once the transport has dropped its last strong reference.
    #[cfg(feature = "h3")]
    Quic { counters: Weak<dyn CarrierLossCounters>, identity: u64 },
    /// A **duplicated** descriptor, not a borrow — without the `dup`, once
    /// the carrier closes the fd number is recycled by an unrelated socket.
    #[cfg(target_os = "linux")]
    Tcp { fd: OwnedFd, identity: u64 },
}

pub struct CarrierLossSample {
    pub sent: u64,     // cumulative, per connection
    pub lost: u64,     // cumulative, per connection
    pub alive: bool,
}

impl CarrierLossProbe {
    pub fn sample(&self) -> Option<CarrierLossSample>;
}
```

Cumulative, never deltas: the accumulator owns differencing, so a missed tick
loses resolution but not correctness.

**Revised from the first design.** This shape replaced an earlier one where
the QUIC variant held `Quic(quinn::Connection)` directly — a full, strong
handle. That design shipped, and a Critical finding in review caught what it
actually did: quinn only implicit-closes a connection once its last `Connection`
handle drops, so a probe holding one *extended the life of the thing it was
measuring*. A registered probe for a wire that was retired locally, or a
standby that stopped being dialed, pinned that connection open indefinitely —
worse, `keep_alive_interval` (8–12 s) means a QUIC carrier's own PINGs keep
`Δsent` nonzero forever, so even the staleness-eviction fix that closed the
finding's TCP case never aged the QUIC one out. The fix was to stop owning
what is being observed: the connection wrappers (`SharedH3Connection`, the
XHTTP H3 carrier) implement `CarrierLossCounters` and hand the probe a `Weak`
onto themselves, so the probe can read counters without holding a strong
reference at all — closing now happens exactly when the transport itself
drops its connection, with or without the probe. `identity` is captured once
at construction, independent of the `Weak`, so a probe can still be
recognised (and evicted) by the registry after the carrier — and therefore
the `Weak` — is dead. Staleness eviction (`MAX_IDLE_TICKS`) stays as
belt-and-braces for QUIC and remains load-bearing for TCP, whose duplicated
fd genuinely keeps a half-closed carrier from tearing down until evicted.

### `TransportStream::loss_probe(&self) -> Option<CarrierLossProbe>`

The only place transport exposes observability. H3 variants clone the
`quinn::Connection`; Http1/H2/XHTTP-over-TCP reach the `TcpStream` under the
TLS/WS wrapper and `dup` its fd. Attribution to a group/uplink/wire happens
entirely outside this crate — `TransportDialOptions` carries no such labels
today and gains none.

### `crates/outline-uplink/src/loss.rs`

Split in two by what each half may hold. `LossEwma` is numbers only and lives
inside `UplinkStatus`, which is cloned on every snapshot. `CarrierLossRegistry`
holds the live probes — and an `OwnedFd` is not `Clone` — so it lives beside the
statuses in the manager's inner state and never enters a status clone.

`CarrierLossRegistry` + `LossEwma`, one pair per wire:

- keeps the previous cumulative `(sent, lost)` of every live carrier, keyed by a
  registry-assigned probe id (carriers have no identity of their own, and a
  reused fd number must never be mistaken for the connection that held it);
- per tick: differences each carrier, drops the ones that disappeared, sums the
  deltas;
- if the window's summed `Δsent` is below `loss_sample_min_packets`, the tick
  yields no sample and the EWMA does not move. This threshold is load-bearing:
  on a near-idle carrier one lost packet out of ten reads as "10% loss".
- otherwise folds `Δlost / Δsent` into an EWMA (`loss_ewma_alpha`).

Exposes `loss_ratio() -> Option<f64>`, `inflation(k, cap) -> f64`, and the
observed volume behind the verdict.

Bounded, per `AGENTS.md`: at most `N` probes retained per wire (newest win),
dead entries evicted on every tick.

### State

Registration happens on a successful dial inside `outline-uplink`, the only
layer that knows the uplink index, the wire slot and the `TransportKind` being
dialed; the probe is filed under that transport's half of the status, so a TCP
carrier's loss never lands on the UDP plane or vice versa.

`PerTransportStatus` gains `carrier_loss: LossAccumulator` for the primary wire
and `fallback_carrier_loss: Vec<LossAccumulator>` for fallbacks — mirroring the
existing `fallback_rtt_ewma` layout, and selecting the active entry by the same
`active_wire` rule that already resolves RTT. One mechanism, not a second
parallel one.

### Sampling loop

A dedicated timer (`loss_sample_interval`, default 10 s), not the probe cycle:
probes run on a much coarser cadence and deliberately skip cycles for active
uplinks (`should_skip_probe_cycle_for_recent_activity`), while differencing needs
an even grid. Loop shape and group-scoped shutdown follow
`spawn_shuffle_timer_loops`.

Sampling deliberately reads live user sessions rather than the warm probe slot:
the warm slot carries almost no traffic, and loss only manifests under load — a
lossy uplink looks clean there.

## Applying it to selection

One edit in the ranking path. `PerTransportStatus::base_latency()` currently
returns `active_wire_rtt_ewma().or(rtt_ewma).or(latency)`; it will multiply that
by the active wire's `1 + loss_latency_penalty_k * loss_ratio`, clamped to
`loss_latency_inflation_max`.

`base_latency` is the shared input of every scope, and Global under
`auto_failback` routes through it too (that mode discards `penalty`, so a
penalty-based design would be blind exactly where the field incident happened).
Physically the choice is honest: loss *is* delivery latency, since each
retransmit costs the affected bytes another round trip.

Flapping is bounded by four things: the EWMA, the volume threshold, the
inflation cap, and the existing `hysteresis` plus sticky-active logic that
`shuffle_wires` already relies on.

**This alone does not fix the incident it is named for.** `base_latency` only
reaches selection through `score`, and `score` is not universally consulted —
in `active_passive` mode with `auto_failback = false` (the fleet's actual
shape), `strict_transport_candidates` returns a probe-healthy pinned active
without ever looking at it. Discovered only once this design was implemented
and checked against the 2026-08-02 timeline: no value of `k` would have moved
that gateway. See "Loss-driven failover for a pinned active uplink" below,
which is what actually closes the incident; this section makes loss visible
and makes it *rank* — necessary, but on its own not sufficient.

## Loss-driven failover for a pinned active uplink

Added after the ranking mechanism above was implemented and measured against
the incident it was named for, once it became clear ranking alone cannot
move a pinned strict active. The precedent already existed in the code for a
different signal: `carrier_degraded_switch_target` yields the leg when the
active has been continuously running below its configured carrier (a silent
`ws_h3 → ws_h2` downgrade, say) past a threshold, and a clean,
equal-or-higher-weight sibling exists. Loss is the same shape of signal, so
it gets the same shape of mechanism, checked right beside the carrier one and
published the same way (`SwitchIntent::Failover`, so sessions migrate on a
cluster group instead of being cut).

**Mechanism.** A per-transport `loss_elevated_since: Option<Instant>` tracks
a *continuous* episode of the active-wire loss ratio exceeding
`loss_failover_ratio`: set on the first qualifying tick above threshold,
cleared the instant a tick comes back at or below it (or the ratio is
unmeasured) — a flapping uplink never accumulates its way into a failover.
The ratio is trusted only when *fresh*: a wire-tagged timestamp
(`loss_last_qualifying_at`, stamped whenever a sampling tick records a window
that actually met `loss_sample_min_packets` for whichever wire was active at
that moment) must name the currently active wire and be within
`3 × loss_sample_interval` of the tick. Without this, a wire idling on
light-but-nonzero traffic — a warm-standby carrier pinged too lightly to ever
clear the volume floor again — would keep reading its last, no-longer-current
ratio as ongoing evidence indefinitely, both for the active's own episode and
for a *candidate's* clean-or-not verdict (a stale reading, however low the
frozen number, is not proof a candidate is currently clean — only that it
once was). Once the episode has run continuously for at least
`loss_failover_duration`, the active yields to a candidate that is
probe-healthy, of equal-or-higher weight (operator priority still stands —
this is a failover, not a failback), has reached `probe.min_failures`
consecutive probe successes, and is itself at or below the threshold on a
fresh reading. The streak requirement is load-bearing, not cosmetic: in
`Global` scope, `selection_health` also admits a candidate via
`fallback_bootstrap_allowed` when probe has never rendered a verdict for it
and it has never recorded a successful dial — without the streak gate, a dead
standby in exactly that state would take the leg, immediately fail the next
dispatch's health check, fail back to the lossy primary, and re-trigger on
the following tick: a switch on every connection. An uplink with no loss
verdict at all counts as clean (absence is never evidence of loss); with no
clean candidate the lossy active — still carrying traffic — stays, since
moving between two lossy paths is churn, not recovery.

## Config (per-group `load_balancing`)

| Key | Default | Meaning |
|---|---|---|
| `loss_latency_penalty_k` | `0.0` | Inflation strength. `0` = observe only; selection is byte-for-byte unchanged. |
| `loss_latency_inflation_max` | `4.0` | Ceiling on the multiplier. |
| `loss_sample_interval` | `10s` | Sampling grid. `0` disables sampling entirely. |
| `loss_sample_min_packets` | `200` | Minimum `Δsent` per window for a tick to count. |
| `loss_ewma_alpha` | `0.2` | Smoothing. |
| `loss_failover_ratio` | `0.0` | Loss ratio above which a strict active uplink counts as degraded for loss-driven failover. `0.0` disables the check entirely — the one knob pair here that moves production traffic without an operator asking. |
| `loss_failover_duration` | unset | How long `loss_failover_ratio` must be exceeded **continuously** before the active yields to a clean, equal-or-higher-weight sibling. Unset disables the check independently of `loss_failover_ratio`. |

The default ships the measurement without the behaviour change: the fleet runs a
week, the real spread between `nuxt` / `senko` / `aeza` becomes visible in
VictoriaMetrics, and `k` (and, separately, the failover pair) is then set by a
config edit — no new binary.

## Observability

- `outline_ws_uplink_carrier_loss_ratio{group,transport,uplink}` — gauge, the
  smoothed loss ratio for the wire currently carrying traffic. No `wire`
  label: only the *active* wire's loss is published, the same wire
  `base_latency` scores from.
- `outline_ws_uplink_carrier_loss_observed_packets{group,transport,uplink}` —
  gauge, cumulative packets behind that ratio since the wire's last reset, so
  "no loss" is distinguishable from "no data". A gauge, not a counter — it
  resets to `0` (via the underlying verdict resetting to "not measured")
  whenever the wire loses its last registered carrier, so a value from
  traffic that no longer exists does not survive as a stale reading.
- `outline_ws_uplink_latency_inflated_seconds{group,transport,uplink}` —
  gauge next to the existing `rtt_ewma_seconds`, showing what selection
  actually ranked by once carrier loss is folded in.
- `outline_ws_uplink_loss_elevated_seconds{group,transport,uplink}` — gauge,
  how long the current loss-driven-failover episode has been running. Absent
  while no episode is running.
- `outline_ws_uplink_loss_failovers_total{transport,group,from_uplink,to_uplink}`
  — counter, one increment per switch the loss-driven-failover check causes,
  distinct from the pre-existing `outline_ws_uplink_failovers_total`
  (data-plane / runtime failovers).
- **Not implemented:** a dashboard / control-snapshot row surfacing
  `loss_ratio` and `inflation` next to `tcp_score_ms`. The metrics above are
  the only observability surface that shipped; the dashboard stays whatever
  it already was.

Together these answer "which link is lossy right now" for every uplink on every
node without a manual investigation.

## Testing

Failing tests come first (`superpowers:test-driven-development`), in `tests/`
subdirectories per repo convention.

`crates/outline-uplink/src/tests/loss.rs`:

- a window below `loss_sample_min_packets` leaves the EWMA untouched;
- a carrier that disappears between ticks does not produce a negative delta;
- inflation is clamped at `loss_latency_inflation_max`;
- `k = 0` reproduces today's `base_latency` exactly;
- ranking: a 0.21 s path at 2 % loss must lose to a 0.30 s clean path at the
  calibrated `k`, and must still win at `k = 0`.

`crates/outline-transport/src/tests/carrier_loss.rs`:

- `TCP_INFO` sampling over a loopback socket (CI runs ubuntu; macOS yields
  `None`);
- a closed socket reports `alive = false` exactly once and is then evicted;
- dropping the last strong reference to a QUIC carrier makes `sample()`
  report `alive = false` — the regression the weak-handle rewrite exists to
  pin (see "Revised from the first design" above).

`crates/outline-uplink/src/tests/mod.rs` (loss-driven failover, end to end
through `tcp_candidates`):

- a continuously-lossy active past `loss_failover_duration` yields to a
  clean, stable, equal-or-higher-weight sibling, and does not yield before
  the duration threshold is crossed or the episode is interrupted;
- a clean candidate without a proven `probe.min_failures` streak, a
  `Global`-scope bootstrap-admitted dead standby, and a lower-weight clean
  candidate all fail to take the leg;
- with no clean candidate the lossy active stays;
- a candidate whose own ratio is fresh and clean still qualifies; one whose
  ratio is numerically clean but stale does not;
- `loss_failover_ratio = 0.0` and `loss_failover_duration` unset each
  independently disable the check.

## Rollout

Not deployed without a separate instruction from the owner. When it is:
`ops/deploy/deploy-binary.sh`, one node at a time, all four clients moved off
unconditionally via `POST :9191/control/activate`, `.102` last.

## Documentation

`bins/outline-ws-rust/docs/UPLINK-CONFIGURATIONS.md` and its `.ru.md` in the same
change.
