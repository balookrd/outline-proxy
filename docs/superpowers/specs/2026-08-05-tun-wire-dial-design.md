# Fallback wires for the TUN ingress (design)

Date: 2026-08-05
Status: design approved by owner (chat)

## Problem

Every uplink on the fleet is configured with a primary carrier and three
fallback wires:

```toml
[[outline.uplinks]]
name = "nuxt"
transport = "vless"
vless_mode = "xhttp_h3"
shuffle_wires = true
shuffle_timer = "10m"

[[outline.uplinks.fallbacks]]   # wire 1: vless over ws_h3
[[outline.uplinks.fallbacks]]   # wire 2: ss over xhttp_h3
[[outline.uplinks.fallbacks]]   # wire 3: ss over ws_h3
```

None of those fallback wires is ever dialed, and `shuffle_wires` rotates
nothing. The wire machinery is reachable only from the SOCKS ingress, and the
fleet does not use SOCKS.

### Evidence

`outline-tun` contains no reference to `wire_dial_order`, `active_wire` or
`fallbacks` — and never has, across the whole history of
`crates/outline-tun/src/tcp/engine/connect.rs`. The TUN dial paths are:

- TCP — `connect_tcp_uplink_inner`: `try_take_tcp_standby` (warm pool, always
  primary) and otherwise `connect_tcp_ws_fresh` (also primary).
- UDP — `crates/outline-tun/src/udp/lifecycle.rs`: calls
  `acquire_udp_standby_or_connect_with_store` directly.

The wire machinery lives in `bins/outline-ws-rust/src/proxy/`:
`tcp/failover.rs:177`, `tcp/connect/failover_step.rs:63`, `udp/transport.rs:55`.

Ingress split over 24 h, `increase(outline_ws_transport_connects_total[24h])`:

| instance | `socks_tcp` | `tun_tcp` |
|---|---|---|
| ubuntu (`.102`) | 0 | 2955 |
| debian (`.104`) | 0 | 2017 |
| cloud3 | 0 | 328 |
| cloud4, cloud1 | 0 | 0 |

Corroboration from the client's own debug log on `.102` over 8 h: 6193 carrier
loss-probe registrations, **every one of them with `wire = 0`** — 5812 on
`nuxt`/Tcp, the rest UDP and standby nodes. A dial on a fallback wire registers
its probe with that wire's index (`proxy/tcp/failover.rs:808`), so a single
non-zero registration would have disproved this.

### Consequences observed today

**Failure isolation within an uplink does not exist.** When a primary carrier
breaks — a DPI rule that targets `xhttp_h3` specifically, say — the fleet cannot
try the same server over `ws_h3` or over SS. It abandons the uplink entirely and
moves to another server. The h3→h2→h1 descent *within* one carrier is a separate
mechanism and does work.

**Loss and RTT attribution is wrong the moment `shuffle_timer` fires.** The
verdict is written to the slot of the wire the probe was registered under
(always 0, correctly — that is where traffic flows), while the metric and the
loss-failover freshness gate read the slot of `active_wire`, which the shuffle
timer re-rolls every 10 minutes. Over 8 h on `.102`: 236 sample points carried a
`carrier_loss_ratio` and **all 236** had `active_wire_index == 0`; zero points
carried a ratio while `active_wire_index != 0`. The uplink *score* is unaffected
— `base_latency_and_wire_loss` falls back to the primary pair when the active
wire has no RTT EWMA — but the published metric and the loss-driven failover
episode both go silent for roughly 60% of wall-clock time.

**`health_weighted_selection` (default `true`) ignores `active_wire` entirely**
in `wire_dial_order`, returning a weighted permutation instead. On the fleet
this is moot, because control never reaches `wire_dial_order` at all.

## Goal

Bring the TUN ingress onto the wire machinery, in both planes, including live
flows — and make the warm-standby pool follow the active wire so rotation is
cheap enough to leave enabled.

Explicitly in scope:

1. TUN TCP and TUN UDP dial through the wire chain.
2. VLESS supported as a fallback wire on UDP — today
   `proxy/udp/transport.rs` documents this as unsupported because the QUIC mux
   factory is keyed on the parent uplink.
3. A live flow whose carrier dies migrates onto a sibling wire of the same
   uplink, not only onto the parent's primary.
4. The warm-standby pool is dialed on the active wire and follows it across a
   rotation.

## Approach

One new abstraction, and one shift of responsibility.

### `WireSpec` — the projection of a single carrier

A new `crates/outline-uplink/src/wire_spec.rs` holds the fields a dial needs,
projected from whichever wire is being dialed: `transport`, the dial URL for the
plane in question, `mode`, `cipher` / `password` / `vless_id`, `fwmark`,
`ipv6_first`, the combined-SS discriminator, the padding override and the
fingerprint profile. Two constructors:

- `WireSpec::from_uplink(&UplinkConfig)` — wire 0.
- `WireSpec::from_fallback(parent_name, &FallbackTransport)` — wire *i*.

The uplink **name** is the parent's in both cases: a wire is not a separate
uplink to the load balancer, to metrics or to scoring. This is a completion of
the `WireSetup` projection that already exists in
`bins/outline-ws-rust/src/proxy/tcp/failover.rs:839`, which carries credentials
only; that type is removed in favour of this one.

`WireSpec` is what holds the boundary. Once it exists, no dial path reads
`candidate.uplink.*` directly, so a newly added dial path cannot silently
default to primary — which is exactly how the TUN ingress ended up where it is.

### The dial core takes a wire

All six public TCP dial methods funnel into one internal entry point,
`connect_tcp_ws_fresh_internal(candidate, source, dial: FreshTcpDial)`
(`manager/standby/mod.rs:375`); UDP funnels into
`acquire_udp_standby_or_connect_with_store`. So the parameterisation is one
point per plane, not six methods:

- `FreshTcpDial` gains a `wire: u8` field.
- Both internal entry points resolve a `WireSpec` for that wire and work through
  it.
- The public methods keep their signatures and pass `wire = 0`; `*_on_wire`
  variants are added for callers that choose a wire.

On the UDP side this is what removes the VLESS-fallback restriction: the mux is
built from a `WireSpec` rather than from `candidate.uplink`, and
`FallbackTransport` already carries `vless_ws_url`, `vless_xhttp_url`,
`vless_mode`, `vless_id`, `fwmark` and `ipv6_first`.

### The wire loop is shared, not copied

`crates/outline-uplink/src/manager/wire_dial.rs` provides
`dial_over_wires(candidate, transport, source, opts, build)`:

1. Take the order from `wire_dial_order`.
2. Dial the next wire (`WireSpec`), warm pool on the active wire, fresh dial
   otherwise.
3. Hand the stream to `build`, the caller's transport-assembly closure — SS /
   VLESS setup differs between TUN and SOCKS.
4. Record `record_wire_outcome` on the result of `build`, not of the dial alone.
5. On success return; on failure move to the next wire.

Step 4 is load-bearing. A failure in the SS handshake must retire the wire and
advance the chain exactly like a failed dial does; the SOCKS loop already
behaves this way and the shared helper inherits it. The rejected alternative —
returning `(stream, wire)` and letting each ingress own its loop — loses that
property and duplicates the loop twice over.

### The warm pool follows the active wire

`StandbyCtx` already resolves `url` and `mode` as fields rather than reaching
into the uplink, so this is a local change: `standby_ctx` sources them from
`WireSpec(active_wire)` instead of `uplink.tcp_dial_url()` and
`effective_tcp_mode(index)`.

`StandbyPool` gains a `wire` marker recording which wire filled it. On take, a
marker that disagrees with the current active wire drains the pool, the caller
gets a fresh dial on the active wire, and the refill loop repopulates on the new
one. The cost of a rotation is closing `warm_standby_tcp` prewarmed connections
(2 on the fleet) per `shuffle_timer` interval.

Refill dials through `WireSpec` too, which matters for measurement coverage:
refill produces 12799 dials/day on `.102` against 2937 from TUN itself, so most
loss-probe registrations come from there.

One trap to avoid: for a combined-SS wire the leg discriminator
(`refill::StandbyCtx::pool_ss_leg`) must come from the `WireSpec`, not from the
parent uplink. A pool filled with the other leg's streams silently drops every
reused datagram — this has happened before.

## Data flow

**New TUN TCP flow.** Candidate selection is unchanged. `dial_over_wires` walks
the order starting at the active wire: wire 0 takes from the warm pool, other
wires always dial fresh. The dial registers its loss probe under the actual wire
and feeds latency into that wire's RTT EWMA slot. `build` performs the SS /
VLESS setup. Success records the outcome and returns; failure records it and
moves on. Exhausting every wire propagates one error to the caller, where
`report_runtime_failure` moves the flow to a different uplink, as today.

**New TUN UDP flow.** The same, skipping wires with no UDP path
(`FallbackTransport::supports_udp`). Wire 0 and wire *i* are both built from a
`WireSpec`, so VLESS is no longer a special case.

**Live TCP flow migration.** `redial_tcp_uplink_for_migration` dials the active
wire instead of the primary, presenting the flow's own Session ID. A wire change
can change proxy protocol (VLESS↔SS); the server already allows cross-protocol
resume on the byte-stream path (`61d2d459`, 2026-07-30).

**Live UDP flow migration is bounded by the server.** Datagram and mux parks are
deliberately not transferable across protocols — the sub-connection map keyed by
mux id, partially parsed frames and NAT slots in SS encoding. UDP migration is
therefore allowed only onto a wire of the same protocol; otherwise the flow
re-establishes without resume, as it does today. This is a limitation of the
method, not of the configuration.

## Error handling and invariants

- **`report_runtime_failure` fires on the parent only after every wire has
  failed.** One broken carrier must never flap a whole uplink out of the
  candidate set.
- **Carrier-descent attribution stays per-wire.** Every
  `note_silent_transport_fallback` call on a dial path becomes the
  `_for_wire` variant carrying the actual wire. Leaving the parent-level variant
  on the primary path reintroduces the bug where a fallback capped primary's
  slot. Same for `effective_tcp_mode_for_wire` / `effective_udp_mode_for_wire`:
  the pool must ask for the active wire's mode, or one carrier's h3→h2 descent
  silently applies to another.
- **Loss attribution is fixed as a consequence, not by a separate patch.** The
  probe is registered under the wire that carries the traffic, `active_wire`
  starts meaning what it says, and the freshness stamp in
  `apply_loss_collection` stops missing. No fallback-to-slot-0 read is added:
  that would paper over the mismatch this design removes.
- **Resume identity.** TUN dials a carrier per flow and holds a private
  `UdpResumeStore`, so a wire change does not resurrect the cross-flow leak
  through the shared `<scope>#udp` slot.

## Rollout

The change alters the dial core that carries all fleet traffic, and enabling it
makes `shuffle_wires` genuinely rotate carriers — traffic starts flowing over
`ws_h3` and SS where today it is always `xhttp_h3`, changing both the client's
metrics and the servers' park composition.

It therefore ships behind `[load_balancing] tun_wire_dial`, default `false`.
The binary deploys inert and is indistinguishable from today's until the flag is
set, exactly as the carrier-loss signal shipped. Enabling proceeds one node at a
time, with all four clients moved off the node being touched, and no restart
without explicit approval.

Three signs confirm the design worked once the flag is on, each absent today:

1. Loss-probe registrations appear with `wire != 0`.
2. `outline_ws_uplink_active_wire_rtt_ewma_seconds` is published for non-zero
   wires.
3. `outline_ws_uplink_carrier_loss_ratio` no longer disappears when
   `active_wire_index` leaves 0.

## Testing

**Unit.** `WireSpec`: both constructors — parent name, own credentials, own URL
and mode, combined-SS discriminator. `dial_over_wires`: traversal order; outcome
recorded on both paths; the chain advances when *transport assembly* fails, not
only the dial; wires without a UDP path are skipped; exhausting the chain
produces a single error with no intermediate `report_runtime_failure`.

**Pool.** Drain on a wire-marker mismatch; refill dials the active wire;
combined-SS leg taken from the `WireSpec` (regression test for the
wrong-leg pool).

**Attribution.** A probe registered under the actual wire rather than 0; carrier
descent capping its own wire's slot. These two cover the defects the task grew
out of.

**Gate.** With `tun_wire_dial = false` the order degenerates to `[0]` and the
pool behaves as today — a deployed binary is indistinguishable from the current
one before the flag flips.

**E2e.** Add to the existing failover harness: primary wire dead, the flow moves
to a fallback wire of the *same* uplink rather than to a sibling uplink, and
`report_runtime_failure` is not called.

Adding a field to `LoadBalancingConfig` requires updating every test literal of
that struct (~16 of them) — mechanical but mandatory. Full repo gate before
commit: `fmt` with the explicit package list, `clippy --all-targets`,
`test --workspace --exclude sockudo-ws`.

## Documentation

`bins/outline-ws-rust/docs/UPLINK-CONFIGURATIONS.md` and its `.ru.md`
counterpart need the wire
chain's actual reach corrected — the current text does not say that fallback
wires were SOCKS-only. `CHANGELOG.md` / `CHANGELOG.ru.md` in the same change.
