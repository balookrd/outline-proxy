// WS topology field extraction — status/wire-chain/role logic ported from
// bins/outline-ui/src/ws/dashboard.html's per-instance/per-uplink renderer
// (applyInstanceView/renderInstancePanel/renderInstanceBody and their
// isActive/healthy/statusTone/legWireChainCell helpers), field names verified
// against the real wire shape (bins/outline-ws-rust/src/http/control/topology.rs
// ControlUplinkTopology/ControlGroupTopology/WireChainEntry, which
// dashboard.html consumes unmodified — outline-ui's /ws/dashboard/api/topology
// proxies /control/topology verbatim, see ws/api.rs `topology()`).
//
// Kept as a standalone lib module (rather than inlined in the Svelte
// components) so the extraction/threshold logic — the intricate part of this
// task — is unit-testable without a running backend; see wsTopology.test.ts.
import type { Uplink, Group, WireChainEntry } from './types';

type Leg = 'tcp' | 'udp';

// Effective health for tone / status calculations. Reads `*_health_effective`
// (probe-confirmed OR any-wire-recently-worked, populated once an uplink has
// fallbacks configured) when it holds a verdict, else falls back to
// `*_healthy` (probe-only — the only signal a single-wire uplink has).
// Mirrors dashboard.html's legHealth() (:515-519).
export function legHealthy(u: Uplink, leg: Leg): boolean | null {
  const eff = leg === 'tcp' ? u.tcp_health_effective : u.udp_health_effective;
  if (eff === true || eff === false) return eff;
  const raw = leg === 'tcp' ? u.tcp_healthy : u.udp_healthy;
  return raw ?? null;
}

// dashboard.html healthy() (:520-522): both legs must not be explicitly
// unhealthy. An unmeasured leg (null — no probe has completed yet) does not
// count against it.
export function isHealthy(u: Uplink): boolean {
  return legHealthy(u, 'tcp') !== false && legHealthy(u, 'udp') !== false;
}

// dashboard.html isActive() (:523).
export function isUplinkActive(u: Uplink): boolean {
  return Boolean(u.active_global || u.active_tcp || u.active_udp);
}

// Carrier packet-loss ratio (0.0-1.0) on the wire currently carrying `leg`, or
// null when the backend has no verdict yet. Null is "not measured", never "0%
// loss". Mirrors dashboard.html legLossRatio() (:1104-1107).
export function legLossRatio(u: Uplink, leg: Leg): number | null {
  const v = leg === 'tcp' ? u.tcp_carrier_loss_ratio : u.udp_carrier_loss_ratio;
  return typeof v === 'number' ? v : null;
}

// Loss thresholds shared with the UplinkCarrierLossHigh Prometheus alert —
// dashboard.html :1108-1110. Amber from 2%, red from 5%.
export const LOSS_WARN = 0.02;
export const LOSS_BAD = 0.05;

// True when a leg that is actually carrying traffic (active for its
// transport, or the whole uplink is globally active) is losing at or above
// `threshold`. Loss on a standby leg is deliberately not counted — mirrors
// dashboard.html activeLegLossy() (:1119-1129).
export function activeLegLossy(u: Uplink, threshold: number): boolean {
  const tcpLoss = legLossRatio(u, 'tcp');
  const udpLoss = legLossRatio(u, 'udp');
  const tcpActive = Boolean(u.active_global || u.active_tcp);
  const udpActive = Boolean(u.active_global || u.active_udp);
  return (tcpActive && tcpLoss != null && tcpLoss >= threshold) || (udpActive && udpLoss != null && udpLoss >= threshold);
}

// ── Instance-level status (the card header dot/chip) ───────────────────────
// Mirrors dashboard.html statusTone()/statusLabel() (:539-554).

export type Tone = 'good' | 'warn' | 'bad';

export function instanceStatusTone(ok: boolean, groups: Group[]): Tone {
  if (!ok) return 'bad';
  const uplinks = groups.flatMap((g) => g.uplinks ?? []);
  if (uplinks.length === 0) return 'warn';
  const healthyCount = uplinks.filter(isHealthy).length;
  const activeCount = uplinks.filter(isUplinkActive).length;
  // A fast-but-lossy uplink is not "Healthy" — an active leg above the loss
  // threshold pulls the headline down to Degraded even when every health
  // flag reads green (health flags are blind to carrier loss).
  const activeLossy = uplinks.some((u) => activeLegLossy(u, LOSS_BAD));
  if (healthyCount === uplinks.length && activeCount > 0) return activeLossy ? 'warn' : 'good';
  if (healthyCount > 0) return 'warn';
  return 'bad';
}

export function instanceStatusLabel(tone: Tone): 'Healthy' | 'Degraded' | 'Offline' {
  return tone === 'good' ? 'Healthy' : tone === 'warn' ? 'Degraded' : 'Offline';
}

// ── Per-row status (the Status column) ──────────────────────────────────────
// Mirrors dashboard.html renderInstanceBody's rowTone/label (:1309-1311):
// disabled beats everything, then active, then probe-healthy, else down.

export type RowTone = 'good' | 'warn' | 'bad' | 'off';
export type RowLabel = 'Active' | 'Ready' | 'Down' | 'Disabled';

export function uplinkRowTone(u: Uplink): RowTone {
  if (u.admin_disabled) return 'off';
  if (isUplinkActive(u)) return 'good';
  if (isHealthy(u)) return 'warn';
  return 'bad';
}

export function uplinkRowLabel(tone: RowTone): RowLabel {
  return tone === 'off' ? 'Disabled' : tone === 'good' ? 'Active' : tone === 'warn' ? 'Ready' : 'Down';
}

// dashboard.html uplinkRole() (:1020-1026).
export function uplinkRole(u: Uplink): string {
  const parts: string[] = [];
  if (u.active_global) parts.push('global');
  if (u.active_tcp) parts.push('tcp');
  if (u.active_udp) parts.push('udp');
  return parts.length ? parts.join(', ') : 'standby';
}

// ── Wire-chain segment extraction ───────────────────────────────────────────
// Mirrors dashboard.html legWireChainCell()'s wireAt()/totalWires/activeIdx
// (:837-950), simplified to the prototype's terse pill vocabulary — no
// downgrade arrow, submode badge, pin timer, or per-dot DOWN marker; just the
// ordered carrier-tier list and which entry is active. WireChain.svelte
// renders the result.

// (transport, mode) → a terse carrier-tier code for the wire-chain pill. Mode
// tokens per the backend (ws_h1/ws_h2/ws_h3/xhttp_h1/xhttp_h2/xhttp_h3, plus
// bare h2/h3 dashboard.html's transportLabel() also accepts as synonyms): the
// h3/h2 tiers collapse WS and XHTTP into one pill — the prototype doesn't
// distinguish carrier family at that tier — while XHTTP's own H1 floor gets
// its own "xhttp" pill. Everything else (ws_h1/http1, an unresolved/
// never-probed mode, or a stray legacy "quic" token) buckets to "ws", the
// same default-to-ws-family dashboard.html's wireFamilyClass() falls back to
// for a mode that doesn't start with "xhttp".
export type Segment = 'h3' | 'h2' | 'ws' | 'xhttp';

function segmentFor(mode: string | null | undefined): Segment {
  const v = (mode ?? '').toLowerCase();
  if (v === 'ws_h3' || v === 'h3' || v === 'xhttp_h3') return 'h3';
  if (v === 'ws_h2' || v === 'h2' || v === 'xhttp_h2') return 'h2';
  if (v === 'xhttp_h1') return 'xhttp';
  return 'ws';
}

// dashboard.html wireAt(i)'s chain-entry branch: `w[leg_mode_effective] ||
// w[leg_mode] || w.tcp_mode || w.udp_mode || null` (:849-851) — the trailing
// cross-leg fallback covers a wire with no mode concept on this leg at all
// (e.g. a Shadowsocks wire, which carries neither field) by borrowing the
// other leg's mode rather than showing nothing.
function chainModeAt(w: WireChainEntry, leg: Leg): string | null {
  const legEffective = leg === 'tcp' ? w.tcp_mode_effective : w.udp_mode_effective;
  const legMode = leg === 'tcp' ? w.tcp_mode : w.udp_mode;
  return legEffective ?? legMode ?? w.tcp_mode ?? w.udp_mode ?? null;
}

// dashboard.html wireAt(0)'s no-chain branch: `uplink[leg_mode_effective] ||
// uplink[leg_mode] || null` (:854-856) — the fallback path every single-wire
// uplink actually takes, since configured_wire_chain is empty (not shipped)
// for uplinks with zero fallbacks configured.
function uplinkModeAt0(u: Uplink, leg: Leg): string | null {
  const legEffective = leg === 'tcp' ? u.tcp_mode_effective : u.udp_mode_effective;
  const legMode = leg === 'tcp' ? u.tcp_mode : u.udp_mode;
  return legEffective ?? legMode ?? null;
}

export interface WireSegments {
  segments: Segment[];
  activeIdx: number;
}

export function legWireSegments(u: Uplink, leg: Leg): WireSegments {
  const fallbacks = u.configured_fallbacks ?? [];
  const chain = u.configured_wire_chain ?? [];
  // dashboard.html :841 — chain length when shipped, else 1 (primary) + every
  // configured fallback. Always >= 1: an uplink always has at least a primary
  // wire even with zero fallbacks.
  const totalWires = chain.length || 1 + fallbacks.length;
  const modeAt = (i: number): string | null => {
    const w = chain[i];
    if (w) return chainModeAt(w, leg);
    if (i === 0) return uplinkModeAt0(u, leg);
    // Fallback-name-only entry (transport known, mode not) — dashboard.html's
    // rolling-deploy guard for a backend that ships configured_fallbacks
    // without the newer configured_wire_chain. Kept for parity even though
    // the two ship in lockstep on every current build.
    return null;
  };
  const segments: Segment[] = [];
  for (let i = 0; i < totalWires; i += 1) segments.push(segmentFor(modeAt(i)));
  const rawActive = (leg === 'tcp' ? u.tcp_active_wire : u.udp_active_wire) ?? 0;
  const activeIdx = Math.min(Math.max(rawActive, 0), Math.max(segments.length - 1, 0));
  return { segments, activeIdx };
}

// ── Single-column RTT / loss (the prototype collapses dashboard.html's
// separate "tcp: Xms · udp: Yms" weightCell text into one figure per column)
// ────────────────────────────────────────────────────────────────────────────

// Prefers the active-wire EWMA over the primary EWMA (matches dashboard.html
// weightCell's own preference, :1145-1146 — the active wire is the one
// actually carrying traffic), TCP leg first since the TCP wire-chain column
// precedes UDP's in the same row.
export function primaryRttMs(u: Uplink): number | null {
  const tcp = u.tcp_active_wire_rtt_ewma_ms ?? u.tcp_rtt_ewma_ms ?? null;
  const udp = u.udp_active_wire_rtt_ewma_ms ?? u.udp_rtt_ewma_ms ?? null;
  return tcp ?? udp;
}

// The worse of the two legs' carrier-loss ratios (0.0-1.0) — an operator
// should see the worse number, not miss it because the other leg happened to
// render first. dashboard.html shows both tcp/udp loss tags side by side
// (:1153); the prototype's single "Loss · Wt" column has room for one.
export function primaryLossRatio(u: Uplink): number | null {
  const tcp = legLossRatio(u, 'tcp');
  const udp = legLossRatio(u, 'udp');
  if (tcp == null && udp == null) return null;
  return Math.max(tcp ?? -Infinity, udp ?? -Infinity);
}

export type MetricTone = 'good' | 'warn' | 'bad' | null;

// Same LOSS_WARN/LOSS_BAD thresholds as the instance-level activeLegLossy(),
// applied here to the single collapsed ratio for the row's metric colour.
export function lossTone(ratio: number | null): MetricTone {
  if (ratio == null) return null;
  if (ratio < LOSS_WARN) return 'good';
  return ratio < LOSS_BAD ? 'warn' : 'bad';
}
