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

// ── Wire-chain extraction (3 layers: proxy › tunnel › carrier) ─────────────
// Mirrors dashboard.html legWireChainCell()'s wireAt()/totalWires/activeIdx
// (:837-950) for the ordering/active-index math, but resolves each wire to
// the full "Variant B" shape (proxy badge, tunnel badge, carrier pill)
// instead of the old single terse pill. WireChain.svelte renders the result
// and builds the hover tooltip; this module only resolves the data.

// The tunnel a wire's mode token names — the WS/XHTTP framing carrying the
// proxy protocol. `null` when the mode is missing (e.g. a Shadowsocks wire
// with no *_mode field at all) or unrecognised.
export type Tunnel = 'ws' | 'xhttp' | null;
// The HTTP version actually carrying the tunnel. `null` under the same
// missing/unrecognised conditions as `Tunnel`.
export type Carrier = 'h3' | 'h2' | 'h1' | null;

export interface ParsedMode {
  tunnel: Tunnel;
  carrier: Carrier;
}

// Parses one wire's mode token (ws_h1/ws_h2/ws_h3/xhttp_h1/xhttp_h2/xhttp_h3,
// plus the bare h2/h3 synonyms dashboard.html's transportLabel() also
// accepted) into its tunnel and carrier layers. Tolerates a missing mode —
// returns all-null rather than guessing — which is the normal shape for a
// Shadowsocks wire carrying no *_mode field, and for a mode that hasn't
// resolved yet.
export function parseWireMode(mode: string | null | undefined): ParsedMode {
  const v = (mode ?? '').toLowerCase();
  switch (v) {
    case 'ws_h3':
      return { tunnel: 'ws', carrier: 'h3' };
    case 'ws_h2':
      return { tunnel: 'ws', carrier: 'h2' };
    case 'ws_h1':
    case 'http1':
      return { tunnel: 'ws', carrier: 'h1' };
    case 'xhttp_h3':
      return { tunnel: 'xhttp', carrier: 'h3' };
    case 'xhttp_h2':
      return { tunnel: 'xhttp', carrier: 'h2' };
    case 'xhttp_h1':
      return { tunnel: 'xhttp', carrier: 'h1' };
    case 'h3':
      return { tunnel: null, carrier: 'h3' };
    case 'h2':
      return { tunnel: null, carrier: 'h2' };
    default:
      return { tunnel: null, carrier: null };
  }
}

// Proxy-layer badge label — lowercase, exactly `vl`/`ss` (owner: "vless=vl
// not V, ss=ss not SS"). Falls back to the raw (lowercased) transport string
// for anything else so an unrecognised transport doesn't silently vanish.
export function proxyLabel(transport: string | null | undefined): string {
  const v = (transport ?? '').toLowerCase();
  if (v === 'vless') return 'vl';
  if (v === 'ss') return 'ss';
  return v || '—';
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

// The proxy transport carrying wire index `i` — chain[i].transport when
// shipped, else the uplink's own transport for the primary wire (index 0,
// the same no-chain case uplinkModeAt0 covers), else the name-only fallback
// entry in configured_fallbacks (always transport names, one per configured
// fallback — see its doc comment on Uplink in types.ts).
function transportAt(u: Uplink, i: number): string {
  const w = (u.configured_wire_chain ?? [])[i];
  if (w) return w.transport;
  if (i === 0) return u.transport;
  return (u.configured_fallbacks ?? [])[i - 1] ?? u.transport;
}

export interface WireLink {
  transport: string;
  tunnel: Tunnel;
  carrier: Carrier;
}

export interface WireChainView {
  links: WireLink[];
  activeIdx: number;
}

export function legWireChain(u: Uplink, leg: Leg): WireChainView {
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
  const links: WireLink[] = [];
  for (let i = 0; i < totalWires; i += 1) {
    const { tunnel, carrier } = parseWireMode(modeAt(i));
    links.push({ transport: transportAt(u, i), tunnel, carrier });
  }
  const rawActive = (leg === 'tcp' ? u.tcp_active_wire : u.udp_active_wire) ?? 0;
  const activeIdx = Math.min(Math.max(rawActive, 0), Math.max(links.length - 1, 0));
  return { links, activeIdx };
}

// ── Wire-chain combo palette (active=full-text / fallback=square redesign) ─
// Owner-approved mockup (wire-active-full.html, reviewed 2026-08-13) replaces
// cabc01c0's single-chip-per-link design (transport-hue text + tunnel-accent
// edge + de-emphasised carrier text) with one shared visual grammar for
// every link: a COMBO background keyed by the (transport, tunnel) pair, plus
// a carrier left-accent edge resolved independently (WireChain.svelte reads
// `link.carrier` directly for that part — it's already exactly 'h3'/'h2'/
// 'h1'/null, no mapping needed). The active link shows this on a chip with
// its full text; every fallback link shows it on a same-coloured square with
// no text at all — see WireChain.svelte and app.css's `.wcombo-*`/
// `.wcarrier-*`.

// The 4 owner-approved transport+tunnel combos, plus 'neutral' — the
// deliberate don't-fabricate fallback for a wire whose tunnel didn't resolve
// (a Shadowsocks wire with no *_mode field, or a bare h3/h2 token with no
// ws_/xhttp_ prefix — see parseWireMode()) or whose transport isn't one of
// the two known proxies. There is no correct combo hue to guess at in either
// case, so 'neutral' renders as a plain muted square/chip (app.css's
// `.wcombo-neutral`) instead of picking one of the 4 real combos at random.
export type ComboKey = 'vlws' | 'vlxh' | 'ssws' | 'ssxh' | 'neutral';

// (transport, tunnel) → combo key. `transport` is nullable here — unlike
// WireLink's own always-a-string field — so call sites can pass a WireLink
// straight through (`wireComboKey(link)`) while the function stays as
// defensive about its input as its siblings (proxyLabel()/
// transportFullLabel()/parseWireMode()) about data that ultimately comes off
// an untyped API boundary. Case-insensitive on transport, same as those.
export function wireComboKey(link: { transport: string | null | undefined; tunnel: Tunnel }): ComboKey {
  const t = (link.transport ?? '').toLowerCase();
  if (link.tunnel === 'ws') {
    if (t === 'vless') return 'vlws';
    if (t === 'ss') return 'ssws';
  } else if (link.tunnel === 'xhttp') {
    if (t === 'vless') return 'vlxh';
    if (t === 'ss') return 'ssxh';
  }
  return 'neutral';
}

// Full (unabbreviated) proxy-layer name for the active chip's full text —
// 'vless'/'ss', distinct from proxyLabel()'s deliberately-abbreviated 'vl'/
// 'ss' badge text used elsewhere ('ss' has no longer form to begin with —
// owner: "ss=ss not SS" — so it is already its own full label too). Falls
// back to the raw lowercased transport for anything else, same "don't
// silently vanish" rule as proxyLabel().
export function transportFullLabel(transport: string | null | undefined): string {
  const v = (transport ?? '').toLowerCase();
  if (v === 'vless') return 'vless';
  if (v === 'ss') return 'ss';
  return v || '—';
}

// Full slash-joined text for one wire link — "vless/xhttp/h3" — the active
// chip's visible text (WireChain.svelte) and the basis for a fallback
// square's tooltip ("vless/xhttp/h3 (fallback)"). Degrades by omitting
// whichever layers didn't resolve rather than fabricating them: "vless/h3"
// for a bare carrier token with no tunnel, "vless" alone for a wire with no
// mode info at all — mirrors legWireChain()'s own graceful-degradation shape.
export function wireFullText(link: WireLink): string {
  return [transportFullLabel(link.transport), link.tunnel, link.carrier].filter((part): part is string => Boolean(part)).join('/');
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

// ── Row action-button gating (Task 10) ──────────────────────────────────────
// Mirrors dashboard.html renderInstanceBody's activateBtn/softBtn construction
// (:1338-1357) as pure predicates over the row's already-computed `RowTone`,
// so the gating rules are unit-testable without a running backend or DOM —
// see wsTopology.test.ts. GroupTable.svelte turns each state into the actual
// button markup (icon/title/aria-label/disabled).

// Activate (hard switch) button state for one row. A disabled uplink
// (`admin_disabled`, tone 'off') never reaches this at all in the caller —
// GroupTable hides the whole activate/soft button group for those rows and
// renders only the power toggle — so 'hidden' here is defensive, not the
// primary path.
export type ActivateButtonState = 'live' | 'active' | 'down' | 'hidden';
export function activateButtonState(tone: RowTone): ActivateButtonState {
  if (tone === 'off') return 'hidden';
  if (tone === 'good') return 'active'; // already active — shown, disabled
  if (tone === 'bad') return 'down'; // every wire unreachable — shown, disabled
  return 'live'; // warn: healthy but passive
}

// Soft switch (cluster resume) button state. Live only on a cluster group's
// healthy-but-passive row; shown-but-disabled on the already-active row (so
// the action column doesn't reflow the instant a row becomes active); hidden
// off-cluster or on a down row. Mirrors dashboard.html's softBtn construction
// (:1351-1357).
export type SoftButtonState = 'live' | 'active' | 'hidden';
export function softButtonState(tone: RowTone, clusterResumeEnabled: boolean): SoftButtonState {
  if (tone === 'off' || !clusterResumeEnabled) return 'hidden';
  if (tone === 'good') return 'active';
  if (tone === 'warn') return 'live';
  return 'hidden'; // bad (down)
}

// ── Fingerprint chip (group header / per-uplink) ────────────────────────────
// Ported from the pre-Svelte-rewrite bins/outline-ui/src/ws/dashboard.html's
// prettyProfileName()/renderFingerprintChip()/fingerprintChip()/
// groupFingerprintIsHomogeneous()/groupFingerprintChip() (git history, that
// file's ~:610-714 as of c9db9a36~1 — removed when the html dashboard was
// replaced by this app and never ported). `process_stable`/`random`
// strategies resolve to one identity for the whole process, so every uplink
// in a group reports the same fingerprint_profile_name — in that case
// GroupTable shows a single chip in the group header instead of repeating it
// on every row; `per_host_stable` (and any future heterogeneous case) keeps
// the per-uplink chip since each uplink resolves to its own identity.

export interface FingerprintChip {
  label: string;
  title: string;
}

// dashboard.html prettyProfileName() (~:610-626). Pool ids are
// `<family>-<version>-<os>`; anything else (including "random") is shown
// verbatim/specially rather than turning into a blank chip.
export function prettyProfileName(name: string): string {
  if (!name) return '';
  if (name === 'random') return 'Random';
  const parts = name.split('-');
  if (parts.length !== 3) return name;
  const [family, version, os] = parts;
  const familyLabel = family.charAt(0).toUpperCase() + family.slice(1);
  const osLabel =
    os === 'macos' ? 'macOS' : os === 'windows' ? 'Windows' : os === 'linux' ? 'Linux' : os.charAt(0).toUpperCase() + os.slice(1);
  return `${familyLabel} ${version} ${osLabel}`;
}

// dashboard.html renderFingerprintChip() (~:631-638) — shared chip shape for
// both the per-uplink chip (heterogeneous case) and the group-header chip
// (homogeneous case).
function fingerprintChipFor(name: string, strategy: string): FingerprintChip {
  const title = strategy ? `fingerprint_profile_name = ${name} · strategy = ${strategy}` : `fingerprint_profile_name = ${name}`;
  return { label: prettyProfileName(name), title };
}

// dashboard.html fingerprintChip() (~:640-644). `null` when the uplink has
// no identity to show (strategy `none`, or no dial URL — fingerprint_profile_name
// is absent on the wire in both cases).
export function uplinkFingerprintChip(u: Uplink): FingerprintChip | null {
  const name = u.fingerprint_profile_name;
  return name ? fingerprintChipFor(name, u.fingerprint_profile_strategy || '') : null;
}

// dashboard.html groupFingerprintIsHomogeneous() (~:697-701). `false` for an
// empty group — render mode falls back to per-uplink, which renders nothing
// for an empty list anyway.
export function groupFingerprintIsHomogeneous(uplinks: Uplink[]): boolean {
  if (uplinks.length === 0) return false;
  const first = uplinks[0]?.fingerprint_profile_name ?? undefined;
  return uplinks.every((u) => (u.fingerprint_profile_name ?? undefined) === first);
}

// dashboard.html groupFingerprintChip() (~:707-714). `null` both when the
// group is heterogeneous (caller falls back to per-uplink chips) and when it
// is homogeneous-but-all-`none` (nothing to show anywhere).
export function groupFingerprintChip(uplinks: Uplink[]): FingerprintChip | null {
  if (!groupFingerprintIsHomogeneous(uplinks)) return null;
  const name = uplinks[0]?.fingerprint_profile_name;
  return name ? fingerprintChipFor(name, uplinks[0]?.fingerprint_profile_strategy || '') : null;
}

// ── RTT tooltip (full tcp+udp breakdown; visible cell text stays primaryRttMs()) ──
// Ported from dashboard.html's weightCell() RTT portion and rttAgeSuffix()
// (git history, ~:1139-1168 as of c9db9a36~1). The visible RTT cell keeps
// showing primaryRttMs()'s single collapsed figure; this is the hover detail
// with both legs and how stale each reading is.

// Age marker for an RTT reading the operator is about to trust: selection
// weights a measurement by 0.5^(age / rtt_ewma_halflife), so a number
// nothing has refreshed in minutes is not what ranking is really using.
// Ported verbatim from dashboard.html's rttAgeSuffix() (~:1164-1168),
// *including* the lack of a seconds branch — it jumps straight from "" to
// minutes at the 60_000ms mark (under a minute is normal probe cadence and
// stays unannotated), then to hours past 60 minutes.
export function rttAgeSuffix(ageMs: number | null | undefined): string {
  if (ageMs == null || ageMs < 60_000) return '';
  const minutes = Math.round(ageMs / 60_000);
  return minutes < 60 ? ` (${minutes}m old)` : ` (${Math.round(minutes / 60)}h old)`;
}

// dashboard.html weightCell()'s RTT-parts construction (~:1139-1148):
// active-wire EWMA preferred over the primary EWMA (same preference as
// primaryRttMs(), applied independently per leg here), each present leg
// rendered as `<leg>: <ms>ms<age suffix>`, joined with " · ". Empty string
// when neither leg has a reading — callers should treat that as "no
// tooltip" (e.g. omit the `title` attribute rather than show a blank one).
export function rttTooltip(u: Uplink): string {
  const tcpRtt = u.tcp_active_wire_rtt_ewma_ms ?? u.tcp_rtt_ewma_ms;
  const udpRtt = u.udp_active_wire_rtt_ewma_ms ?? u.udp_rtt_ewma_ms;
  const parts: string[] = [];
  if (tcpRtt != null) parts.push(`tcp: ${tcpRtt}ms${rttAgeSuffix(u.tcp_active_wire_rtt_age_ms)}`);
  if (udpRtt != null) parts.push(`udp: ${udpRtt}ms${rttAgeSuffix(u.udp_active_wire_rtt_age_ms)}`);
  return parts.join(' · ');
}
