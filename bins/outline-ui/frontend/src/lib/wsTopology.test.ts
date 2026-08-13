import { describe, it, expect } from 'vitest';
import {
  legHealthy,
  isHealthy,
  isUplinkActive,
  legLossRatio,
  activeLegLossy,
  LOSS_WARN,
  LOSS_BAD,
  instanceStatusTone,
  instanceStatusLabel,
  uplinkRowTone,
  uplinkRowLabel,
  uplinkRole,
  parseWireMode,
  proxyLabel,
  legWireChain,
  primaryRttMs,
  primaryLossRatio,
  lossTone,
  activateButtonState,
  softButtonState,
  prettyProfileName,
  uplinkFingerprintChip,
  groupFingerprintIsHomogeneous,
  groupFingerprintChip,
  rttAgeSuffix,
  rttTooltip,
} from './wsTopology';
import type { Uplink, Group, WireChainEntry } from './types';

// Ported from bins/outline-ui/src/ws/dashboard.html's per-uplink/per-instance
// renderer (legHealth/healthy/isActive/statusTone/legWireChainCell's wireAt,
// etc.), field names verified against the real wire shape:
// ControlUplinkTopology / ControlGroupTopology / WireChainEntry in
// bins/outline-ws-rust/src/http/control/topology.rs.

function baseUplink(overrides: Partial<Uplink> = {}): Uplink {
  return {
    name: 'cloud1',
    transport: 'vless',
    tcp_mode: 'ws_h3',
    udp_mode: 'ws_h3',
    tcp_mode_effective: 'ws_h3',
    udp_mode_effective: 'ws_h3',
    weight: 10,
    tcp_healthy: true,
    udp_healthy: true,
    tcp_health_effective: null,
    udp_health_effective: null,
    tcp_rtt_ewma_ms: 42,
    udp_rtt_ewma_ms: 40,
    tcp_carrier_loss_ratio: null,
    udp_carrier_loss_ratio: null,
    last_error: null,
    active_global: false,
    active_global_reason: null,
    active_tcp: false,
    active_tcp_reason: null,
    active_udp: false,
    active_udp_reason: null,
    configured_fallbacks: [],
    tcp_active_wire: 0,
    udp_active_wire: 0,
    admin_disabled: false,
    ...overrides,
  };
}

function baseGroup(overrides: Partial<Group> = {}): Group {
  return {
    name: 'main',
    load_balancing_mode: 'active_passive',
    routing_scope: 'global',
    auto_failback: true,
    ...overrides,
  };
}

describe('legHealthy / isHealthy — dashboard.html legHealth()/healthy() (:515-522)', () => {
  it('prefers *_health_effective over *_healthy when it holds a verdict', () => {
    const u = baseUplink({ tcp_healthy: false, tcp_health_effective: true });
    expect(legHealthy(u, 'tcp')).toBe(true);
  });
  it('falls back to *_healthy when *_health_effective is null (single-wire uplink)', () => {
    const u = baseUplink({ tcp_healthy: false, tcp_health_effective: null });
    expect(legHealthy(u, 'tcp')).toBe(false);
  });
  it('isHealthy is true when neither leg is explicitly unhealthy', () => {
    expect(isHealthy(baseUplink({ tcp_healthy: true, udp_healthy: true }))).toBe(true);
  });
  it('isHealthy is false when either leg is explicitly unhealthy', () => {
    expect(isHealthy(baseUplink({ tcp_healthy: false, udp_healthy: true }))).toBe(false);
  });
  it('isHealthy treats an unmeasured leg (null) as not-unhealthy', () => {
    expect(isHealthy(baseUplink({ tcp_healthy: null, udp_healthy: null }))).toBe(true);
  });
});

describe('isUplinkActive — dashboard.html isActive() (:523)', () => {
  it('true on active_global', () => expect(isUplinkActive(baseUplink({ active_global: true }))).toBe(true));
  it('true on active_tcp alone', () => expect(isUplinkActive(baseUplink({ active_tcp: true }))).toBe(true));
  it('true on active_udp alone', () => expect(isUplinkActive(baseUplink({ active_udp: true }))).toBe(true));
  it('false when nothing is active (standby)', () => expect(isUplinkActive(baseUplink())).toBe(false));
});

describe('legLossRatio / activeLegLossy — dashboard.html :1104-1129', () => {
  it('legLossRatio reads the numeric ratio', () => {
    expect(legLossRatio(baseUplink({ tcp_carrier_loss_ratio: 0.03 }), 'tcp')).toBe(0.03);
  });
  it('legLossRatio is null when unmeasured', () => {
    expect(legLossRatio(baseUplink(), 'tcp')).toBeNull();
  });
  it('counts loss on an active leg at/above threshold', () => {
    const u = baseUplink({ active_tcp: true, tcp_carrier_loss_ratio: 0.06 });
    expect(activeLegLossy(u, LOSS_BAD)).toBe(true);
  });
  it('ignores loss on a standby leg even when far over threshold', () => {
    const u = baseUplink({
      active_tcp: true,
      active_udp: false,
      tcp_carrier_loss_ratio: 0.01,
      udp_carrier_loss_ratio: 0.9,
    });
    expect(activeLegLossy(u, LOSS_BAD)).toBe(false);
  });
  it('active_global makes both legs count', () => {
    const u = baseUplink({ active_global: true, tcp_carrier_loss_ratio: null, udp_carrier_loss_ratio: 0.2 });
    expect(activeLegLossy(u, LOSS_BAD)).toBe(true);
  });
});

describe('instanceStatusTone / instanceStatusLabel — dashboard.html statusTone() (:539-554)', () => {
  it('unreachable instance is always bad, regardless of stale group data', () => {
    const groups: Group[] = [baseGroup({ uplinks: [baseUplink({ active_global: true })] })];
    expect(instanceStatusTone(false, groups)).toBe('bad');
  });
  it('reachable instance with zero uplinks is warn', () => {
    expect(instanceStatusTone(true, [baseGroup({ uplinks: [] })])).toBe('warn');
  });
  it('all healthy + at least one active + no active loss is good', () => {
    const groups: Group[] = [baseGroup({ uplinks: [baseUplink({ active_global: true })] })];
    expect(instanceStatusTone(true, groups)).toBe('good');
  });
  it('all healthy + active but the active leg is lossy above LOSS_BAD degrades to warn', () => {
    const groups: Group[] = [baseGroup({ uplinks: [baseUplink({ active_global: true, tcp_carrier_loss_ratio: 0.2 })] })];
    expect(instanceStatusTone(true, groups)).toBe('warn');
  });
  it('some but not all healthy is warn', () => {
    const groups: Group[] = [
      baseGroup({
        uplinks: [baseUplink({ active_global: true }), baseUplink({ name: 'cloud2', tcp_healthy: false, udp_healthy: false })],
      }),
    ];
    expect(instanceStatusTone(true, groups)).toBe('warn');
  });
  it('none healthy is bad', () => {
    const groups: Group[] = [baseGroup({ uplinks: [baseUplink({ tcp_healthy: false, udp_healthy: false })] })];
    expect(instanceStatusTone(true, groups)).toBe('bad');
  });
  it('label mapping', () => {
    expect(instanceStatusLabel('good')).toBe('Healthy');
    expect(instanceStatusLabel('warn')).toBe('Degraded');
    expect(instanceStatusLabel('bad')).toBe('Offline');
  });
});

describe('uplinkRowTone / uplinkRowLabel — dashboard.html renderInstanceBody row logic (:1309-1311)', () => {
  it('admin_disabled wins over everything else', () => {
    const u = baseUplink({ admin_disabled: true, active_global: true });
    expect(uplinkRowTone(u)).toBe('off');
    expect(uplinkRowLabel(uplinkRowTone(u))).toBe('Disabled');
  });
  it('active uplink is good/Active', () => {
    const u = baseUplink({ active_tcp: true });
    expect(uplinkRowTone(u)).toBe('good');
    expect(uplinkRowLabel('good')).toBe('Active');
  });
  it('healthy-but-standby uplink is warn/Ready', () => {
    const u = baseUplink();
    expect(uplinkRowTone(u)).toBe('warn');
    expect(uplinkRowLabel('warn')).toBe('Ready');
  });
  it('unhealthy standby uplink is bad/Down', () => {
    const u = baseUplink({ tcp_healthy: false, udp_healthy: false });
    expect(uplinkRowTone(u)).toBe('bad');
    expect(uplinkRowLabel('bad')).toBe('Down');
  });
});

describe('uplinkRole — dashboard.html uplinkRole() (:1020-1026)', () => {
  it('global only', () => expect(uplinkRole(baseUplink({ active_global: true }))).toBe('global'));
  it('tcp + udp, not global', () => {
    expect(uplinkRole(baseUplink({ active_tcp: true, active_udp: true }))).toBe('tcp, udp');
  });
  it('nothing active is standby', () => expect(uplinkRole(baseUplink())).toBe('standby'));
});

describe('parseWireMode — Variant B tunnel/carrier split', () => {
  it('parses every ws_* tier', () => {
    expect(parseWireMode('ws_h3')).toEqual({ tunnel: 'ws', carrier: 'h3' });
    expect(parseWireMode('ws_h2')).toEqual({ tunnel: 'ws', carrier: 'h2' });
    expect(parseWireMode('ws_h1')).toEqual({ tunnel: 'ws', carrier: 'h1' });
  });
  it('parses every xhttp_* tier', () => {
    expect(parseWireMode('xhttp_h3')).toEqual({ tunnel: 'xhttp', carrier: 'h3' });
    expect(parseWireMode('xhttp_h2')).toEqual({ tunnel: 'xhttp', carrier: 'h2' });
    expect(parseWireMode('xhttp_h1')).toEqual({ tunnel: 'xhttp', carrier: 'h1' });
  });
  it('is case-insensitive and accepts the http1/bare h2/h3 synonyms', () => {
    expect(parseWireMode('WS_H3')).toEqual({ tunnel: 'ws', carrier: 'h3' });
    expect(parseWireMode('http1')).toEqual({ tunnel: 'ws', carrier: 'h1' });
    expect(parseWireMode('h3')).toEqual({ tunnel: null, carrier: 'h3' });
    expect(parseWireMode('h2')).toEqual({ tunnel: null, carrier: 'h2' });
  });
  it('tolerates a missing mode (Shadowsocks wire with no *_mode field)', () => {
    expect(parseWireMode(null)).toEqual({ tunnel: null, carrier: null });
    expect(parseWireMode(undefined)).toEqual({ tunnel: null, carrier: null });
  });
  it('an unrecognised token returns all-null instead of guessing', () => {
    expect(parseWireMode('quic')).toEqual({ tunnel: null, carrier: null });
  });
});

describe('proxyLabel — owner: "vless=vl not V, ss=ss not SS"', () => {
  it('vless → vl, lowercase', () => expect(proxyLabel('vless')).toBe('vl'));
  it('VLESS (any case) → vl', () => expect(proxyLabel('VLESS')).toBe('vl'));
  it('ss → ss, lowercase', () => expect(proxyLabel('ss')).toBe('ss'));
  it('falls back to the raw lowercased transport for anything else', () => expect(proxyLabel('mystery')).toBe('mystery'));
  it('missing transport renders an em dash rather than an empty badge', () => {
    expect(proxyLabel(null)).toBe('—');
    expect(proxyLabel(undefined)).toBe('—');
  });
});

describe('legWireChain — dashboard.html legWireChainCell()/wireAt() (:837-950) ordering/active-index, Variant B shape', () => {
  it('single-wire uplink (no chain, no fallbacks) reads the top-level effective mode and its own transport', () => {
    const u = baseUplink({ transport: 'vless', tcp_mode_effective: 'ws_h3', configured_wire_chain: undefined });
    expect(legWireChain(u, 'tcp')).toEqual({
      links: [{ transport: 'vless', tunnel: 'ws', carrier: 'h3' }],
      activeIdx: 0,
    });
  });
  it('falls back to the configured mode when no downgrade is active (effective unset)', () => {
    const u = baseUplink({ tcp_mode: 'xhttp_h1', tcp_mode_effective: null, configured_wire_chain: undefined });
    expect(legWireChain(u, 'tcp').links).toEqual([{ transport: 'vless', tunnel: 'xhttp', carrier: 'h1' }]);
  });
  it('multi-wire chain: h3 primary, h2 fallback, ws_h1 fallback — active on the middle wire, h1 distinct from h2/h3', () => {
    const chain: WireChainEntry[] = [
      { transport: 'vless', tcp_mode: 'ws_h3', tcp_mode_effective: 'ws_h3' },
      { transport: 'vless', tcp_mode: 'ws_h2', tcp_mode_effective: 'ws_h2' },
      { transport: 'vless', tcp_mode: 'ws_h1', tcp_mode_effective: 'ws_h1' },
    ];
    const u = baseUplink({ configured_fallbacks: ['vless', 'vless'], configured_wire_chain: chain, tcp_active_wire: 1 });
    expect(legWireChain(u, 'tcp')).toEqual({
      links: [
        { transport: 'vless', tunnel: 'ws', carrier: 'h3' },
        { transport: 'vless', tunnel: 'ws', carrier: 'h2' },
        { transport: 'vless', tunnel: 'ws', carrier: 'h1' },
      ],
      activeIdx: 1,
    });
  });
  it('a Shadowsocks wire with a real mode reads its own transport (ss), not the vless bucket', () => {
    const chain: WireChainEntry[] = [{ transport: 'ss', udp_mode: 'ws_h2', udp_mode_effective: 'ws_h2' }];
    const u = baseUplink({ transport: 'ss', configured_wire_chain: chain, tcp_mode: null, tcp_mode_effective: null });
    // tcp leg on a wire with no tcp_mode/tcp_mode_effective borrows the wire's udp_mode (mirrors dashboard.html's
    // `w.tcp_mode_effective || w.tcp_mode || w.tcp_mode || w.udp_mode` chain) before ever reaching "no info at all".
    expect(legWireChain(u, 'tcp').links).toEqual([{ transport: 'ss', tunnel: 'ws', carrier: 'h2' }]);
  });
  it('a Shadowsocks wire with genuinely no mode fields renders transport-only (null tunnel/carrier)', () => {
    const chain: WireChainEntry[] = [{ transport: 'ss' }];
    const u = baseUplink({ transport: 'ss', configured_wire_chain: chain, tcp_mode: null, tcp_mode_effective: null });
    expect(legWireChain(u, 'tcp').links).toEqual([{ transport: 'ss', tunnel: null, carrier: null }]);
  });
  it('a name-only fallback (configured_fallbacks entry, no matching wire-chain entry) still reports its own transport', () => {
    const u = baseUplink({ transport: 'vless', configured_fallbacks: ['ss'], configured_wire_chain: undefined });
    expect(legWireChain(u, 'tcp').links).toEqual([
      { transport: 'vless', tunnel: 'ws', carrier: 'h3' },
      { transport: 'ss', tunnel: null, carrier: null },
    ]);
  });
  it('clamps an out-of-range active-wire index instead of returning undefined', () => {
    const u = baseUplink({ tcp_active_wire: 7 });
    expect(legWireChain(u, 'tcp').activeIdx).toBe(0);
  });
  it('tcp and udp legs read their own independent active-wire index', () => {
    const chain: WireChainEntry[] = [
      { transport: 'vless', tcp_mode: 'ws_h3', udp_mode: 'ws_h3' },
      { transport: 'vless', tcp_mode: 'ws_h2', udp_mode: 'ws_h2' },
    ];
    const u = baseUplink({
      configured_fallbacks: ['vless'],
      configured_wire_chain: chain,
      tcp_active_wire: 0,
      udp_active_wire: 1,
    });
    expect(legWireChain(u, 'tcp').activeIdx).toBe(0);
    expect(legWireChain(u, 'udp').activeIdx).toBe(1);
  });
});

describe('primaryRttMs — dashboard.html weightCell()\'s active-wire-first preference (:1145-1146)', () => {
  it('prefers the active-wire EWMA over the primary EWMA', () => {
    const u = baseUplink({ tcp_active_wire_rtt_ewma_ms: 15, tcp_rtt_ewma_ms: 99 });
    expect(primaryRttMs(u)).toBe(15);
  });
  it('falls back to primary EWMA when the active-wire figure is absent', () => {
    const u = baseUplink({ tcp_rtt_ewma_ms: 55 });
    expect(primaryRttMs(u)).toBe(55);
  });
  it('falls back to udp when tcp has no reading at all', () => {
    const u = baseUplink({ tcp_rtt_ewma_ms: null, udp_rtt_ewma_ms: 33 });
    expect(primaryRttMs(u)).toBe(33);
  });
  it('null when neither leg has a reading', () => {
    expect(primaryRttMs(baseUplink({ tcp_rtt_ewma_ms: null, udp_rtt_ewma_ms: null }))).toBeNull();
  });
});

describe('primaryLossRatio / lossTone — combined single-column loss (worse of the two legs)', () => {
  it('takes the worse of tcp/udp when both are measured', () => {
    const u = baseUplink({ tcp_carrier_loss_ratio: 0.01, udp_carrier_loss_ratio: 0.08 });
    expect(primaryLossRatio(u)).toBeCloseTo(0.08);
  });
  it('uses whichever leg is measured when the other is not', () => {
    expect(primaryLossRatio(baseUplink({ tcp_carrier_loss_ratio: null, udp_carrier_loss_ratio: 0.03 }))).toBeCloseTo(0.03);
  });
  it('null when neither leg is measured', () => {
    expect(primaryLossRatio(baseUplink())).toBeNull();
  });
  it('lossTone thresholds match the shared LOSS_WARN/LOSS_BAD constants', () => {
    expect(lossTone(null)).toBeNull();
    expect(lossTone(0.01)).toBe('good');
    expect(lossTone(LOSS_WARN)).toBe('warn');
    expect(lossTone(0.03)).toBe('warn');
    expect(lossTone(LOSS_BAD)).toBe('bad');
    expect(lossTone(0.2)).toBe('bad');
  });
});

describe('activateButtonState — dashboard.html activateBtn gating (:1338-1344)', () => {
  it('warn (healthy but passive) is live', () => expect(activateButtonState('warn')).toBe('live'));
  it('good (already active) is shown-disabled as "active"', () => expect(activateButtonState('good')).toBe('active'));
  it('bad (down — every wire unreachable) is shown-disabled as "down"', () => expect(activateButtonState('bad')).toBe('down'));
  it('off (admin_disabled) is hidden', () => expect(activateButtonState('off')).toBe('hidden'));
});

describe('softButtonState — dashboard.html softBtn gating (:1351-1357)', () => {
  it('cluster + warn is live', () => expect(softButtonState('warn', true)).toBe('live'));
  it('cluster + good (already active) is shown-disabled as "active"', () => {
    expect(softButtonState('good', true)).toBe('active');
  });
  it('cluster + bad (down) is hidden — no soft-switching a dead uplink', () => {
    expect(softButtonState('bad', true)).toBe('hidden');
  });
  it('cluster + off (admin_disabled) is hidden', () => expect(softButtonState('off', true)).toBe('hidden'));
  it('non-cluster group hides soft regardless of tone', () => {
    expect(softButtonState('warn', false)).toBe('hidden');
    expect(softButtonState('good', false)).toBe('hidden');
  });
});

describe('prettyProfileName — dashboard.html prettyProfileName() (~:610-626)', () => {
  it('formats a <family>-<version>-<os> pool id', () => {
    expect(prettyProfileName('chrome-151-macos')).toBe('Chrome 151 macOS');
  });
  it('special-cases windows/linux os labels', () => {
    expect(prettyProfileName('firefox-152-windows')).toBe('Firefox 152 Windows');
    expect(prettyProfileName('edge-150-linux')).toBe('Edge 150 Linux');
  });
  it('capitalises an unrecognised os token verbatim', () => {
    expect(prettyProfileName('safari-26-bsd')).toBe('Safari 26 Bsd');
  });
  it('"random" gets its own label, not the 3-part parser', () => {
    expect(prettyProfileName('random')).toBe('Random');
  });
  it('a name that is not 3 hyphen-separated parts is shown verbatim', () => {
    expect(prettyProfileName('custom-profile')).toBe('custom-profile');
  });
  it('empty name is empty', () => expect(prettyProfileName('')).toBe(''));
});

describe('uplinkFingerprintChip — dashboard.html fingerprintChip() (~:640-644)', () => {
  it('builds a chip with strategy in the title when both fields are present', () => {
    const u = baseUplink({ fingerprint_profile_name: 'chrome-151-macos', fingerprint_profile_strategy: 'per_host_stable' });
    expect(uplinkFingerprintChip(u)).toEqual({
      label: 'Chrome 151 macOS',
      title: 'fingerprint_profile_name = chrome-151-macos · strategy = per_host_stable',
    });
  });
  it('omits the strategy clause from the title when strategy is absent', () => {
    const u = baseUplink({ fingerprint_profile_name: 'random', fingerprint_profile_strategy: undefined });
    expect(uplinkFingerprintChip(u)).toEqual({ label: 'Random', title: 'fingerprint_profile_name = random' });
  });
  it('null when the uplink has no fingerprint identity', () => {
    expect(uplinkFingerprintChip(baseUplink({ fingerprint_profile_name: null }))).toBeNull();
    expect(uplinkFingerprintChip(baseUplink({ fingerprint_profile_name: undefined }))).toBeNull();
  });
});

describe('groupFingerprintIsHomogeneous / groupFingerprintChip — dashboard.html groupFingerprintIsHomogeneous()/groupFingerprintChip() (~:697-714)', () => {
  it('homogeneous when every uplink shares the same fingerprint_profile_name', () => {
    const uplinks = [
      baseUplink({ name: 'a', fingerprint_profile_name: 'random', fingerprint_profile_strategy: 'random' }),
      baseUplink({ name: 'b', fingerprint_profile_name: 'random', fingerprint_profile_strategy: 'random' }),
    ];
    expect(groupFingerprintIsHomogeneous(uplinks)).toBe(true);
    expect(groupFingerprintChip(uplinks)).toEqual({
      label: 'Random',
      title: 'fingerprint_profile_name = random · strategy = random',
    });
  });
  it('homogeneous-but-all-absent is still homogeneous, with no chip to show', () => {
    const uplinks = [baseUplink({ name: 'a', fingerprint_profile_name: null }), baseUplink({ name: 'b', fingerprint_profile_name: null })];
    expect(groupFingerprintIsHomogeneous(uplinks)).toBe(true);
    expect(groupFingerprintChip(uplinks)).toBeNull();
  });
  it('heterogeneous (per_host_stable — each uplink its own identity) hides the group chip', () => {
    const uplinks = [
      baseUplink({ name: 'a', fingerprint_profile_name: 'chrome-151-macos', fingerprint_profile_strategy: 'per_host_stable' }),
      baseUplink({ name: 'b', fingerprint_profile_name: 'firefox-152-windows', fingerprint_profile_strategy: 'per_host_stable' }),
    ];
    expect(groupFingerprintIsHomogeneous(uplinks)).toBe(false);
    expect(groupFingerprintChip(uplinks)).toBeNull();
  });
  it('empty group is not homogeneous (no uplinks to agree on anything)', () => {
    expect(groupFingerprintIsHomogeneous([])).toBe(false);
    expect(groupFingerprintChip([])).toBeNull();
  });
});

describe('rttAgeSuffix — dashboard.html rttAgeSuffix() (~:1164-1168), no seconds branch', () => {
  it('a fresh/never-refreshed reading (null age) has no suffix', () => expect(rttAgeSuffix(null)).toBe(''));
  it('under a minute has no suffix (normal probe cadence)', () => expect(rttAgeSuffix(59_999)).toBe(''));
  it('exactly a minute rounds to "1m old"', () => expect(rttAgeSuffix(60_000)).toBe(' (1m old)'));
  it('minutes format below the hour mark', () => expect(rttAgeSuffix(125_000)).toBe(' (2m old)'));
  it('hours format once minutes reach 60', () => expect(rttAgeSuffix(2 * 3_600_000)).toBe(' (2h old)'));
});

describe('rttTooltip — dashboard.html weightCell() RTT portion (~:1139-1148)', () => {
  it('formats both legs exactly as the owner specified: "tcp: Xms (Ym old) · udp: Xms (Ym old)"', () => {
    const u = baseUplink({
      tcp_active_wire_rtt_ewma_ms: 228,
      tcp_active_wire_rtt_age_ms: 125_000,
      udp_active_wire_rtt_ewma_ms: 94,
      udp_active_wire_rtt_age_ms: 130_000,
    });
    expect(rttTooltip(u)).toBe('tcp: 228ms (2m old) · udp: 94ms (2m old)');
  });
  it('prefers the active-wire EWMA over the primary EWMA, per leg', () => {
    const u = baseUplink({ tcp_active_wire_rtt_ewma_ms: 15, tcp_rtt_ewma_ms: 99, udp_active_wire_rtt_ewma_ms: null, udp_rtt_ewma_ms: 40 });
    expect(rttTooltip(u)).toBe('tcp: 15ms · udp: 40ms');
  });
  it('a fresh reading (age under a minute) carries no age suffix', () => {
    const u = baseUplink({ tcp_rtt_ewma_ms: 42, tcp_active_wire_rtt_age_ms: 500, udp_rtt_ewma_ms: null });
    expect(rttTooltip(u)).toBe('tcp: 42ms');
  });
  it('a leg with no reading at all is skipped, not rendered as blank', () => {
    const u = baseUplink({ tcp_rtt_ewma_ms: null, udp_rtt_ewma_ms: 40 });
    expect(rttTooltip(u)).toBe('udp: 40ms');
  });
  it('empty string when neither leg has a reading', () => {
    expect(rttTooltip(baseUplink({ tcp_rtt_ewma_ms: null, udp_rtt_ewma_ms: null }))).toBe('');
  });
});
