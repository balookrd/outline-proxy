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
  legWireSegments,
  primaryRttMs,
  primaryLossRatio,
  lossTone,
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
    const groups: Group[] = [{ name: 'main', uplinks: [baseUplink({ active_global: true })] }];
    expect(instanceStatusTone(false, groups)).toBe('bad');
  });
  it('reachable instance with zero uplinks is warn', () => {
    expect(instanceStatusTone(true, [{ name: 'main', uplinks: [] }])).toBe('warn');
  });
  it('all healthy + at least one active + no active loss is good', () => {
    const groups: Group[] = [{ name: 'main', uplinks: [baseUplink({ active_global: true })] }];
    expect(instanceStatusTone(true, groups)).toBe('good');
  });
  it('all healthy + active but the active leg is lossy above LOSS_BAD degrades to warn', () => {
    const groups: Group[] = [
      { name: 'main', uplinks: [baseUplink({ active_global: true, tcp_carrier_loss_ratio: 0.2 })] },
    ];
    expect(instanceStatusTone(true, groups)).toBe('warn');
  });
  it('some but not all healthy is warn', () => {
    const groups: Group[] = [
      {
        name: 'main',
        uplinks: [baseUplink({ active_global: true }), baseUplink({ name: 'cloud2', tcp_healthy: false, udp_healthy: false })],
      },
    ];
    expect(instanceStatusTone(true, groups)).toBe('warn');
  });
  it('none healthy is bad', () => {
    const groups: Group[] = [{ name: 'main', uplinks: [baseUplink({ tcp_healthy: false, udp_healthy: false })] }];
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

describe('legWireSegments — dashboard.html legWireChainCell()/wireAt() (:837-950), simplified vocabulary', () => {
  it('single-wire uplink (no chain, no fallbacks) reads the top-level effective mode', () => {
    const u = baseUplink({ tcp_mode_effective: 'ws_h3', configured_wire_chain: undefined });
    expect(legWireSegments(u, 'tcp')).toEqual({ segments: ['h3'], activeIdx: 0 });
  });
  it('falls back to the configured mode when no downgrade is active (effective unset)', () => {
    const u = baseUplink({ tcp_mode: 'xhttp_h1', tcp_mode_effective: null, configured_wire_chain: undefined });
    expect(legWireSegments(u, 'tcp')).toEqual({ segments: ['xhttp'], activeIdx: 0 });
  });
  it('multi-wire chain: h3 primary, h2 fallback, ws_h1 fallback — active on the middle wire', () => {
    const chain: WireChainEntry[] = [
      { transport: 'vless', tcp_mode: 'ws_h3', tcp_mode_effective: 'ws_h3' },
      { transport: 'vless', tcp_mode: 'ws_h2', tcp_mode_effective: 'ws_h2' },
      { transport: 'vless', tcp_mode: 'ws_h1', tcp_mode_effective: 'ws_h1' },
    ];
    const u = baseUplink({ configured_fallbacks: ['vless', 'vless'], configured_wire_chain: chain, tcp_active_wire: 1 });
    expect(legWireSegments(u, 'tcp')).toEqual({ segments: ['h3', 'h2', 'ws'], activeIdx: 1 });
  });
  it('a Shadowsocks wire (no mode fields at all) falls back to the cross-leg mode, else the ws bucket', () => {
    const chain: WireChainEntry[] = [{ transport: 'ss', udp_mode: 'ws_h2', udp_mode_effective: 'ws_h2' }];
    const u = baseUplink({ transport: 'ss', configured_wire_chain: chain, tcp_mode: null, tcp_mode_effective: null });
    // tcp leg on a wire with no tcp_mode/tcp_mode_effective borrows the wire's udp_mode (mirrors dashboard.html's
    // `w.tcp_mode_effective || w.tcp_mode || w.tcp_mode || w.udp_mode` chain) before ever reaching "no info at all".
    expect(legWireSegments(u, 'tcp')).toEqual({ segments: ['h2'], activeIdx: 0 });
  });
  it('clamps an out-of-range active-wire index instead of returning undefined', () => {
    const u = baseUplink({ tcp_active_wire: 7 });
    expect(legWireSegments(u, 'tcp').activeIdx).toBe(0);
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
    expect(legWireSegments(u, 'tcp').activeIdx).toBe(0);
    expect(legWireSegments(u, 'udp').activeIdx).toBe(1);
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
