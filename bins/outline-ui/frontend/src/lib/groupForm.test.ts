import { describe, it, expect } from 'vitest';
import {
  emptyGroupFields,
  fieldsFromConfig,
  validateGroupForm,
  buildGroupPayload,
} from './groupForm';
import type { GroupConfig } from './types';

describe('validateGroupForm', () => {
  it('create requires a name', () => {
    const f = { ...emptyGroupFields(), name: '' };
    expect(validateGroupForm(f, false)).toMatch(/name/i);
  });
  it('reselect requires active_passive mode', () => {
    const f = { ...emptyGroupFields(), name: 'g', mode: 'active_active', reselectMode: 'interval' as const, reselectInterval: '10h' };
    expect(validateGroupForm(f, false)).toMatch(/active_passive/);
  });
  it('reselect sync requires the at-schedule mode', () => {
    const f = { ...emptyGroupFields(), name: 'g', mode: 'active_passive', routingScope: 'global', reselectMode: 'interval' as const, reselectInterval: '10h', reselectSync: true };
    expect(validateGroupForm(f, false)).toMatch(/sync/i);
  });
  it('accepts a plain active_active group', () => {
    const f = { ...emptyGroupFields(), name: 'g', mode: 'active_active', routingScope: 'per_flow' };
    expect(validateGroupForm(f, false)).toBeNull();
  });
});

describe('buildGroupPayload', () => {
  it('emits only set key fields', () => {
    const f = { ...emptyGroupFields(), name: 'main', mode: 'active_active', routingScope: 'per_flow' };
    expect(buildGroupPayload(f, false)).toEqual({ name: 'main', mode: 'active_active', routing_scope: 'per_flow' });
  });
  it('omits name on edit (identity is immutable)', () => {
    const f = { ...emptyGroupFields(), name: 'main', mode: 'active_passive' };
    expect(buildGroupPayload(f, true)).toEqual({ mode: 'active_passive', routing_scope: 'per_flow' });
  });
  it('encodes reselect at-schedule with sync', () => {
    const f = {
      ...emptyGroupFields(),
      name: 'g', mode: 'active_passive', routingScope: 'global',
      reselectMode: 'at' as const, reselectAt: '03:00\n15:00', reselectSync: true,
    };
    expect(buildGroupPayload(f, false)).toEqual({
      name: 'g', mode: 'active_passive', routing_scope: 'global',
      reselect_at: ['03:00', '15:00'], reselect_sync: true,
    });
  });
  it('parses advanced fields by kind', () => {
    const f = { ...emptyGroupFields(), name: 'g', mode: 'active_active' };
    f.advanced.sticky_ttl_secs = '300';
    f.advanced.rtt_ewma_alpha = '0.3';
    f.advanced.auto_failback = 'false';
    expect(buildGroupPayload(f, false)).toEqual({
      name: 'g', mode: 'active_active', routing_scope: 'per_flow',
      sticky_ttl_secs: 300, rtt_ewma_alpha: 0.3, auto_failback: false,
    });
  });
  it('round-trips advanced fields through fieldsFromConfig', () => {
    const cfg: GroupConfig = { name: 'g', mode: 'active_active', sticky_ttl_secs: 120, health_weighted_selection: true };
    expect(buildGroupPayload(fieldsFromConfig(cfg), true)).toEqual({
      mode: 'active_active', routing_scope: 'per_flow', sticky_ttl_secs: 120, health_weighted_selection: true,
    });
  });
});
