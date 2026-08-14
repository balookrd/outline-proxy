import { describe, it, expect } from 'vitest';
import {
  emptyRouteFields,
  fieldsFromConfig,
  validateRouteForm,
  buildRoutePayload,
} from './routeForm';
import type { RouteConfig } from './types';

describe('validateRouteForm', () => {
  it('non-default rule requires via', () => {
    const f = { ...emptyRouteFields(), prefixes: '10.0.0.0/8' };
    expect(validateRouteForm({ ...f, via: '' })).toMatch(/via/);
  });
  it('non-default rule requires at least one matcher', () => {
    const f = { ...emptyRouteFields(), via: 'main' };
    expect(validateRouteForm(f)).toMatch(/matcher|prefix|domain/i);
  });
  it('default rule needs no matcher', () => {
    const f = { ...emptyRouteFields(), isDefault: true, via: 'main' };
    expect(validateRouteForm(f)).toBeNull();
  });
  it('invert with domains is rejected client-side', () => {
    const f = { ...emptyRouteFields(), prefixes: '10.0.0.0/8', domains: 'x.example', via: 'drop', invert: true };
    expect(validateRouteForm(f)).toMatch(/invert/i);
  });
  it('default rule still requires via', () => {
    const f = { ...emptyRouteFields(), isDefault: true, via: '' };
    expect(validateRouteForm(f)).toMatch(/via/);
  });
});

describe('buildRoutePayload', () => {
  it('splits textarea lines into arrays, drops blanks', () => {
    const f = { ...emptyRouteFields(), prefixes: '10.0.0.0/8\n\n192.168.0.0/16 ', via: 'direct' };
    expect(buildRoutePayload(f)).toEqual({ prefixes: ['10.0.0.0/8', '192.168.0.0/16'], via: 'direct' });
  });
  it('default rule omits matchers', () => {
    const f = { ...emptyRouteFields(), isDefault: true, via: 'main', prefixes: 'ignored' };
    expect(buildRoutePayload(f)).toEqual({ default: true, via: 'main' });
  });
  it('encodes fallback kind: direct', () => {
    const f = { ...emptyRouteFields(), prefixes: '1.2.3.0/24', via: 'main', fallbackKind: 'direct' as const };
    expect(buildRoutePayload(f)).toEqual({ prefixes: ['1.2.3.0/24'], via: 'main', fallback_direct: true });
  });
  it('encodes fallback kind: drop', () => {
    const f = { ...emptyRouteFields(), prefixes: '1.2.3.0/24', via: 'main', fallbackKind: 'drop' as const };
    expect(buildRoutePayload(f)).toEqual({ prefixes: ['1.2.3.0/24'], via: 'main', fallback_drop: true });
  });
  it('encodes fallback kind: via', () => {
    const f = {
      ...emptyRouteFields(),
      prefixes: '1.2.3.0/24',
      via: 'main',
      fallbackKind: 'via' as const,
      fallbackVia: 'backup',
    };
    expect(buildRoutePayload(f)).toEqual({ prefixes: ['1.2.3.0/24'], via: 'main', fallback_via: 'backup' });
  });
  it('encodes file_poll_secs when set', () => {
    const f = { ...emptyRouteFields(), files: '/etc/outline/blocked.txt', via: 'main', filePollSecs: 30 };
    expect(buildRoutePayload(f)).toEqual({
      files: ['/etc/outline/blocked.txt'],
      via: 'main',
      file_poll_secs: 30,
    });
  });
  it('round-trips a config through fieldsFromConfig', () => {
    const cfg: RouteConfig = { prefixes: ['10.0.0.0/8'], via: 'direct', invert: false };
    expect(buildRoutePayload(fieldsFromConfig(cfg))).toEqual({ prefixes: ['10.0.0.0/8'], via: 'direct' });
  });
  it('round-trips file_poll_secs through fieldsFromConfig', () => {
    const cfg: RouteConfig = { files: ['/etc/outline/blocked.txt'], via: 'main', file_poll_secs: 45 };
    expect(buildRoutePayload(fieldsFromConfig(cfg))).toEqual({
      files: ['/etc/outline/blocked.txt'],
      via: 'main',
      file_poll_secs: 45,
    });
  });
});
