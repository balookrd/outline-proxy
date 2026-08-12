import { describe, it, expect } from 'vitest';
import { formatRtt, formatLossPct, parseAliases, aliasesToText, initials } from './format';

describe('format', () => {
  it('rtt', () => { expect(formatRtt(42)).toBe('42ms'); expect(formatRtt(null)).toBe('—'); });
  it('loss', () => {
    expect(formatLossPct(0)).toBe('0%');
    expect(formatLossPct(2.4)).toBe('2.4%');
    expect(formatLossPct(null)).toBe('—');
  });
  it('parseAliases: `name = cidr[, cidr]` per line → name→cidr[] map', () => {
    expect(parseAliases('mobile = 10.0.0.0/8')).toEqual({ mobile: ['10.0.0.0/8'] });
    expect(parseAliases('office = 192.0.2.0/24, 203.0.113.5')).toEqual({
      office: ['192.0.2.0/24', '203.0.113.5'],
    });
  });
  it('parseAliases: multiple aliases split on newline or semicolon', () => {
    const expected = { mobile: ['10.0.0.0/8'], office: ['192.0.2.0/24'] };
    expect(parseAliases('mobile = 10.0.0.0/8\noffice = 192.0.2.0/24')).toEqual(expected);
    expect(parseAliases('mobile = 10.0.0.0/8; office = 192.0.2.0/24')).toEqual(expected);
  });
  it('parseAliases: blank / whitespace / `=`-less lines are skipped, all-empty → null', () => {
    expect(parseAliases('   ')).toBeNull();
    expect(parseAliases('no-equals-here')).toBeNull();
    expect(parseAliases('bad line\nmobile = 10.0.0.0/8')).toEqual({ mobile: ['10.0.0.0/8'] });
  });
  it('aliasesToText: map → `name = cidr, cidr` per line, normalizing a bare string to one CIDR', () => {
    expect(aliasesToText({ mobile: '10.0.0.0/8', office: ['192.0.2.0/24', '203.0.113.5'] })).toBe(
      'mobile = 10.0.0.0/8\noffice = 192.0.2.0/24, 203.0.113.5',
    );
    expect(aliasesToText(null)).toBe('');
  });
  it('aliases round-trip: text → parseAliases → aliasesToText is stable', () => {
    const text = 'mobile = 10.0.0.0/8\noffice = 192.0.2.0/24, 203.0.113.5';
    expect(aliasesToText(parseAliases(text))).toBe(text);
  });
  it('initials', () => { expect(initials('iphone')).toBe('IP'); });
});
