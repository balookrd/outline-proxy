import { describe, it, expect } from 'vitest';
import { formatRtt, formatLossPct, parseAliases, initials } from './format';

describe('format', () => {
  it('rtt', () => { expect(formatRtt(42)).toBe('42ms'); expect(formatRtt(null)).toBe('—'); });
  it('loss', () => {
    expect(formatLossPct(0)).toBe('0%');
    expect(formatLossPct(2.4)).toBe('2.4%');
    expect(formatLossPct(null)).toBe('—');
  });
  it('aliases split on comma/space, empty → null', () => {
    expect(parseAliases('a, b  c')).toEqual(['a', 'b', 'c']);
    expect(parseAliases('   ')).toBeNull();
  });
  it('initials', () => { expect(initials('iphone')).toBe('IP'); });
});
