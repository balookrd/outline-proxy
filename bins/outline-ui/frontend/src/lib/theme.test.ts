import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { theme, effectiveMode, THEME_COLORS } from './theme.svelte';

// This project has no jsdom/happy-dom installed (only referenced as vitest's
// own optional peer deps) and no vitest.config setting a DOM environment, so
// tests run under vitest's default "node" environment — no real `window` or
// `document`. `poll.test.ts` already establishes the pattern for this
// codebase: stub just the global a test needs with `vi.stubGlobal` rather
// than pull in a DOM environment. That covers `effectiveMode`'s
// `window.matchMedia` branch below; the `applyTheme` meta-tag assertions from
// the task brief need a real `document` (querySelector/createElement/
// documentElement) that isn't worth hand-stubbing, so they're left as
// `.todo` — see the task report for this decision.
function stubPrefersDark(dark: boolean) {
  vi.stubGlobal('window', {
    matchMedia: (query: string) => ({
      matches: dark && query.includes('dark'),
      media: query,
      addEventListener: () => {},
      removeEventListener: () => {},
    }),
  });
}

beforeEach(() => {
  theme.mode = null;
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('THEME_COLORS', () => {
  it('matches the --bg tokens in app.css', () => {
    expect(THEME_COLORS.dark).toBe('#020617');
    expect(THEME_COLORS.light).toBe('#f4f6fb');
  });
});

describe('effectiveMode', () => {
  it('returns the explicit mode when one is set', () => {
    stubPrefersDark(true);
    theme.mode = 'light';
    expect(effectiveMode()).toBe('light');
  });

  it('falls back to the system preference when no explicit mode is set', () => {
    stubPrefersDark(true);
    expect(effectiveMode()).toBe('dark');
    stubPrefersDark(false);
    expect(effectiveMode()).toBe('light');
  });
});

describe('applyTheme', () => {
  // Needs a real `document` (querySelector/createElement/documentElement) —
  // no jsdom in this project, see the file header comment and the task report.
  it.todo('creates the theme-color meta tag and matches the effective theme');
  it.todo('updates the existing meta tag when the theme flips');
  it.todo('follows the system preference for the browser chrome when no mode is set');
});
