import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { theme, effectiveMode, applyTheme, toggleTheme, THEME_COLORS } from './theme.svelte';

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
  it('creates the theme-color meta tag and matches the effective theme', () => {
    vi.spyOn(window, 'matchMedia').mockImplementation((query: string) => ({
      matches: query.includes('dark'),
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }));
    const fav = document.createElement('link');
    fav.id = 'favicon';
    document.head.appendChild(fav);

    theme.mode = 'light';
    applyTheme();

    expect(document.documentElement.dataset.theme).toBe('light');
    const meta = document.querySelector('meta[name="theme-color"]');
    expect(meta).not.toBeNull();
    expect(meta?.getAttribute('content')).toBe(THEME_COLORS.light);
    expect(fav.getAttribute('href')).toBe('/favicon-light.png');
  });

  it('updates the existing meta tag when the theme flips', () => {
    vi.spyOn(window, 'matchMedia').mockImplementation((query: string) => ({
      matches: query.includes('dark'),
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }));

    theme.mode = 'dark';
    applyTheme();
    expect(document.querySelectorAll('meta[name="theme-color"]')).toHaveLength(1);
    expect(document.querySelector('meta[name="theme-color"]')?.getAttribute('content')).toBe(
      THEME_COLORS.dark,
    );

    toggleTheme();

    expect(theme.mode).toBe('light');
    expect(localStorage.getItem('theme')).toBe('light');
    expect(document.documentElement.dataset.theme).toBe('light');
    expect(document.querySelectorAll('meta[name="theme-color"]')).toHaveLength(1);
    expect(document.querySelector('meta[name="theme-color"]')?.getAttribute('content')).toBe(
      THEME_COLORS.light,
    );
  });

  it('follows the system preference for the browser chrome when no mode is set', () => {
    let prefersDark = true;
    vi.spyOn(window, 'matchMedia').mockImplementation((query: string) => ({
      matches: prefersDark && query.includes('dark'),
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }));

    document.documentElement.dataset.theme = 'light';
    theme.mode = null;
    applyTheme();

    expect(document.documentElement.hasAttribute('data-theme')).toBe(false);
    expect(document.querySelector('meta[name="theme-color"]')?.getAttribute('content')).toBe(
      THEME_COLORS.dark,
    );

    prefersDark = false;
    applyTheme();
    expect(document.querySelector('meta[name="theme-color"]')?.getAttribute('content')).toBe(
      THEME_COLORS.light,
    );
  });
});
