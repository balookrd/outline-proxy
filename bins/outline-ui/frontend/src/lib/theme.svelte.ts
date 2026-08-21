type Mode = 'dark' | 'light';

const stored = (typeof localStorage !== 'undefined' ? localStorage.getItem('theme') : null) as Mode | null;

// `mode: null` means "no explicit choice yet" — `applyTheme()` then removes
// `data-theme` entirely so app.css's `@media (prefers-color-scheme)` block
// governs first paint. An explicit toggle always stamps a concrete mode and
// persists it, which outranks the OS preference from then on (see app.css).
export const theme = $state<{ mode: Mode | null }>({ mode: stored });

// Page background per theme, kept in sync with `--bg` in app.css. Used for the
// browser's own chrome (`<meta name="theme-color">`) so the address bar on
// mobile/PWA matches the page instead of staying on the opposite theme.
export const THEME_COLORS: Record<Mode, string> = {
  dark: '#020617',
  light: '#f4f6fb',
};

// The theme actually being rendered: the explicit choice when there is one,
// otherwise whatever the OS asks for. Both the icon and the browser chrome key
// off this, so a user on "system" still sees the correct sun/moon.
export function effectiveMode(): Mode {
  if (theme.mode) return theme.mode;
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function applyThemeColor(mode: Mode) {
  let meta = document.querySelector('meta[name="theme-color"]');
  if (!meta) {
    meta = document.createElement('meta');
    meta.setAttribute('name', 'theme-color');
    document.head.appendChild(meta);
  }
  meta.setAttribute('content', THEME_COLORS[mode]);
}

export function applyTheme() {
  const root = document.documentElement;
  if (theme.mode) root.dataset.theme = theme.mode;
  else root.removeAttribute('data-theme'); // let @media (prefers-color-scheme) decide
  applyThemeColor(effectiveMode());
}

export function toggleTheme() {
  const effective: Mode = effectiveMode();
  theme.mode = effective === 'dark' ? 'light' : 'dark';
  localStorage.setItem('theme', theme.mode);
  applyTheme();
}
