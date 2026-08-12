type Mode = 'dark' | 'light';

const stored = (typeof localStorage !== 'undefined' ? localStorage.getItem('theme') : null) as Mode | null;

// `mode: null` means "no explicit choice yet" — `applyTheme()` then removes
// `data-theme` entirely so app.css's `@media (prefers-color-scheme)` block
// governs first paint. An explicit toggle always stamps a concrete mode and
// persists it, which outranks the OS preference from then on (see app.css).
export const theme = $state<{ mode: Mode | null }>({ mode: stored });

export function applyTheme() {
  const root = document.documentElement;
  if (theme.mode) root.dataset.theme = theme.mode;
  else root.removeAttribute('data-theme'); // let @media (prefers-color-scheme) decide
}

export function toggleTheme() {
  const effective: Mode = theme.mode ?? (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  theme.mode = effective === 'dark' ? 'light' : 'dark';
  localStorage.setItem('theme', theme.mode);
  applyTheme();
}
