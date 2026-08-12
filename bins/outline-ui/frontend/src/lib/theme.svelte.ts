export const theme = $state({ mode: (localStorage.getItem('theme') ?? 'dark') as 'dark'|'light' });
export function applyTheme() { document.documentElement.dataset.theme = theme.mode; }
export function toggleTheme() { theme.mode = theme.mode === 'dark' ? 'light' : 'dark'; localStorage.setItem('theme', theme.mode); applyTheme(); }
