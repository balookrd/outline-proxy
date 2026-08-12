// Minimal global toast queue on runes, following the same module-level
// `$state` pattern as theme.svelte.ts/router.svelte.ts (a plain exported
// store, no context/provider indirection). Mounted once via
// components/layout/Toasts.svelte in App.svelte; any component calls
// `toast(...)` directly, matching dashboard.html's global `showToast()`.
export type ToastKind = 'ok' | 'error';
export interface ToastMessage {
  id: number;
  kind: ToastKind;
  text: string;
}

const DURATION_MS = 3200;

let nextId = 0;
export const toasts = $state<ToastMessage[]>([]);

export function toast(text: string, kind: ToastKind = 'ok') {
  const id = ++nextId;
  toasts.push({ id, kind, text });
  setTimeout(() => dismiss(id), DURATION_MS);
}

export function dismiss(id: number) {
  const index = toasts.findIndex((t) => t.id === id);
  if (index !== -1) toasts.splice(index, 1);
}
