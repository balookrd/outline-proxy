export function formatRtt(ms: number | null): string {
  return ms == null ? '—' : `${Math.round(ms)}ms`;
}
export function formatLossPct(loss: number | null): string {
  if (loss == null) return '—';
  return loss === 0 ? '0%' : `${loss.toFixed(1)}%`;
}
export function parseAliases(text: string): string[] | null {
  const parts = text.split(/[,\s]+/).map((s) => s.trim()).filter(Boolean);
  return parts.length ? parts : null;
}
export function initials(id: string): string {
  return id.slice(0, 2).toUpperCase();
}
