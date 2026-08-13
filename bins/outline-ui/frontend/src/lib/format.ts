export function formatRtt(ms: number | null): string {
  return ms == null ? '—' : `${Math.round(ms)}ms`;
}
export function formatLossPct(loss: number | null): string {
  if (loss == null) return '—';
  return loss === 0 ? '0%' : `${loss.toFixed(1)}%`;
}
// IP aliases: name -> CIDRs map, matching server/control/handlers.rs's
// `Option<BTreeMap<String, OneOrManyCidr>>` and ss/dashboard.html's
// parseAliases/aliasesToText (:987-999, :980-985). Textarea is one line per
// alias: `name = cidr, cidr`.
export function parseAliases(text: string): Record<string, string[]> | null {
  const out: Record<string, string[]> = {};
  for (const line of text.split(/[\n;]+/)) {
    const t = line.trim();
    if (!t) continue;
    const eq = t.indexOf('=');
    if (eq < 0) continue;
    const name = t.slice(0, eq).trim();
    const cidrs = t.slice(eq + 1).split(',').map((s) => s.trim()).filter(Boolean);
    if (name && cidrs.length) out[name] = cidrs;
  }
  return Object.keys(out).length ? out : null;
}
// Inverse of parseAliases, for prefilling the edit-drawer textarea. Accepts
// a bare string per name (not just a 1-element array) because the server's
// OneOrManyCidr round-trips a single CIDR that way — same shape User.aliases
// declares in types.ts.
export function aliasesToText(aliases: Record<string, string | string[]> | null | undefined): string {
  if (!aliases) return '';
  return Object.entries(aliases)
    .map(([name, val]) => `${name} = ${(Array.isArray(val) ? val : [val]).join(', ')}`)
    .join('\n');
}
export function initials(id: string): string {
  return id.slice(0, 2).toUpperCase();
}
