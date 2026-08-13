import type { RouteConfig } from './types';

// Target kinds for the `via` picker beyond the concrete group names the server
// reports: the two reserved words a rule can also target.
export const TARGET_KINDS = ['direct', 'drop'] as const;

export type FallbackKind = '' | 'direct' | 'drop' | 'via';

// Plain-string form state (textareas for the list fields), framework-free so
// payload-building is unit-testable without mounting Svelte. Mirrors the
// server's RoutePayload (routes_crud/payload.rs).
export interface RouteFormFields {
  isDefault: boolean;
  // One entry per line; blanks ignored.
  prefixes: string;
  files: string;
  domains: string;
  domainFiles: string;
  filePollSecs: number | null;
  invert: boolean;
  // Group name, or a reserved 'direct' / 'drop'.
  via: string;
  fallbackKind: FallbackKind;
  fallbackVia: string;
}

export function emptyRouteFields(): RouteFormFields {
  return {
    isDefault: false,
    prefixes: '',
    files: '',
    domains: '',
    domainFiles: '',
    filePollSecs: null,
    invert: false,
    via: '',
    fallbackKind: '',
    fallbackVia: '',
  };
}

const lines = (s: string): string[] =>
  s.split('\n').map((l) => l.trim()).filter((l) => l.length > 0);

const asText = (v: unknown): string => (Array.isArray(v) ? (v as string[]).join('\n') : '');

export function fieldsFromConfig(config: RouteConfig | null | undefined): RouteFormFields {
  const c = config ?? {};
  let fallbackKind: FallbackKind = '';
  if (c.fallback_direct) fallbackKind = 'direct';
  else if (c.fallback_drop) fallbackKind = 'drop';
  else if (typeof c.fallback_via === 'string') fallbackKind = 'via';
  // A single `file`/`domain_file` folds into the multi-line textarea alongside
  // the list form — both render as one entry per line on save.
  const prefixText = asText(c.prefixes);
  const fileText = [c.file, ...(c.files ?? [])].filter((x): x is string => !!x).join('\n');
  const domText = asText(c.domains);
  const domFileText = [c.domain_file, ...(c.domain_files ?? [])].filter((x): x is string => !!x).join('\n');
  return {
    isDefault: c.default === true,
    prefixes: prefixText,
    files: fileText,
    domains: domText,
    domainFiles: domFileText,
    filePollSecs: typeof c.file_poll_secs === 'number' ? c.file_poll_secs : null,
    invert: c.invert === true,
    via: typeof c.via === 'string' ? c.via : '',
    fallbackKind,
    fallbackVia: typeof c.fallback_via === 'string' ? c.fallback_via : '',
  };
}

export function validateRouteForm(f: RouteFormFields): string | null {
  if (!f.via.trim()) return 'via is required';
  if (f.isDefault) return null; // default rule: via only, no matchers
  const hasMatcher =
    lines(f.prefixes).length > 0 ||
    lines(f.files).length > 0 ||
    lines(f.domains).length > 0 ||
    lines(f.domainFiles).length > 0;
  if (!hasMatcher) return 'a non-default rule needs at least one prefix/file/domain matcher';
  if (f.invert && (lines(f.domains).length > 0 || lines(f.domainFiles).length > 0)) {
    return 'invert applies to CIDR prefixes only — it cannot combine with domains';
  }
  if (f.fallbackKind === 'via' && !f.fallbackVia.trim()) return 'fallback group is required';
  return null;
}

export function buildRoutePayload(f: RouteFormFields): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (f.isDefault) {
    out.default = true;
    out.via = f.via.trim();
    return applyFallback(out, f);
  }
  const prefixes = lines(f.prefixes);
  const files = lines(f.files);
  const domains = lines(f.domains);
  const domainFiles = lines(f.domainFiles);
  if (prefixes.length) out.prefixes = prefixes;
  if (files.length) out.files = files;
  if (domains.length) out.domains = domains;
  if (domainFiles.length) out.domain_files = domainFiles;
  if (f.filePollSecs !== null) out.file_poll_secs = Math.trunc(f.filePollSecs);
  if (f.invert) out.invert = true;
  out.via = f.via.trim();
  return applyFallback(out, f);
}

function applyFallback(out: Record<string, unknown>, f: RouteFormFields): Record<string, unknown> {
  if (f.fallbackKind === 'direct') out.fallback_direct = true;
  else if (f.fallbackKind === 'drop') out.fallback_drop = true;
  else if (f.fallbackKind === 'via' && f.fallbackVia.trim()) out.fallback_via = f.fallbackVia.trim();
  return out;
}
