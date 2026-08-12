import type { UplinkConfig, FallbackConfig } from './types';

// Plain-string/number form state for features/ws/UplinkDrawer.svelte, kept
// framework-free like lib/userForm.ts so payload-building is unit-testable
// without mounting a Svelte component. Task 8 reproduced only the legacy
// ws/uplinks.html field set; Task 8b extended it to every top-level field
// `UplinkPayload` accepts (bins/outline-ws-rust/src/http/control/
// uplinks_crud/payload.rs). Task 8c adds the per-uplink `fallbacks[]`
// repeatable sub-form (`FallbackPayload` in the same file).
export const TRANSPORTS = ['ss', 'vless'] as const;

// All four `*_mode` fields (tcp_mode/udp_mode/vless_mode/ss_mode) deserialize
// into the same backend `TransportMode` enum (crates/outline-transport/src/
// config.rs, `#[serde(rename_all = "snake_case")]`) — WsH1/H2/H3 +
// XhttpH1/H2/H3. Shared verbatim by fallback entries too: `FallbackSection`'s
// `tcp_mode`/`udp_mode`/`vless_mode`/`ss_mode` are the exact same
// `Option<TransportMode>` type as the primary wire's.
export const MODES = ['', 'ws_h1', 'ws_h2', 'ws_h3', 'xhttp_h1', 'xhttp_h2', 'xhttp_h3'] as const;

// The wire-shape field set shared by the primary uplink and one of its
// `fallbacks[]` entries — everything `FallbackPayload` accepts
// (uplinks_crud/payload.rs), which is exactly `UplinkPayload`'s field set
// minus `name`/`weight`/`fallbacks` (those are parent-uplink-only — see the
// doc comment on `FallbackPayload` in payload.rs: "no name/weight/group;
// those belong to the parent uplink"). `useShareLink` is presentation state
// (which half of the form is visible / which half buildWireFields emits),
// not itself a wire field.
export interface WireFields {
  // Share-link vs explicit mode (Task 8 review Minor #3; generalized to
  // fallbacks in Task 8c). `link` is mutually exclusive on the wire with
  // `transport` and every explicit carrier/credential field below — see
  // `expand_share_link` in bins/outline-ws-rust/src/config/load/uplinks/
  // wire_shape.rs, which is shared verbatim by the primary wire
  // (`resolve_primary_wire_shape`) and each fallback entry (`apply_link` in
  // config/load/uplinks/fallback_resolution.rs) — one Rust function, one
  // conflict rule, for both surfaces. `useShareLink` picks which half of the
  // form is shown *and* which half buildWireFields emits — never both.
  useShareLink: boolean;
  link: string;
  transport: string;
  tcpWsUrl: string;
  tcpXhttpUrl: string;
  tcpMode: string;
  udpWsUrl: string;
  udpXhttpUrl: string;
  udpMode: string;
  vlessWsUrl: string;
  vlessXhttpUrl: string;
  vlessMode: string;
  vlessId: string;
  ssWsUrl: string;
  ssXhttpUrl: string;
  ssMode: string;
  method: string;
  password: string;
  fwmark: number | null;
  ipv6First: '' | 'true' | 'false';
}

export interface UplinkFormFields extends WireFields {
  name: string;
  weight: number | null;
}

// A `[[outline.uplinks.fallbacks]]` entry has no identity/weight of its own
// (`FallbackPayload` doc comment) — its field set IS the shared wire shape,
// verbatim, so this is a plain alias rather than a second near-duplicate
// interface.
export type FallbackFormFields = WireFields;

// Create-mode default for the shared wire-shape fields. `transport` starts
// on "ss" — see emptyUplinkFields below for why that reproduces legacy
// <select> behavior. It matters slightly more for a fallback than for the
// primary uplink: `FallbackPayload.transport` has *no* backend default (a
// fallback needs `transport` or a `link`, no third option — see
// `apply_link` in bins/outline-ws-rust/src/config/load/uplinks/
// fallback_resolution.rs:44-48, `fallbacks[{idx}] requires transport`), so a
// fresh explicit-mode fallback row needs a concrete value here for the
// backend to accept it at all — same reason the TRANSPORTS <select> below
// never offers a blank option.
export function emptyWireFields(): WireFields {
  return {
    useShareLink: false,
    link: '',
    transport: 'ss',
    tcpWsUrl: '',
    tcpXhttpUrl: '',
    tcpMode: '',
    udpWsUrl: '',
    udpXhttpUrl: '',
    udpMode: '',
    vlessWsUrl: '',
    vlessXhttpUrl: '',
    vlessMode: '',
    vlessId: '',
    ssWsUrl: '',
    ssXhttpUrl: '',
    ssMode: '',
    method: '',
    password: '',
    fwmark: null,
    ipv6First: '',
  };
}

// Create-mode default. `transport` starts on "ss" (the first TRANSPORTS
// entry, only meaningful in explicit mode): uplinks.html's <select> for this
// field had no blank option (unlike tcp_mode/udp_mode/vless_mode/
// ipv6_first, which all start with `""`), so with nothing explicitly chosen
// the browser silently pre-selected "ss" and that value is what actually got
// submitted. Defaulting to "ss" here reproduces that effective behavior
// rather than inventing a blank state the legacy form never had.
// `useShareLink` starts false: explicit mode is the more common case (and
// matches Task 8's only mode).
export function emptyUplinkFields(): UplinkFormFields {
  return { ...emptyWireFields(), name: '', weight: null };
}

// Create-mode default for a freshly added fallback row ("Add fallback" in
// UplinkDrawer.svelte).
export function emptyFallbackFields(): FallbackFormFields {
  return emptyWireFields();
}

// Shared config->fields population for the wire-shape subset — reads a
// plain JSON object (either an `UplinkConfig` or a `FallbackConfig`; both
// share this field set, see `WireConfig`/`WireFields`) with the same
// mode-detection rule for both surfaces. See fieldsFromConfig's doc comment
// below for why "`link` present ⇒ share-link mode" is reliable, not just a
// good guess; the same reasoning applies unchanged to a fallback entry's own
// `link` (each fallback expands independently at config-load time, in
// `apply_link`).
function wireFieldsFromConfig(cfg: Record<string, unknown>): WireFields {
  const hasLink = typeof cfg.link === 'string' && cfg.link.trim() !== '';
  return {
    useShareLink: hasLink,
    link: hasLink ? (cfg.link as string) : '',
    transport: typeof cfg.transport === 'string' && cfg.transport ? cfg.transport : 'ss',
    tcpWsUrl: typeof cfg.tcp_ws_url === 'string' ? cfg.tcp_ws_url : '',
    tcpXhttpUrl: typeof cfg.tcp_xhttp_url === 'string' ? cfg.tcp_xhttp_url : '',
    tcpMode: typeof cfg.tcp_mode === 'string' ? cfg.tcp_mode : '',
    udpWsUrl: typeof cfg.udp_ws_url === 'string' ? cfg.udp_ws_url : '',
    udpXhttpUrl: typeof cfg.udp_xhttp_url === 'string' ? cfg.udp_xhttp_url : '',
    udpMode: typeof cfg.udp_mode === 'string' ? cfg.udp_mode : '',
    vlessWsUrl: typeof cfg.vless_ws_url === 'string' ? cfg.vless_ws_url : '',
    vlessXhttpUrl: typeof cfg.vless_xhttp_url === 'string' ? cfg.vless_xhttp_url : '',
    vlessMode: typeof cfg.vless_mode === 'string' ? cfg.vless_mode : '',
    vlessId: typeof cfg.vless_id === 'string' ? cfg.vless_id : '',
    ssWsUrl: typeof cfg.ss_ws_url === 'string' ? cfg.ss_ws_url : '',
    ssXhttpUrl: typeof cfg.ss_xhttp_url === 'string' ? cfg.ss_xhttp_url : '',
    ssMode: typeof cfg.ss_mode === 'string' ? cfg.ss_mode : '',
    method: typeof cfg.method === 'string' ? cfg.method : '',
    password: typeof cfg.password === 'string' ? cfg.password : '',
    fwmark: typeof cfg.fwmark === 'number' ? cfg.fwmark : null,
    ipv6First: cfg.ipv6_first === true ? 'true' : cfg.ipv6_first === false ? 'false' : '',
  };
}

// Edit-mode population from the `config` object /control/uplinks attaches to
// a list entry — or none, when the on-disk TOML couldn't be read
// (getUplinkConfig() in uplinks.html falls back to `{}` in that case, so the
// edit form still opens with every field blank rather than failing).
//
// Mode detection (the brief's explicit instruction): the on-disk table for
// an uplink written through `link` carries *only* `link` — payload_to_table
// writes the raw payload fields verbatim, and share-link expansion into
// transport/carrier fields happens at config-*load* time, not at rest (see
// uplinks_crud/payload.rs + the config loader). So `link` present in `config`
// is a reliable signal the uplink is in share-link mode; anything else
// (including a config with no recognizable fields at all) defaults to
// explicit mode, matching Task 8.
export function fieldsFromConfig(config: UplinkConfig | null | undefined): UplinkFormFields {
  const cfg = config ?? {};
  return {
    name: typeof cfg.name === 'string' ? cfg.name : '',
    ...wireFieldsFromConfig(cfg),
    weight: typeof cfg.weight === 'number' ? cfg.weight : null,
  };
}

// One `[[outline.uplinks.fallbacks]]` entry's config -> form fields. Same
// mode-detection rule as fieldsFromConfig, applied to a single fallback's
// own `link`/carrier fields.
export function fallbackFieldsFromConfig(config: FallbackConfig | null | undefined): FallbackFormFields {
  return wireFieldsFromConfig(config ?? {});
}

// `config.fallbacks` (the on-disk `[[outline.uplinks.fallbacks]]` array,
// proxied verbatim through table_to_json) -> the drawer's repeatable
// sub-form rows, in on-disk (priority) order. Anything that isn't an array
// (missing — the common case, an uplink with no fallbacks doesn't have the
// key at all — or a wrong type from an unexpected server response) becomes
// no rows, same "fail open to blank, not to a crash" posture
// fieldsFromConfig takes for a missing `config` itself.
export function fallbacksFromConfig(config: UplinkConfig | null | undefined): FallbackFormFields[] {
  const raw = config?.fallbacks;
  return Array.isArray(raw) ? raw.map((fb) => fallbackFieldsFromConfig(fb as FallbackConfig)) : [];
}

// Matches submitForm()'s pre-submit guard in uplinks.html: only `name` is
// required, and only on create. Extended for share-link mode: creating a
// share-link uplink with a blank `link` would submit a payload with no
// transport and no carrier URLs at all (buildUplinkPayload sends nothing
// else in this mode), which the backend would reject anyway (e.g. "requires
// tcp_ws_url") — catch it here with a clearer message instead. Edit has no
// required fields in either mode: a PATCH can touch just weight/fwmark/
// ipv6_first, leaving `link` (or the explicit fields) untouched.
export function validateUplinkForm(fields: UplinkFormFields, editing: boolean): string | null {
  if (!editing && !fields.name.trim()) {
    return 'name is required';
  }
  if (!editing && fields.useShareLink && !fields.link.trim()) {
    return 'link is required in share-link mode';
  }
  return null;
}

// A fallback row has no create/edit distinction of its own: the whole
// `fallbacks` array is always replaced wholesale on submit (see
// buildUplinkPayload's doc comment below), so every row is effectively a
// fresh declaration every time, regardless of whether the *parent* uplink is
// being created or edited. A blank link in share-link mode is therefore
// always a client-checkable mistake here — unlike the top-level form, there
// is no "leave the existing link untouched" case at this granularity (the
// *drawer* tracks "untouched" by leaving the prefilled row alone, not by a
// blank field inside it).
export function validateFallbackForm(fields: FallbackFormFields): string | null {
  if (fields.useShareLink && !fields.link.trim()) {
    return 'link is required in share-link mode';
  }
  return null;
}

// Matches collectForm() in uplinks.html: every field with a non-empty
// current value is sent, unconditionally — not a diff against the original
// config. Shared by the primary wire (buildUplinkPayload) and each fallback
// entry (buildFallbackPayload) so both surfaces emit wire fields under
// byte-identical rules — that's what guarantees the share-link/explicit
// split can never leak both onto the wire for either surface, mirroring
// `expand_share_link`'s mutual-exclusion check, which is itself shared by
// the primary wire and the fallback pre-pass on the Rust side (see
// `apply_link` in bins/outline-ws-rust/src/config/load/uplinks/
// fallback_resolution.rs). `fwmark`/`ipv6_first` sit outside the
// share-link/explicit branch on both surfaces: `LinkConflictFields` never
// gates on them (wire_shape.rs), so they're always safe to send alongside
// `link`.
export function buildWireFields(fields: WireFields): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (fields.useShareLink) {
    if (fields.link.trim()) out.link = fields.link.trim();
  } else {
    if (fields.transport.trim()) out.transport = fields.transport.trim();
    if (fields.tcpWsUrl.trim()) out.tcp_ws_url = fields.tcpWsUrl.trim();
    if (fields.tcpXhttpUrl.trim()) out.tcp_xhttp_url = fields.tcpXhttpUrl.trim();
    if (fields.tcpMode.trim()) out.tcp_mode = fields.tcpMode.trim();
    if (fields.udpWsUrl.trim()) out.udp_ws_url = fields.udpWsUrl.trim();
    if (fields.udpXhttpUrl.trim()) out.udp_xhttp_url = fields.udpXhttpUrl.trim();
    if (fields.udpMode.trim()) out.udp_mode = fields.udpMode.trim();
    if (fields.vlessWsUrl.trim()) out.vless_ws_url = fields.vlessWsUrl.trim();
    if (fields.vlessXhttpUrl.trim()) out.vless_xhttp_url = fields.vlessXhttpUrl.trim();
    if (fields.vlessMode.trim()) out.vless_mode = fields.vlessMode.trim();
    if (fields.vlessId.trim()) out.vless_id = fields.vlessId.trim();
    if (fields.ssWsUrl.trim()) out.ss_ws_url = fields.ssWsUrl.trim();
    if (fields.ssXhttpUrl.trim()) out.ss_xhttp_url = fields.ssXhttpUrl.trim();
    if (fields.ssMode.trim()) out.ss_mode = fields.ssMode.trim();
    if (fields.method.trim()) out.method = fields.method.trim();
    if (fields.password.trim()) out.password = fields.password.trim();
  }
  if (fields.fwmark !== null) out.fwmark = Math.trunc(fields.fwmark);
  if (fields.ipv6First !== '') out.ipv6_first = fields.ipv6First === 'true';
  return out;
}

// One `[[outline.uplinks.fallbacks]]` entry's payload — literally
// buildWireFields, since a fallback's field set (unlike the primary
// uplink's) IS the full wire-shape set with nothing else layered on top (no
// name, no weight; see FallbackFormFields' doc comment). Kept as its own
// named function — rather than having callers reach for buildWireFields
// directly — so call sites read symmetrically ("build one fallback" /
// "build the primary wire"), and so a fallback-only concern can grow here
// later without touching buildWireFields' shared contract.
export function buildFallbackPayload(fields: FallbackFormFields): Record<string, unknown> {
  return buildWireFields(fields);
}

// `name` is excluded whenever `editing` is true regardless of its value
// (the identity key is immutable — see merge_patch_into_table's own "name
// is deliberately not merged" comment in bins/outline-ws-rust/src/http/
// control/uplinks_crud/payload.rs). `weight` is top-level-only (no fallback
// has its own weight), so it's added here rather than in buildWireFields.
//
// `fallbacks` is **always** built fresh from the caller's current
// `fallbacks` array and included in the output — present ⇒ replace the
// whole on-disk array, including with `[]` (which clears it) — matching
// `merge_patch_into_table`'s fallbacks handling (payload.rs) exactly:
// "a present `fallbacks` field replaces the whole list... omitted (None)
// leaves the existing list untouched." The caller (UplinkDrawer.svelte)
// always knows its complete current fallback-row state — it's component
// state built fresh from `fallbacksFromConfig` on open, not a diff — so
// there's never an "I don't know, better omit it" case to reach for.
// `fallbacks` is a required parameter (not optional/defaulted) specifically
// so a future call site can't silently forget it: TypeScript will refuse to
// compile a call that omits it, rather than the omission quietly reading on
// the wire as "leave the operator's just-edited fallbacks untouched" (or,
// worse, silently clearing them if a default of `[]` had been used
// instead). See payload.rs's doc comments on `UplinkPayload::fallbacks` /
// `merge_patch_into_table` for the exact on-disk semantics this mirrors.
export function buildUplinkPayload(
  fields: UplinkFormFields,
  editing: boolean,
  fallbacks: FallbackFormFields[],
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (!editing && fields.name.trim()) out.name = fields.name.trim();
  Object.assign(out, buildWireFields(fields));
  if (fields.weight !== null) out.weight = fields.weight;
  out.fallbacks = fallbacks.map(buildFallbackPayload);
  return out;
}
