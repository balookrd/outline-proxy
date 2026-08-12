import type { UplinkConfig } from './types';

// Plain-string/number form state for features/ws/UplinkDrawer.svelte, kept
// framework-free like lib/userForm.ts so payload-building is unit-testable
// without mounting a Svelte component. Task 8 reproduced only the legacy
// ws/uplinks.html field set; this extends to every top-level field
// `UplinkPayload` accepts (bins/outline-ws-rust/src/http/control/
// uplinks_crud/payload.rs), *except* `fallbacks` — that's Task 8c's
// repeatable sub-form, out of scope here.
export const TRANSPORTS = ['ss', 'vless'] as const;

// All four `*_mode` fields (tcp_mode/udp_mode/vless_mode/ss_mode) deserialize
// into the same backend `TransportMode` enum (crates/outline-transport/src/
// config.rs, `#[serde(rename_all = "snake_case")]`) — WsH1/H2/H3 +
// XhttpH1/H2/H3. Task 8's WS_MODES/VLESS_MODES split (ws-only for tcp/udp,
// ws+xhttp_h2/h3 for vless) undersold that: it predates tcp_xhttp_url/
// udp_xhttp_url/ss_* being exposed in this drawer at all, so tcp/udp/ss had
// no reason yet to offer xhttp modes. Now that those URL fields exist here
// too, all four mode selects share one full option list.
export const MODES = ['', 'ws_h1', 'ws_h2', 'ws_h3', 'xhttp_h1', 'xhttp_h2', 'xhttp_h3'] as const;

export interface UplinkFormFields {
  name: string;
  // Share-link vs explicit mode (Task 8 review Minor #3). `link` is
  // mutually exclusive on the wire with `transport` and every explicit
  // carrier/credential field — see `expand_share_link` in
  // bins/outline-ws-rust/src/config/load/uplinks/wire_shape.rs. Task 8's
  // drawer always resent `transport` (defaulted to "ss") alongside `link`,
  // so editing any share-link uplink 400'd. `useShareLink` picks which half
  // of the form is shown *and* which half buildUplinkPayload emits — never
  // both. See that function for the enforcement point.
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
  weight: number | null;
  fwmark: number | null;
  ipv6First: '' | 'true' | 'false';
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
  return {
    name: '',
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
    weight: null,
    fwmark: null,
    ipv6First: '',
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
  const hasLink = typeof cfg.link === 'string' && cfg.link.trim() !== '';
  return {
    name: typeof cfg.name === 'string' ? cfg.name : '',
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
    weight: typeof cfg.weight === 'number' ? cfg.weight : null,
    fwmark: typeof cfg.fwmark === 'number' ? cfg.fwmark : null,
    ipv6First: cfg.ipv6_first === true ? 'true' : cfg.ipv6_first === false ? 'false' : '',
  };
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

// Matches collectForm() in uplinks.html: every field with a non-empty
// current value is sent, unconditionally — not a diff against the original
// config. An edit form pre-filled from the existing config therefore resends
// its unchanged values too; only fields that were (and remain) blank stay
// omitted. `name` is excluded whenever `editing` is true regardless of its
// value (the identity key is immutable — see merge_patch_into_table's own
// "name is deliberately not merged" comment in
// bins/outline-ws-rust/src/http/control/uplinks_crud/payload.rs). Numeric
// coercion mirrors collectForm's parseFloat(weight)/parseInt(fwmark, 10);
// ipv6_first maps the tri-state select to a boolean, omitted when blank.
//
// Share-link vs explicit is a hard *structural* split, not just a UI
// convenience: `fields.useShareLink` picks one of two disjoint branches
// below, so the emitted payload can never contain both `link` and
// `transport`/an explicit carrier or credential field — even if a stale
// value lingers in the other branch's form state (e.g. the user typed a URL,
// then flipped the toggle without clearing it). That mirrors
// `expand_share_link`'s mutual-exclusion check
// (bins/outline-ws-rust/src/config/load/uplinks/wire_shape.rs) exactly, so a
// share-link edit no longer 400s the way Task 8's drawer did.
// weight/fwmark/ipv6_first are outside both branches: `expand_share_link`
// doesn't gate on them (see `LinkConflictFields`), so they're always safe to
// send alongside `link`.
export function buildUplinkPayload(fields: UplinkFormFields, editing: boolean): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (!editing && fields.name.trim()) out.name = fields.name.trim();

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

  if (fields.weight !== null) out.weight = fields.weight;
  if (fields.fwmark !== null) out.fwmark = Math.trunc(fields.fwmark);
  if (fields.ipv6First !== '') out.ipv6_first = fields.ipv6First === 'true';
  return out;
}
