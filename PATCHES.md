# Local Patches

Single source of truth for the local patches applied to the vendored crates.
*Русская версия: [PATCHES.ru.md](PATCHES.ru.md).*

The monorepo vendors and patches five upstream crates to make the HTTP/3
WebSocket path practical and the carriers' handshakes browser-shaped. The patched
copies live in `vendor/h3`, `vendor/sockudo-ws`, `vendor/quinn-proto`,
`vendor/rustls` and `vendor/hyper`, wired in through the root `Cargo.toml`
`[patch.crates-io]`. The `.patch` files in this directory are review and
maintenance artifacts; actual builds use the vendored copies.

Regenerated against:

- **h3** — crates.io `h3 0.0.8`.
- **sockudo-ws** — GitHub tag `v1.7.5` (commit `7819745`), in raw upstream
  git formatting (see the note below).
- **quinn-proto** — crates.io `quinn-proto 0.11.15`.
- **rustls** — crates.io `rustls 0.23.40`.
- **hyper** — crates.io `hyper 1.10.1`.

## Patch artifacts

| File | Covers |
|------|--------|
| [`h3-0.0.8.patch`](h3-0.0.8.patch) | all `vendor/h3` deviations from upstream `h3 0.0.8` |
| [`sockudo-ws-1.7.5.patch`](sockudo-ws-1.7.5.patch) | all `vendor/sockudo-ws/src` deviations (the one-line `Cargo.toml` change is documented below, not in the patch) |
| [`quinn-proto-0.11.15.patch`](quinn-proto-0.11.15.patch) | all `vendor/quinn-proto` deviations from upstream `quinn-proto 0.11.15` (`src/` and `Cargo.toml`) |
| [`rustls-0.23.40.patch`](rustls-0.23.40.patch) | all `vendor/rustls` deviations from upstream `rustls 0.23.40` (`src/` and `Cargo.toml`) |
| [`hyper-1.10.1.patch`](hyper-1.10.1.patch) | all `vendor/hyper` deviations from upstream `hyper 1.10.1` (`src/` only) |

## Gate modules

All production code reaches the patched API surface through five gate
modules (client h3, server h3, client QUIC, client rustls, client hyper):

- [`crates/outline-transport/src/h3/vendored.rs`](crates/outline-transport/src/h3/vendored.rs) — client
  (`Protocol::WEBSOCKET` on Extended CONNECT, `Stream::from_h3_client` +
  `WebSocketStream::from_raw`).
- [`bins/outline-ss-rust/src/server/h3/vendored.rs`](bins/outline-ss-rust/src/server/h3/vendored.rs) — server
  (the `h3::ext::Protocol` request extension, `Stream::from_h3_server` +
  `WebSocketStream::from_raw`, the restored `WebSocketServer::into_parts`,
  plus re-exports of the sockudo-ws types the server uses).
- [`crates/outline-transport/src/quic/vendored.rs`](crates/outline-transport/src/quic/vendored.rs) — client, patched
  `quinn-proto` (`TransportConfig::initial_stream_receive_window`).
- [`crates/outline-transport/src/tls_vendored.rs`](crates/outline-transport/src/tls_vendored.rs) — client, patched
  `rustls` (`ClientConfig::client_hello_shape` with `ClientHelloShape` /
  `ExtensionOrder`, `kx_group::SECP521R1`, and `apply_tls_hello_profile`, which
  turns a browser TLS hello profile — QUIC or TCP — into a `ClientHelloShape`).
- [`crates/outline-transport/src/hyper_vendored.rs`](crates/outline-transport/src/hyper_vendored.rs) — client, patched
  `hyper` (`ext::HeaderCaseMap`: `header_case_map` builds the browser's HTTP/1.1
  spelling of every header via `request_headers::h1_wire_name`, and
  `set_h1_header_case` attaches it to an `xhttp_h1` request — nothing without a
  profile).

When rebasing the vendored crates onto a new upstream, start (and ideally
end) at these gate files. CI enforces that `sockudo_ws` is referenced only
from the gate modules, and that the patched quinn-proto API
(`initial_stream_receive_window`) appears only in
`crates/outline-transport/src/quic/vendored.rs`, and that the patched rustls API
(`client_hello_shape`, `ClientHelloShape`, `ExtensionOrder`,
`kx_group::SECP521R1`) appears only in
`crates/outline-transport/src/tls_vendored.rs` (the step "invariant — patched rustls
API only behind the gate module" in `.github/workflows/ci.yml`), and that the
patched hyper API (`HeaderCaseMap`) appears only in
`crates/outline-transport/src/hyper_vendored.rs` (the step "invariant — patched
hyper API only behind the gate module"); test modules are exempt because they
impersonate the client side on purpose.

## h3 (0.0.8)

Logical changes carried by `h3-0.0.8.patch`:

1. **RFC 9220 WebSocket** (`src/ext.rs`, `src/lib.rs`) — adds
   `Protocol::WEBSOCKET` and parses/serialises `:protocol = websocket`.
   Upstream `h3 0.0.8` does not recognise it, but Extended CONNECT WebSocket
   over HTTP/3 requires this pseudo-header value.
2. **fix-h3-poll-write** (`src/connection.rs`, `src/client/stream.rs`,
   `src/server/stream.rs`) — adds `queue_send` / `poll_drain` /
   `queue_grease` / `poll_quic_finish` so `AsyncWrite::poll_write` and
   `poll_shutdown` no longer recreate the `send_data` future on every poll.
   The old code double-wrote when the QUIC send buffer was full; h3-quinn
   reports that as `H3_INTERNAL_ERROR`, which closes the entire QUIC
   connection and kills every multiplexed session on it.
3. **Vendoring trim** (`Cargo.toml`) — dev-dependencies removed so the
   workspace does not pull them.

## sockudo-ws (1.7.5)

> **Note — crate yanked.** `sockudo-ws 1.7.5` was yanked from crates.io
> (download returns `403 AccessDenied`), so the baseline is the GitHub tag
> `v1.7.5`. The vendored `src/` is kept in the **upstream git formatting**
> (not the crates.io-published reformatting), so `sockudo-ws-1.7.5.patch`
> applies directly to a clean `git clone` of that tag — no rustfmt step. The
> library `Cargo.toml` still drops the upstream `[[bin]]` / bench targets, as
> a published library crate would (so `src/bin/` is absent here and is not
> part of the patch).
>
> **Formatting drift is not prevented automatically.** rustfmt's `ignore` key
> is nightly-only, so the `ignore = ["vendor"]` line in `rustfmt.toml` is inert
> on the stable toolchain the gate runs: a bare `cargo fmt --all` *will*
> reformat `vendor/` to the project style and silently desynchronise the tree
> from this patch (that is exactly how 21 files drifted between 2026-07-11 and
> 2026-08-08). Keep `cargo fmt` scoped to the explicit package list in
> `AGENTS.md`, and revert any format-only diff under `vendor/`. To verify the
> tree still matches: clone the tag, `git apply sockudo-ws-1.7.5.patch`, and
> `diff -r` the two `src/` trees — they must be byte-identical apart from
> `src/bin/`.

Logical changes carried by `sockudo-ws-1.7.5.patch`:

1. **h3-noerror** (`src/server.rs`) — treats `ApplicationClose: H3_NO_ERROR`
   as a normal close and suppresses the false-positive `HTTP/3 accept error`
   / `HTTP/3 connection error` `eprintln!`s on a clean shutdown. Also restores
   `WebSocketServer::into_parts`, which the `outline-ss-rust` accept loop
   needs.
2. **fix-h3-poll-write** (`src/stream/transport_stream.rs`) — the sockudo half
   of the poll-write fix, applied to the live H3 WebSocket stream `Stream<Http3>`
   (`Http3StreamInner::{Server,Client}`, the type reached via `from_h3_client` /
   `from_h3_server`): `write_queued` / `shutdown_started` state machines that
   drive h3's `queue_send` / `poll_drain` / `queue_grease` / `poll_quic_finish`
   exactly once per logical write / shutdown. `poll_shutdown` additionally drains
   a still-pending `poll_write` (`write_queued.is_some()`) to completion before
   issuing `queue_grease`: otherwise a shutdown racing an un-drained downlink
   write (relay teardown under a stream-open/close burst) calls `send_data`
   while h3-quinn's send stream still has `writing = Some(..)`, which h3-quinn
   escalates to a connection-level `H3_INTERNAL_ERROR` that collapses every
   multiplexed session on the shared QUIC carrier. A third state flag,
   `send_poisoned`, closes the remaining hole: h3-quinn's `poll_ready` clears
   its `writing` slot **only on the success path**, so a drain that fails leaves
   the send side occupied while our own `write_queued` is reset — the next
   `queue_grease()` then trips the very misuse guard the drain was meant to
   avoid. Any send-side failure now poisons the stream, and `h3_shutdown_phase`
   (unit-tested) routes a poisoned stream straight to the QUIC FIN, which never
   goes through `send_data`. `poll_write` refuses a poisoned stream outright,
   for the same reason and on the same slot: the WebSocket layer keeps writing
   after a failed write — the Close frame it emits on teardown is exactly such
   a write — and that `queue_send` is itself a second `send_data` into the
   still-occupied slot. Guarding only the shutdown path left that hole open,
   and it was the one still collapsing carriers in production after the
   `send_poisoned` flag first landed. (Note: the unused `Http3ServerStream` /
   `Http3ClientStream` wrappers in `src/http3/stream.rs` are left at upstream
   vanilla — the data plane never instantiates them, so the fix lives only in
   the one live stream type.)
3. **valid-close-codes-1012-1014** (`src/error.rs`) — `Error::is_valid_code`
   accepted only `1000..=1003 | 1007..=1011 | 3000..=4999`, rejecting the
   IANA-registered 1012 (Service Restart), 1013 (Try Again Later) and 1014
   (Bad Gateway). The server sends a routine `Close 1013` ("try again later")
   per upstream target; on the HTTP/3 path that rejection turned a benign
   per-target close into a fatal carrier read error (`Invalid close code:
   1013`), flapping `ws_h3 -> ws_h2` and tearing down flows on the wire. Range
   widened to `1007..=1014` (1015 stays out — TLS, never on the wire).
4. **h3-read-buf-capacity** (`src/stream/transport_stream.rs`) — the initial
   `read_buf` capacity on the live H3 WebSocket streams drops from 64 KiB to
   32 KiB in `from_h3_client` and `from_h3_server`
   (`Http3StreamInner::{Client,Server}` — the same two constructors
   `fix-h3-poll-write` patches). The buffer is allocated eagerly per stream and
   every tunnelled flow carries its own carrier, so the reserve was paid once
   per flow; on `.104`, under a 700 MiB cgroup cap, it is part of what got the
   process OOM-killed. `BytesMut::with_capacity` sets a starting capacity rather
   than a ceiling, so a large message still grows the buffer on demand — only
   the eager reserve changes. `from_h2` (`Http2StreamInner::recv_buf`) and
   `from_quic` (`Http3StreamInner::Raw`) are deliberately left upstream-vanilla:
   the data plane never instantiates them — the same rule that keeps
   `fix-h3-poll-write` confined to the two live stream types.

**`Cargo.toml`** (kept out of the patch): the rustls-stack dependencies are
pinned with `default-features = false` and the `aws_lc_rs` provider feature
(`tokio-rustls = { features = ["aws_lc_rs", "tls12"] }`, `quinn` on
`rustls-aws-lc-rs`, `rustls` on `aws_lc_rs`) so the vendored crate stays on
the same crypto provider as the rest of the workspace and the graph keeps
exactly one `CryptoProvider` (see the single-provider invariant in the root
`AGENTS.md`).

## quinn-proto (0.11.15)

Baseline — crates.io `quinn-proto 0.11.15`. Logical changes carried by
`quinn-proto-0.11.15.patch`:

1. **advertised-stream-window** (`src/config/transport.rs`,
   `src/transport_parameters.rs`, `src/connection/mod.rs`,
   `src/connection/streams/{state,mod,recv}.rs`) — new
   `TransportConfig::initial_stream_receive_window(Option<VarInt>)`. This value
   goes into the `initial_max_stream_data_*` transport parameters and is the
   initial credit of every receive stream (including the receive half of locally
   opened bidi streams); `stream_receive_window` stays the window a stream is
   widened to when the application first polls it (`MAX_STREAM_DATA` is queued
   even if no bytes were read yet). This
   lets the H3 client advertise a browser's window in the Initial (visible to
   passive DPI) while operating with a larger one (later `MAX_STREAM_DATA`
   frames are encrypted). `None` (the default) keeps upstream behaviour; the
   server does not use the patch. `max_stream_data` computes the difference with
   `saturating_sub`, so a runtime window smaller than the advertised one cannot
   panic.
2. **browser-shaped-transport-parameters** (`src/config/transport.rs`,
   `src/transport_parameters.rs`) — `TransportConfig` options the H3 client needs
   so the transport parameters in the Initial match a browser's:
   `advertise_min_ack_delay`, `send_grease_transport_parameter`,
   `advertise_max_idle_timeout` (the local idle timer keeps working),
   `advertise_max_udp_payload_size`, `advertised_max_datagram_frame_size`,
   `version_information` (RFC 9368: v1 as chosen version, `other_versions` from fixed
   versions and per-connection GREASE slots, optionally permuted) and
   `extra_transport_parameters` (raw `(id, value)` pairs woven into random positions
   of the shared shuffled order). Limits: `extra_transport_parameters` takes at most
   2 parameters (the 3rd of the 3 slots is reserved for `version_information`) and
   values of at most 16 bytes; the setter panics otherwise. It also asserts that no
   extra id collides with an id quinn writes itself
   (`TransportParameterId::SUPPORTED`) or with `version_information` (0x11).
   `advertised_max_datagram_frame_size` must not exceed `datagram_receive_buffer_size`.
   `version_information` is client-only (chosen version is always QUIC v1).
   Defaults match upstream, and with the defaults the rng is consumed in the same
   order as upstream (the extras and `version_information` draw from it only when
   set), so the server, which does not use these options, is unaffected.
3. **browser-order-and-firefox** (`src/config/transport.rs`,
   `src/transport_parameters.rs`, `src/cid_queue.rs`, `src/connection/mod.rs`,
   `src/connection/streams/{state,mod,recv}.rs`, `src/lib.rs`) — options for the
   Safari and Firefox profiles:
   `transport_parameter_order` (`Shuffled` / `Fixed` / `Rotated`; in `Rotated` only
   the regular parameters are rotated), `initial_stream_receive_windows`
   (per-direction initial credit by stream class, with the pools of freed `Recv`
   split by class too), `advertised_active_connection_id_limit` (the remote CID ring
   buffer holds 8 entries; the limit is checked against the advertised value capped
   at 8, default 5; more than 8 active CIDs from the peer end in
   `CONNECTION_ID_LIMIT_ERROR`) and `max_ack_delay_ms` (advertised and also the
   local ACK timer). All defaults are upstream's, the rng is consumed in the
   default mode exactly as upstream, and the server does not use the options.
4. **Vendoring trim** (`Cargo.toml`) — dev-dependencies removed (upstream
   `rcgen` with default `ring` would violate the aws-lc-rs invariant).

Conformance check: apply the patch to a clean copy of crates.io 0.11.15 and
compare `diff -r src/` — byte-identical.

## Maintenance strategy (sockudo-ws)

`sockudo-ws` is yanked from crates.io (download returns `403`) and `v1.7.5`
is the last version available to pin against, so the vendored copy is
treated as a **de-facto fork we own**, not a temporary pin waiting on an
upstream fix. The practical consequences:

- **Fixes land here.** Bugs and security issues are fixed in
  `vendor/sockudo-ws/src` directly; the same change updates
  `sockudo-ws-1.7.5.patch` and both `PATCHES*.md`. We do not block a fix on
  a hypothetical upstream release.
- **Provenance is pinned to a commit, not just a tag.** The baseline is
  GitHub tag `v1.7.5` at commit `7819745`; record the commit hash so the
  vendored tree can be re-verified even if the tag is moved or the
  repository disappears — that tag is the only public baseline left now that
  crates.io serves `403`.
- **The blast radius is already small.** Production reaches the crate only
  through the gate modules above, and CI enforces it, so a rebase or an
  audit only has to understand the patched files plus the gate modules — not
  the whole crate.
- **Keep the diff minimal; do not prune unused modules — yet.** The crate
  carries code the HTTP/3 WebSocket path never exercises (`io_uring`,
  `compression` / `deflate`, `simd`, `multiplex`, most of `pubsub`).
  Deleting it would shrink the audit surface but balloon the diff against
  the `v1.7.5` tag and make every re-verify harder, so the tree stays
  byte-aligned with upstream instead. Pruning becomes an option only if we
  decide to stop tracking upstream entirely (a hard fork + rename); record
  that decision here if it is ever taken.

**Revisit / exit triggers** — reconsider the dependency when one of these
holds, not on a schedule:

- upstream `h3` gains native RFC 9220 WebSocket-over-HTTP/3 support, which
  would retire the WebSocket-stream layer and part of the patch set;
- a maintained WebSocket-over-HTTP/3 alternative appears;
- an unfixable security issue surfaces in a module we do not use, where
  excising it is cheaper than carrying it.

## rustls (0.23.40)

Baseline — crates.io `rustls 0.23.40`. Changes carried by
`rustls-0.23.40.patch`:

1. **client-hello-shape** (`src/client/client_conn.rs`, `src/client/builder.rs`,
   `src/client/hs.rs`, `src/client/common.rs`, `src/client/tls13.rs`,
   `src/client/ech.rs`, `src/msgs/handshake.rs`, `src/lib.rs`) — new
   `ClientConfig::client_hello_shape: Option<Arc<ClientHelloShape>>` (default
   `None`, set in `builder.rs`; `ClientHelloShape` and `ExtensionOrder` are
   re-exported from `rustls::client`). The H3 client uses it so the ClientHello in
   the QUIC Initial matches a browser's (JA4 included), and the TCP carriers, the
   certificate check and the HTTPS probe use it for the TCP ClientHello. Fields:
   - `omit_extended_master_secret`, `omit_ec_point_formats`,
     `omit_status_request` — do not send extensions 23 / 11 / 5;
   - `extra_extensions: Vec<(u16, Vec<u8>)>` — extensions written verbatim, ordered
     like the built-in ones; an entry with a built-in type replaces rustls' encoding,
     `pre_shared_key` entries are ignored, and the types are recorded as sent (a
     server echoing them is not an unsolicited extension). Types are not
     de-duplicated and must not collide with the GREASE values; with real
     (non-GREASE) ECH a type the inner hello compresses would be written twice —
     none of our profiles does either;
   - `grease` — BoringSSL-style RFC 8701 GREASE: random `0x?A?A` values drawn once
     per connection (after all upstream randomness, kept across a
     HelloRetryRequest), first in `cipher_suites`, `supported_groups` and
     `supported_versions`, a first `key_share` entry with the one-byte key `00`
     (dropped after an HRR that names a group), and two distinct GREASE extensions,
     the first empty, the last carrying `00` (only `pre_shared_key` follows it);
   - `extension_order: ExtensionOrder` — `Upstream` (rustls' shuffle, then ECH,
     then `pre_shared_key`), `ShuffledWithEch` (ECH shuffled with the rest,
     `pre_shared_key` last) or `Fixed(Vec<u16>)` (the listed types first, types not
     sent skipped, the rest in upstream order — so unlisted ECH comes after every
     other extension, followed only by the trailing GREASE extension, if enabled,
     and `pre_shared_key`; the GREASE extensions are first and last regardless of the
     list). The order is kept for the ClientHello after an HRR;
   - `extra_key_share_groups: Vec<NamedGroup>` — extra `key_share` entries after the
     built-in ones (groups without TLS 1.3 support or already offered are skipped).
     The client keeps their private keys, and when the ServerHello selects one of
     these groups the key exchange completes with it instead of failing
     (`tls13.rs`); an HRR is rejected as illegal if it asks for a group already
     offered this way. After an HRR without a group they are sent again, after one
     naming a group they are dropped;
   - `ech_grease_payload_lengths: Vec<u16>` — `payload` length (AEAD tag included)
     of a GREASE `encrypted_client_hello` (`ech.rs`): empty keeps rustls' sizing,
     one value is used as is, several are picked from uniformly per connection
     (rejection sampling on the config's `SecureRandom`, after the HPKE key pair
     and before the random payload). Real ECH is not affected;
   - `wire_cipher_suites: Vec<CipherSuite>` — exactly the `cipher_suites` on the
     wire, after the GREASE suite when `grease` is set, without the renegotiation
     SCSV. Empty (default): rustls' own list. Only the advertised list changes: the
     suites rustls can negotiate stay the provider's, so a ServerHello selecting a
     listed suite the provider lacks (CBC, RSA key exchange, 3DES) fails the
     handshake with an error. The list must contain every provider suite the config
     should be able to negotiate — `outline-transport` checks that, the patch does
     not;
   - `advertise_tls12: bool` — add `0303` after `0304` to the wire
     `supported_versions` even for a TLS 1.3-only config. Only the extension
     changes; suite filtering, SCSV, `extended_master_secret`, tickets and the
     ServerHello version check still follow the config's real versions, so a server
     answering TLS 1.2 fails the handshake. Not neutral for QUIC: it ignores QUIC's
     ban on TLS 1.2 and would put `0303` into a QUIC hello, so QUIC profiles keep it
     `false`. Default `false`;
   - `grease_signature_algorithms: bool` — with `grease`, a separate GREASE value
     (`0x?A?A`, its own random byte, kept across an HRR) goes first in
     `signature_algorithms`. Ignored without `grease`; the schemes accepted from the
     server are still the verifier's. Default `false`;
   - `alps: Vec<(Vec<u8>, Vec<u8>)>` — client side of ALPS (`application_settings`,
     new codepoint 17613) as `(ALPN protocol, client settings)` pairs. Non-empty:
     the hello carries 17613 listing, in ALPN order, the offered ALPN protocols that
     have an entry (none offered: no extension); it is encoded like a raw extension,
     so it takes part in `extension_order` the same way and the hello is byte-for-byte
     what the former raw 17613 entry produced. It is not recorded as sent: a 17613 in
     the ServerHello stays unsolicited, and in EncryptedExtensions (`tls13.rs`) it is
     accepted only when the negotiated ALPN protocol is in the list — otherwise, or
     without ALPN, the handshake fails (`unsupported_extension`,
     `UnsolicitedEncryptedExtension`). An accepted answer queues the protocol's
     settings (`ClientConnectionData`), and the client sends them, before its
     Certificate / Finished, as a handshake message `EncryptedExtensions` (type 8)
     holding only `application_settings`; it is part of the transcript, so the client
     Finished and the resumption secret cover it, while the application traffic
     secrets (transcript up to the server Finished) do not. Not sent when early data
     was accepted (as in BoringSSL). QUIC needs nothing extra: the message rides the
     Handshake-epoch CRYPTO data like the rest of the flight. The server's settings
     are not kept. An `extra_extensions` entry of type 17613 overrides the field
     (written verbatim, recorded as sent, no client settings, and the server's ALPS answer
     is then not answered, so a server waiting for them aborts — the Google front-end
     abort). Each settings value must fit the u16 length fields (at most 65531 bytes;
     `outline-transport` asserts it). Chrome carries its HTTP/2 SETTINGS in the client
     ALPS data; ours is empty, so the encrypted second-flight record is a few bytes
     shorter than Chrome's. Default empty.

   The four newest fields default to empty / `false`, and with those defaults a
   `Some(shape)` ClientHello and handshake are structurally identical to what they
   were before them (the QUIC profiles are unchanged on the wire; with `grease` the
   RNG stream gains one byte for the signature-algorithm GREASE value, which shifts
   the random bytes drawn after it). With `None`, the ClientHello,
   the ServerHello / HelloRetryRequest / EncryptedExtensions handling and the order in
   which randomness is drawn are byte-for-byte upstream; the server (`outline-ss-rust`) and the cluster mesh
   never set the option; every client TLS dial (TCP and QUIC carriers, the certificate check,
   the HTTPS data-path probe) does.
2. **secp521r1** (`src/crypto/aws_lc_rs/mod.rs`, `src/crypto/ring/kx.rs`) — new
   `rustls::crypto::aws_lc_rs::kx_group::SECP521R1` (ECDH P-521 via aws-lc-rs,
   offered by Safari and Firefox). It lives in a small module in
   `aws_lc_rs/mod.rs` because `ring/kx.rs` is shared with the *ring* provider,
   which lacks P-521; that file only makes `KxGroup`, its fields and
   `uncompressed_point` `pub(crate)`. The group is in neither `DEFAULT_KX_GROUPS`
   nor `ALL_KX_GROUPS`, so the defaults do not change.
3. **Vendoring trim** (`Cargo.toml`) — dev-dependencies removed, together with
   the `[[example]]` and `[[bench]]` targets (their sources, `Cargo.lock`,
   README and `.clippy.toml` are not vendored), the same way as for
   `quinn-proto`. `build.rs` is verbatim upstream.

The rustls `brotli` / `zlib` features stay off: with them the server, which shares
the vendored crate, would gain certificate compressors and start compressing its
certificate. The client's certificate decompressors live in `outline-transport`
(`brotli-decompressor`, `flate2`, `ruzstd`), always built in now that the TCP dials
use them too.

Conformance check: apply the patch to a clean copy of crates.io 0.23.40 (the
retained file set) and compare with `diff -r` — empty.

## hyper (1.10.1)

Baseline — crates.io `hyper 1.10.1`. The vendored copy is verbatim upstream
(`Cargo.toml`, `Cargo.toml.orig`, `LICENSE`, `src/`; no vendoring trim — hyper's
dev-dependencies are not resolved for a non-member path crate). Changes carried by
`hyper-1.10.1.patch`:

1. **public-header-case-map** (`src/ext/mod.rs`) — visibility only:
   `hyper::ext::HeaderCaseMap` becomes `pub` (its field stays private), and so do
   its existing `default()` (an empty map) and `append(name, orig: Bytes)`; both
   gain the doc comments `#![deny(missing_docs)]` requires. No behaviour changes:
   hyper's HTTP/1.1 client already writes each header name from a `HeaderCaseMap`
   request extension when one is present (the n-th spelling of a name with its
   n-th value, names without a spelling as before), it simply could not be built
   outside the crate. `xhttp_h1` uses it to write header names in the browser's
   case — Chrome's `sec-ch-ua*` lowercase, every other name canonical — which
   hyper's only public option, `title_case_headers` (every name Title-Case), cannot
   do. The server crates never build the map, so their wire is unchanged.

Conformance check: apply the patch to a clean copy of crates.io 1.10.1 (the
retained file set) and compare with `diff -r` — empty.

## Regenerating

To rebuild the patch artifacts after changing vendored source:

- **h3** — diff the vendored copy against a clean upstream checkout:
  ```bash
  diff against a fresh `h3 0.0.8` from crates.io, e.g. via a throwaway git
  baseline, then `git diff vendor/h3` over the changed files.
  ```
- **sockudo-ws** — diff `vendor/sockudo-ws/src` against a clean `v1.7.5`
  GitHub checkout's `src/` (both already in raw upstream formatting).
- **quinn-proto / rustls / hyper** — unpack the clean crate from crates.io into a fresh
  throwaway git repository (keeping only the vendored file set), commit it, copy the
  vendored files over it and take `git diff` as the patch; check by applying it with
  `patch -p1` to another clean copy and comparing with `diff -r` (empty).

A `cargo update` that moves `hyper` past 1.10.1 in either lockfile (root or
`android/rust`) leaves the patch as `[[patch.unused]]` and the build then fails with
E0603 (private `HeaderCaseMap`); re-vendor the new version with the patch instead.

Do not raise the upstream versions or drop `[patch.crates-io]` without a
deliberate reason: the HTTP/3 WebSocket path depends on these patches, and
`xhttp_h1`'s browser header case on the hyper one.
