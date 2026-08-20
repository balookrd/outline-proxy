# Local Patches

Single source of truth for the local patches applied to the vendored crates.
*Русская версия: [PATCHES.ru.md](PATCHES.ru.md).*

The monorepo vendors and patches two upstream crates to make the HTTP/3
WebSocket path practical. The patched copies live in `vendor/h3` and
`vendor/sockudo-ws`, wired in through the root `Cargo.toml`
`[patch.crates-io]`. The `.patch` files in this directory are review and
maintenance artifacts; actual builds use the vendored copies.

Regenerated against:

- **h3** — crates.io `h3 0.0.8`.
- **sockudo-ws** — GitHub tag `v1.7.5` (commit `7819745`), in raw upstream
  git formatting (see the note below).

## Patch artifacts

| File | Covers |
|------|--------|
| [`h3-0.0.8.patch`](h3-0.0.8.patch) | all `vendor/h3` deviations from upstream `h3 0.0.8` |
| [`sockudo-ws-1.7.5.patch`](sockudo-ws-1.7.5.patch) | all `vendor/sockudo-ws/src` deviations (the one-line `Cargo.toml` change is documented below, not in the patch) |

## Gate modules

All production code reaches the patched API surface through two gate
modules, one per side:

- [`crates/outline-transport/src/h3/vendored.rs`](crates/outline-transport/src/h3/vendored.rs) — client
  (`Protocol::WEBSOCKET` on Extended CONNECT, `Stream::from_h3_client` +
  `WebSocketStream::from_raw`).
- [`bins/outline-ss-rust/src/server/h3/vendored.rs`](bins/outline-ss-rust/src/server/h3/vendored.rs) — server
  (the `h3::ext::Protocol` request extension, `Stream::from_h3_server` +
  `WebSocketStream::from_raw`, the restored `WebSocketServer::into_parts`,
  plus re-exports of the sockudo-ws types the server uses).

When rebasing the vendored crates onto a new upstream, start (and ideally
end) at these two files. CI enforces that `sockudo_ws` is referenced only
from the gate modules; test modules are exempt because they impersonate the
client side on purpose.

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
  through the two gate modules above, and CI enforces it, so a rebase or an
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

## Regenerating

To rebuild the patch artifacts after changing vendored source:

- **h3** — diff the vendored copy against a clean upstream checkout:
  ```bash
  diff against a fresh `h3 0.0.8` from crates.io, e.g. via a throwaway git
  baseline, then `git diff vendor/h3` over the changed files.
  ```
- **sockudo-ws** — diff `vendor/sockudo-ws/src` against a clean `v1.7.5`
  GitHub checkout's `src/` (both already in raw upstream formatting).

Do not raise the upstream versions or drop `[patch.crates-io]` without a
deliberate reason: the HTTP/3 WebSocket path depends on these patches.
