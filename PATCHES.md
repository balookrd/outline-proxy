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
- **sockudo-ws** — GitHub tag `v1.7.5`, rustfmt-normalised to the crate's
  published formatting (see the note below).

## Patch artifacts

| File | Covers |
|------|--------|
| [`h3-0.0.8.patch`](h3-0.0.8.patch) | all `vendor/h3` deviations from upstream `h3 0.0.8` |
| [`sockudo-ws-1.7.5.patch`](sockudo-ws-1.7.5.patch) | all `vendor/sockudo-ws/src` deviations (the one-line `Cargo.toml` change is documented below, not in the patch) |

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
> (download returns `403 AccessDenied`), so the patch is regenerated against
> the GitHub tag `v1.7.5` after rustfmt-normalising it to the crate's
> published formatting — the git tree otherwise differs only in whitespace /
> import order and in stripped `[[bin]]` / bench targets. The vendored copy
> `vendor/sockudo-ws` remains the authoritative source.

Logical changes carried by `sockudo-ws-1.7.5.patch`:

1. **h3-noerror** (`src/server.rs`) — treats `ApplicationClose: H3_NO_ERROR`
   as a normal close and suppresses the false-positive `HTTP/3 accept error`
   / `HTTP/3 connection error` `eprintln!`s on a clean shutdown. Also restores
   `WebSocketServer::into_parts`, which the `outline-ss-rust` accept loop
   needs.
2. **MIPS fallback** (`src/pubsub.rs`) — `CounterU64` falls back to
   `Mutex<u64>` on targets without `target_has_atomic = "64"` so `pubsub`
   builds on MIPS32 (the `release-router` build).
3. **fix-h3-poll-write** (`src/http3/stream.rs`,
   `src/stream/transport_stream.rs`) — the sockudo half of the poll-write
   fix: `write_queued` / `shutdown_started` state machines that drive h3's
   `queue_send` / `poll_drain` / `queue_grease` / `poll_quic_finish` exactly
   once per logical write / shutdown.

**`Cargo.toml`** (one line, kept out of the patch): `tokio-rustls` is set to
`default-features = false, features = ["ring", "tls12"]` so the
`release-router` build does not pull `aws-lc-sys` — this keeps the whole
workspace on `ring` (see the ring-only invariant in the root `AGENTS.md`).

## Regenerating

To rebuild the patch artifacts after changing vendored source:

- **h3** — diff the vendored copy against a clean upstream checkout:
  ```bash
  diff against a fresh `h3 0.0.8` from crates.io, e.g. via a throwaway git
  baseline, then `git diff vendor/h3` over the changed files.
  ```
- **sockudo-ws** — rustfmt-normalise a clean `v1.7.5` GitHub checkout with the
  workspace `rustfmt.toml`, then diff its `src/` against
  `vendor/sockudo-ws/src`.

Do not raise the upstream versions or drop `[patch.crates-io]` without a
deliberate reason: the HTTP/3 WebSocket path depends on these patches.
