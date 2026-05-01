# Changelog

All notable changes to this project are documented in this file.

This changelog covers the repository's stable git tags `v1.0.0` through `v1.3.1`; the latest stable release is `v1.3.1` (2026-04-30). The repository also uses a `nightly` tag for channel publishing; those changes are grouped under the corresponding stable release. The `## Unreleased` section captures changes that landed since `v1.3.1`.

*Русская версия: [CHANGELOG.ru.md](CHANGELOG.ru.md)*

## Unreleased

Changes since `v1.3.1` (2026-04-30):

### Added

- Extended the dynamic access-key generator to emit a second VLESS-over-XHTTP URI per user when `xhttp_path_vless` is set: the existing `<user>-vless-xhttp.<ext>` keeps `?type=xhttp&mode=packet-up` (filename and fragment unchanged for backward compatibility with already-distributed `ssconf://` links), and a new `<user>-vless-xhttp-stream-one.<ext>` carries `?type=xhttp&mode=stream-one` with a `<host-short>:<user>-xhttp-stream-one` fragment. The server already serves both wire modes on the same base path, so the user can pick whichever survives the network they land on without hand-editing the URI.
- Added L4 SNI fallback (camouflage). The new `[sni_fallback]` block peeks the TLS ClientHello before handshake and, when the SNI does not match `match_sni`, splices the raw TCP stream — including the captured ClientHello — to an upstream backend (haproxy, nginx, caddy, …) that holds its own cert for the foreign SNI. Sister of `[http_fallback]` one OSI layer below: the listener now looks like an SNI-routed haproxy frontend to passive scanners. Whitelist supports nginx-style one-label-left wildcards (`*.api.example.com`); `allow_no_sni = false` (default) sends SNI-less connections to the backend; `proxy_protocol = "v1" | "v2"` is strongly recommended so the backend logs the real client IP — without it a raw splice would surface as `127.0.0.1`. Throw-away `rustls::server::Acceptor` parses the ClientHello, captured bytes are replayed back into the local TLS terminator via a `PrependStream` wrapper when the SNI matches, or written to the backend ahead of `tokio::io::copy_bidirectional` when it doesn't. Malformed handshakes (over `max_client_hello_bytes`, default 8 KiB) close locally — junk does not get forwarded to the backend so it cannot poison its logs. Requires the main TCP listener to terminate TLS; HTTP/3 SNI is parsed by quinn before our code sees it and is out of scope. Shared PROXY-protocol encoder lifted out of `transport::fallback` into `transport::proxy_protocol` so both fallbacks emit the same wire form.
- Added L7 HTTP fallback (camouflage). The new `[http_fallback]` block reverse-proxies every request that misses an existing WebSocket / XHTTP / metrics / control / dashboard route to an external upstream (haproxy, nginx, caddy, …) instead of returning `404`, so the listener stops standing out from a regular web service. Hop-by-hop headers (RFC 7230 §6.1 + anything listed in `Connection:`) are stripped on both directions, the body streams through, and `Host` is rewritten to the backend authority (matches nginx's `proxy_set_header Host $proxy_host;`). `X-Forwarded-For`, `X-Forwarded-Proto`, and `X-Forwarded-Host` are appended/set per per-feature toggles; `X-Forwarded-Proto` reflects whether the inbound listener terminated TLS. Optional `proxy_protocol = "v1" | "v2"` prepends a HAProxy PROXY-protocol header to the upstream TCP connection so the backend logs the real client IP — destination address comes from the inbound listener's bind addr (degrades to UNKNOWN/UNSPEC for `0.0.0.0` / `[::]`). One upstream TCP connection per request (no pooling); HTTPS upstream, Unix-domain sockets, and an h3 fallback are out of scope for the MVP.
- Added `backend_proto = "h1" | "h2"` to `[http_fallback]`, controlling the HTTP wire-version the listener uses when relaying to the upstream backend. Default `"h1"` keeps existing deployments byte-identical with prior behaviour; `"h2"` switches the upstream client to prior-knowledge HTTP/2 (h2c, no ALPN), useful when the backend is a gRPC gateway or an envoy/caddy/nginx upstream configured for h2c. Independent of the inbound protocol — an HTTP/1.1 client to this listener can still be relayed to an h2 backend and vice versa. Plain HTTP only on the wire to the upstream (HTTPS upstream remains out of scope for the MVP); intended for trusted private-network or loopback backends, matching the existing `http://` MVP restriction. Lays the groundwork for the upcoming HTTP/3 fallback adapter, which will share the same `backend_proto` toggle.
- Extended `[http_fallback]` to the HTTP/3 listener via two new toggles, `apply_to_h1` (default `true`, preserves the legacy TCP-only behaviour) and `apply_to_h3` (default `false`, opt-in). With `apply_to_h3 = true`, every QUIC request that does not match an XHTTP base path, a WS-over-h3 CONNECT, or the `/` auth-root challenge is reverse-proxied to the configured upstream — the same `backend`, the same `backend_proto = "h1" | "h2"`, the same hop-by-hop / `X-Forwarded-*` rewriting as the TCP path. `X-Forwarded-Proto` is always reported as `https` since QUIC is encrypted by spec, regardless of whether `tls_cert_path` was set on the TCP listener. PROXY-protocol headers emitted on the upstream TCP socket carry `Transport=DGRAM` (`0x12` / `0x22`) so the backend can tell the origin was UDP/QUIC; v1 is rejected at config-load time when `apply_to_h3 = true` because the v1 wire form has no UDP variant. Request body is buffered up-front before forwarding (fallback traffic is typically small probes; splitting `RequestStream` for both halves was not worth the complexity for a 404-replacement path); the response body is streamed chunk-by-chunk back over QUIC so a masquerade backend serving a large file or an SSE feed flows through without holding the whole response in RAM. Trailers are forwarded in both directions when the chosen `backend_proto` carries them. Auth-root challenges (`http_root.auth = true` for `/`) keep priority over the fallback on the h3 path, mirroring how the axum router pins `/` ahead of the wildcard fallback on the TCP path.

### Fixed

- Extend the `http/1.1` last-resort trailer to the XHTTP `mode=packet-up` access-key URI (`alpn=h3,h2,http/1.1` when `[server.h3]` is configured, `alpn=h2,http/1.1` otherwise). Packet-up is the only XHTTP wire-mode that works on h1 — each packet is its own short request/response, so the carrier never needs the h2 frame interleaving (or h3 streams) that stream-one's single bidi POST requires. The server's axum handler has always accepted packet-up over both HTTP/1.1 and HTTP/2; only the URI was advertising the narrower subset, so the dial path already supports what the URI now declares. Stream-one's URI keeps the shorter `alpn=h3,h2` list — listing `http/1.1` there would still invite a 505 on every dial. The `AlpnCarrier` enum splits `Xhttp` into `XhttpPacketUp` (h1-trailer) / `XhttpStreamOne` (no trailer), and the `XhttpMode` carrier dispatch in the access-key generator picks the matching variant per artifact, so the URI is now fully mode-aware. Bonus: clients behind a CDN that strips h2 ALPN now have a working path on the packet-up URI instead of falling through to the WS one.
- Append `http/1.1` as the last-resort fallback on the WS-VLESS access-key URI (`alpn=h3,h2,http/1.1` when `[server.h3]` is configured, `alpn=h2,http/1.1` otherwise). Classic WebSocket Upgrade over HTTP/1.1 is the universal floor — old clients that cannot speak h2 Extended CONNECT (RFC 8441) or h3 Extended CONNECT (RFC 9220) still match a transport instead of timing out on a too-narrow ALPN list. XHTTP URIs deliberately keep the shorter `alpn=h3,h2` list because `stream-one` returns 505 over h1 (h1 cannot full-duplex the request body / response body interleaving stream-one needs); listing `http/1.1` there would invite the client to pick a transport that immediately bounces the dial. The split is captured by a new `AlpnCarrier` enum so the WS and XHTTP code paths share `preferred_alpn_list` but diverge on the trailer.
- Extend the ALPN preference list (`alpn=h3,h2` when `[server.h3]` is configured, `alpn=h2` otherwise) to **every** TLS-carrying VLESS access-key URI — both the WS variant and both XHTTP variants. Previously only the XHTTP URIs carried it; the WS URI still defaulted to whatever the client picked, which for xray-family clients meant HTTP/1.1 and a measurable RTT cost (h2 Extended CONNECT per RFC 8441 / h3 Extended CONNECT per RFC 9220 are both faster paths). The shared `preferred_alpn_list` helper computes the list once from the deployment topology so the WS and XHTTP code paths cannot drift. Plain HTTP (`ws://`) URIs still skip the parameter — ALPN is a TLS extension.
- Pin the ALPN preference list (`alpn=h3,h2` when `[server.h3]` is configured, `alpn=h2` otherwise) on every TLS-carrying VLESS-XHTTP access-key URI so xray-family clients (`happ`, `hiddify`, `v2rayN`) negotiate h2 / h3 instead of falling through to HTTP/1.1. Stream-one over h1 fails server-side because hyper's HTTP/1.1 server cannot full-duplex (request body + response body interleaving needs h2 frame multiplexing or h3 streams), so an h1-only ALPN negotiation drops every stream-one POST with 505 — which surfaced as "TLS handshake error" in `happ`'s ping diagnostic until the user manually added `alpn=h3,h2` in the client UI. h3 is listed first when the QUIC listener is up so dual-stack clients prefer the lower-RTT carrier and only fall back to h2 when UDP/QUIC is blocked. Comma is percent-encoded on the wire (`alpn=h3%2Ch2`), per RFC 3986. Plain HTTP (`ws://`) deployments skip the parameter entirely — ALPN is a TLS extension; emitting it on a non-TLS URI would be ignored noise. Existing already-distributed `ssconf://` links keep working unchanged because the URI shape is a superset (a parameter was added, none renamed or removed).
- Accept the bare-`<base>` URL shape for XHTTP stream-one — what xray's `OpenStream` produces when `mode = "stream-one"` is configured. xray's client passes `sessionId=""` to `OpenStream`, and `ApplyMetaToRequest` skips the path-append when the id is empty, leaving the wire URL at `<base>` (or `<base>/` after path normalisation). Our previous router only registered `<base>/<id>` and `<base>/<id>/<seq>`, so every sessionless stream-one POST 404'd into the fallback. The new `xhttp_handler_no_session` mints a fresh server-side id per request — every stream-one carrier is fully self-contained (request body = uplink, response body = downlink, no companion GET to attach against), so a per-request id is exactly what the registry expects. Both `<base>` and `<base>/` shapes are routed because xray-style clients differ on whether path normalisation adds the trailing slash. Mirror match is added to the HTTP/3 dispatcher's `match_xhttp_path`. The temporary `xhttp_handler_no_session` GET on this shape returns 405 — there is no companion request the GET can attach to. Discovered via `hiddify` traffic landing in the new `[http_fallback]` debug log with `method=POST uri=/<base>/`.
- The `[http_fallback]` adapter now logs an `http fallback received unmatched request` debug line on every request that lands in it — `method`, `uri`, `version`, `peer_addr`. The XHTTP rollout against xray-family clients (`happ`, `hiddify`, `v2rayN`) keeps surfacing wire-shape mismatches that 404 silently into the fallback; having the request line in the log saves a tcpdump round on every new compatibility report. Cheap (one line per request, debug-level).
- Auto-detect XHTTP stream-one when a POST arrives without a `seq` and without `?mode=stream-one`, matching xray / sing-box's wire-level convention. xray clients do not echo the `?mode=` selector on the wire — the carrier is implied by URL shape: a POST to `<base>/<id>` (no seq segment) means stream-one / stream-up, a POST to `<base>/<id>/<seq>` means packet-up. Our previous dispatcher required the explicit `?mode=stream-one` query, so xray-family clients (`happ`, `hiddify`, `v2rayN`) hit the packet-up branch on every stream-one POST, got 400 for the missing seq, and retried until they timed out — a sibling of the path-seq fix above. The dispatcher now treats POST + no seq as stream-one (regardless of `?mode=`) on both the axum (h2) and HTTP/3 paths; an explicit `?mode=stream-one` with a seq is still rejected as a client mismatch. Existing access-key URIs that carry `?mode=stream-one` keep working unchanged because the explicit query still pins the carrier when present; the change only widens what the server accepts.
- Made the XHTTP packet-up uplink URL recognise the xray / sing-box default placement, so xray-family clients (`happ`, `hiddify`, `v2rayN`, etc.) stop timing out on every test connection. Previously the server only registered the `<base>/<id>` route shape and read the per-packet `seq` from the `X-Xhttp-Seq` header — the convention `outline-ws-rust` ships with. xray clients default to `PlacementPath` for both session and seq and put `seq` into the URL itself, sending POSTs to `<base>/<id>/<seq>`; without a matching route those POSTs 404'd silently and the client retried with fresh session ids until it gave up. Both the axum router (HTTP/1.1, HTTP/2) and the HTTP/3 dispatcher now match either shape; the path-based seq wins over the header form when a client supplies both, so a future client that sends both gets a deterministic answer instead of a silent disagreement. `<base>/<id>/<seq>` accepts only POSTs (a GET on this shape returns 400) and only for `?mode=packet-up` (stream-one has no per-packet seq); a non-numeric `<seq>` segment is left for the global not-found handler so a typo cannot accidentally hit the GET branch. Existing `outline-ws-rust` clients keep using the header form unchanged.

### Changed

- Re-aligned the bilingual README so EN and RU mirror one-to-one again. Restored the missing "Plain Shadowsocks Socket Service" deployment-mode section in the RU side, renumbered the SNI/HTTP fallback modes accordingly, moved "HTTP/3 Performance Tuning" to its EN position (after "Observability", before "Production Operations"), refreshed the Prometheus metric bullet list to reflect current emitters (`smaps`-derived virtual-mapping gauges, thread count, etc.) instead of the legacy `[heap]` / allocator-trim wording, and brought the "VLESS over WebSocket" feature-table row up to parity with the EN note about availability over h1/h2/h3. Section count, bullet count, table count and code-fence count now match across all five bilingual docs (README, ARCHITECTURE, SESSION-RESUMPTION, PATCHES, CHANGELOG).
- Rewrote the CHANGELOG header and split the prior "Unreleased" backlog into per-tag sections (`## 1.3.1`, `## 1.3.0`, `## 1.2.0`, `## 1.1.0`) attributed to the actual git tags shipped between `v1.0.2` and `v1.3.1`. Previously every change since `v1.0.2` lived under "Unreleased", which was misleading because four stable releases had already cut. The Unreleased section now only carries work that landed after `v1.3.1`.

## 1.3.1 - 2026-04-30

### Added

- Added cross-repo SS-TCP coverage on the raw-QUIC carrier — the matrix cell flagged as missing in the handoff brief. Server side reuses `serve_h3_server` with `H3Alpn::Ss` and the shared self-signed CA+leaf cert; client side dials through the public `outline_transport::connect_ss_tcp_quic` with `https://` URL and the same `Chacha20IetfPoly1305` cipher / `secret-b` master key the other SS tests use. No resume variant: SS-over-raw-QUIC has no wire-level slot for a resume token (no HTTP headers, and the Addons-TLV mechanism is VLESS-only).
- Extended the cross-repo coverage to the dispatcher's WS-h2 → WS-h1 fallback path with the resume token preserved end-to-end. Two new tests — VLESS-WS, SS-WS — bind a plain-TCP h1-only axum server with `OrphanRegistry` enabled, get client A through `WsH1` to capture an `X-Outline-Session` token, then dial client B with `WsH2` against the same `ws://` URL. The h2 prior-knowledge preface lands on hyper's h1 codec as a malformed h1 request, the dispatcher records the failure and retries on h1 with the same `X-Outline-Resume` header — the server reattaches the parked upstream and `TransportStream::downgraded_from()` reports the original `WsH2`. (XHTTP is excluded — the dispatcher has no h1 fallback for XHTTP; XHTTP minimum is h2.) Plain TCP avoids the tungstenite-vs-override-slot mismatch the h1 path would hit over TLS — tungstenite uses webpki for `wss://` and does not consult our cross-repo TLS override.
- Extended the cross-repo coverage to the dispatcher's h3→h2 fallback path with the resume token preserved end-to-end. Three new tests — XHTTP, VLESS-WS, SS-WS — bind a TLS-only axum server with `OrphanRegistry` enabled, get client A through h2 to capture an `X-Outline-Session` token, then point client B at the same `https://`/`wss://` URL with `XhttpH3` / `WsH3` requested. With no UDP listener on the port, h3 connect times out (10 s) and the dispatcher falls back to h2 carrying the same resume header — server reattaches the parked upstream and `TransportStream::downgraded_from()` reports the original h3 mode. Driving these tests surfaced and fixed a six-year-old client-side h2 dialer bug (double slash in `:path`); see ws-rust commit d268ce9.
- Extended the cross-repo session-resumption coverage to h3 carriers: XHTTP packet-up over h3 reattaches via the same `X-Outline-Resume-Capable` / `X-Outline-Session` header pair the h2 path uses (uplink-EOF driven through the test-only `XhttpRegistry::first_session` + `close_uplink` since the client crate has no FIN signal), VLESS-TCP over WebSocket-h3 (RFC 9220) reattaches via a graceful WS Close on the QUIC bidi stream, and SS-TCP over WebSocket-h3 reattaches via Close on the writer's priority channel with the same 100 ms wait the h2 path uses to let `AbortOnDrop` not race the spawned writer task.
- Extended the cross-repo session-resumption coverage beyond XHTTP h2: VLESS-TCP over WebSocket-h2 reattaches the parked upstream after a graceful WS Close from client A, VLESS-TCP over raw QUIC reattaches via the VLESS Addons `RESUME_ID` opcode (`0x11`), and SS-TCP over WebSocket-h2 reattaches via the same `X-Outline-Session` header pair the production listener emits. The SS-WS path needs a 100 ms wait between sending Close on the writer's priority channel and dropping the wrapper — the writer's `AbortOnDrop` would otherwise kill the spawned task before the Close frame hits the wire and the relay would treat the disconnect as an error rather than a parkable shutdown.
- Extended the cross-repo carrier matrix to cover WebSocket-h1 and WebSocket-h3 (RFC 9220) for both VLESS and Shadowsocks. The VLESS suite now exercises packet-up h2/h3 + stream-one h2/h3 over XHTTP, plus VLESS-TCP over WS-h1 / WS-h2 / WS-h3 / raw-QUIC. The SS suite now covers SS-TCP plain plus SS-TCP over WS-h1 / WS-h2 / WS-h3. h3 carriers (XHTTP h3, WS-h3) share a single self-signed cert installed once via `outline_transport::install_test_tls_root`; the WS-h3 path mandates `wss://` URLs, the WS-h1/h2 path mandates `ws://`.
- Added cross-repo end-to-end Shadowsocks coverage: SS over plain TCP (server's `serve_ss_tcp_listener`, client splits a raw `TcpStream` and wraps with `TcpShadowsocksWriter::connect_socket` / `TcpShadowsocksReader::new_socket`) and SS over WebSocket-h2 (server's default `/tcp` axum route, client splits a `TransportStream` from `connect_websocket_with_resume` and wraps with the WS-flavoured `connect` / `new` constructors). Cipher is `Chacha20IetfPoly1305`, master key is derived client-side via `CipherKind::derive_master_key` (re-exported from `shadowsocks-crypto` for the same reason `TargetAddr` was earlier).
- Added cross-repo end-to-end VLESS coverage on top of the XHTTP suite: VLESS-TCP over WebSocket-h2 (plain TCP, `ws://` URL) and VLESS-TCP over raw QUIC (TLS+QUIC, `vless` ALPN, self-signed cert installed on the client via `outline_transport::install_test_tls_root`). Both dial through the public client surface (`connect_websocket_with_resume`, `connect_vless_tcp_quic_with_resume`) and exchange a real VLESS handshake against a local TCP echo upstream.
- Added cross-repo end-to-end XHTTP coverage: a new test module drives the real `outline-ws-rust` client crate (sibling repo, pulled in as a dev-dep with a relative-path entry) against this server in a single tokio process. Five sub-cases — packet-up h2, stream-one h2, and h2 resume across two consecutive dials carrying the same `X-Outline-Session` token over plain TCP, plus packet-up h3 and stream-one h3 over a self-signed TLS+QUIC endpoint with the cert installed on the client via the new `outline_transport::install_test_tls_root` knob. The resume case drives the uplink-EOF directly via `XhttpSession::close_uplink` because the client crate has no FIN signal yet; h3→h2 fallback with cross-carrier resume is deferred (10 s QUIC connect timeout per failed dial).
- Added regression coverage for the XHTTP downlink ring's mid-flight GET-drop / reattach contract: a GET response dropped before the session ends does not tear the session down, the downlink slot is released, and a fresh GET on the same path id reads bytes pushed after the disconnect.
- Extended VLESS-over-XHTTP with the `stream-one` wire mode alongside the existing `packet-up`. The server now picks the carrier per request from the URL query: `?mode=stream-one` selects a single bidirectional POST whose request body carries the uplink and whose response body carries the downlink, while the absence of the query (or `?mode=packet-up`) keeps the GET+POST pair behaviour. Stream-one rejects HTTP/1.1 with 505 because plain h1 cannot full-duplex; on h3 the bidi QUIC stream is split via `RequestStream::split` so uplink and downlink halves run on dedicated tasks. The same base path serves both modes — clients on the same `xhttp_path_vless` can pick whichever survives the network they land on.
- Wired cross-transport session resumption through the XHTTP carrier. When `[session_resumption]` is enabled the XHTTP handler reads `X-Outline-Resume-Capable` / `X-Outline-Resume` off the first GET or POST that creates a session, mints `X-Outline-Session` exactly once per session, and stashes the token on `XhttpSession::issued_resume_id` so every subsequent attach (reconnecting GET, late POST) surfaces the same value to the client. The minted `ResumeContext` is threaded straight into `run_vless_relay`, so the existing per-protocol park-on-drop / take-on-resume machinery just works — including across a carrier switch (a client whose `xhttp_h3` dial fails can fall back to `xhttp_h2` carrying the same token, and the server re-attaches the parked VLESS upstream instead of opening a fresh one).
- Added VLESS-over-XHTTP packet-up listener for VLESS, sharing the existing VLESS relay through a new `WsSocket` adapter so TCP, UDP, mux.cool/XUDP, and session resumption all work over h1, h2, and h3 without reimplementation. Wire side: GET on `<base>/<id>` opens the long-lived downlink, POSTs on the same URL with `X-Xhttp-Seq` carry the uplink. A reorder buffer absorbs out-of-order POSTs from h2-multiplexed clients; the downlink ring survives mid-flight GET drops (CDN ~100 s cut-off) so the next GET on the same id resumes from where the previous one stopped. Each response carries a random `X-Padding` header (100–1024 bytes of URL-safe ASCII) plus SSE-style masquerade headers (`Content-Type: text/event-stream`, `Cache-Control: no-store, no-cache, must-revalidate`, `Pragma: no-cache`, `X-Accel-Buffering: no`) to defeat passive size/shape fingerprinting. Configured via `xhttp_path_vless` (top-level + per-user override); validation rejects path collisions with WS / TCP / UDP. The dynamic access-key generator emits an extra `vless://...?type=xhttp&mode=packet-up&path=...` URI per user when set, accepted as-is by xray, sing-box, Hiddify, v2rayNG, and Shadowrocket.

## 1.3.0 - 2026-04-29

### Changed

- Replaced the `tokio::sync::Mutex<bool>` flags guarding the raw-QUIC oversize-record stream's magic-prefix state with `AtomicBool`. The previous layout took two async mutexes per record (`send` + `pending_magic` on send, `recv` + `expect_magic` on recv), forcing two extra `.await` points on the hot path even though each flag only flips once from `true` to `false` and access is already serialised by the outer `send`/`recv` mutex. Datagrams that exceed `Connection::max_datagram_size()` now spend two fewer task yields per record on this fallback channel.

## 1.2.0 - 2026-04-28

### Added

- Added `tuning.ws_data_channel_capacity` to make the per-session WebSocket writer fan-in bounded mpsc capacity configurable. Defaults: `16` / `64` / `128` for `small` / `medium` / `large` profiles. The previous hard-coded `16` was sized for memory-constrained multi-session deployments and starved high-bandwidth single-tenant TUN clients during bursty video traffic — short WS-writer stalls back-pressured the upstream TCP read and the player's playback buffer underran. The default profile (`large`) now restores adequate throughput headroom; memory-constrained deployments can set the override to `16` to keep the prior behaviour.
- Added cross-transport session resumption for SS-over-WebSocket, single-target VLESS-over-WebSocket, single-target VLESS-UDP over WebSocket, VLESS mux over WebSocket, SS-UDP over WebSocket and **VLESS-TCP over raw QUIC** (opt-in via `[session_resumption]`, off by default). When enabled, the server mints a 16-byte Session ID, returns it in the `X-Outline-Session` response header on WebSocket Upgrade (HTTP/1.1, HTTP/2, HTTP/3), and parks the live upstream into an in-memory orphan registry on disconnect instead of tearing it down. A subsequent connect on any WebSocket transport carrying `X-Outline-Resume: <hex>` re-attaches to the parked upstream after authenticating the same user, skipping the upstream connect. For VLESS mux the entire `MuxState` — every TCP and UDP sub-connection inside it — is parked **atomically**; UDP sub-conns are reattached via the shared socket reference (no back-buffer, packets in-flight while parked may be dropped, matching UDP loss-tolerance). Single-target VLESS-UDP works the same way: the connected `UdpSocket` is preserved across the WS reconnect along with the partial 2-byte-length-prefixed frame buffer. SS-UDP-over-WS streams are connectionless across the WebSocket — one stream may register multiple `(user, fwmark, target)` NAT entries — so park snapshots the *list of NAT keys* this stream owns and detaches its sender from each (`detach_session_for_stream` is matched by a stream-unique `u64` so a concurrent reconnect cannot trample the slot); resume re-points each surviving entry at the new sender on the first authenticated datagram, without re-binding any upstream socket. Raw-QUIC has no HTTP headers, so the negotiation rides inside the VLESS request Addons TLV: tag `0x10 RESUME_CAPABLE`, tag `0x11 RESUME_ID`; the response carries `0x10 SESSION_ID` and `0x11 RESUME_RESULT`. Raw-QUIC TCP parks under the same `Parked::Tcp(Vless)` shape used by VLESS-over-WS, so a client that loses raw QUIC can fall back to VLESS-over-WS and resume the same upstream transparently. The parked entry records which proxy protocol authenticated the original session — cross-protocol or cross-shape resume requests (SS↔VLESS, single↔mux, tcp↔udp, ss-udp↔vless-udp) are rejected. Direct SS-UDP (no WebSocket tunneling) remains out of scope by spec. Owner-mismatched resumes are reported externally as `unknown` to avoid an existence oracle. Per-user (`orphan_per_user_cap = 4`) and global (`orphan_global_cap = 10000`) caps bound memory; a periodic sweeper evicts entries past `orphan_ttl_tcp_secs` (default 30 s). New metrics: `outline_ss_orphan_park_total{kind}`, `_resume_hit_total{kind}`, `_resume_miss_total{reason}`, `_evicted_total{kind,reason}`, `_current{kind}` — `kind` is `tcp`, `vless_udp_single`, `vless_mux` or `ss_udp_stream`. UDP single-target and raw-QUIC paths remain out of scope; see `docs/SESSION-RESUMPTION.md` for the wire format and roadmap.
- Added raw VLESS-over-QUIC and Shadowsocks-over-QUIC (no WebSocket, no HTTP/3 framing). The same `h3_listen` QUIC endpoint multiplexes them by ALPN: a new `[server.h3].alpn` list (default `["h3"]`) selects the protocols advertised — `h3` keeps the existing HTTP/3 + WebSocket-over-HTTP/3 path, `vless` carries one VLESS request per QUIC bidi stream (TCP target spliced on the stream; UDP target uses the bidi stream as a control/lifetime anchor and exchanges packets as QUIC datagrams prefixed with a 4-byte big-endian session_id), `ss` carries one SS-AEAD TCP session per bidi stream and one SS-AEAD UDP packet per QUIC datagram (routed through the same NAT table and replay store as the plain UDP listener). Adds the `quic` protocol label to existing metrics. The `mux.cool` VLESS command is rejected on raw QUIC — open additional QUIC streams instead.
- Added VLESS mux.cool / XUDP support over WebSocket: TCP and UDP sub-connections share a single VLESS stream (xray/happ/hiddify-compatible), with per-packet destination addressing on Keep frames and up to 8 concurrent sub-connections per session. The XUDP `GlobalID` is parsed but cross-connection session reuse is not yet wired.

### Security

- Bounded the HTTP/3 listener with two semaphores to prevent DoS via unbounded task fan-out: connection accepts are capped at 4096 (matching the TLS/shadowsocks listeners), and per-stream WebSocket handlers are capped globally at 65536 across all QUIC connections. Previously a client could open many QUIC connections and multiply per-connection stream limits into unbounded `tokio::spawn` fan-out.
- Capped the SS-2022 anti-replay session store via `tuning.udp_replay_max_sessions` (profile defaults 16k/64k/256k; `0` disables). Previously a client with a valid key could rotate `client_session_id` on every packet and inflate the store unbounded until the next idle sweep. Drops at the cap are exposed as `outline_ss_udp_replay_store_full_dropped_total{user,protocol}`.
- Moved config file persistence on control-plane mutations off the tokio worker: the user list mutex is now a `tokio::sync::Mutex` and `persist_users` runs via `spawn_blocking`, so a slow-disk write (NFS, USB) no longer stalls the runtime while the lock is held.
- VLESS-over-WebSocket now sends a graceful WebSocket Close frame on parser/auth failure instead of dropping the channels silently. Previously a probe with a wrong VLESS version byte or unknown UUID got an abrupt FIN/RST without any RFC 6455 Close — a sharp signature that distinguishes VLESS from a benign WebSocket endpoint and from the SS-over-WS path (which already sent a Close on auth failure). Upstream TCP/UDP connect failures still map to Close 1013 (Try Again Later); parser/auth failures map to a plain Close, mirroring the SS path.
- Added a probe-resistance sink on rejected handshakes for VLESS and Shadowsocks across WebSocket, plain TCP and raw-QUIC transports. After a parser/auth rejection the connection is held open and inbound traffic is drained to /dev/null until the existing handshake timeout (`SS_TCP_HANDSHAKE_TIMEOUT_SECS = 30`) or a 64 KiB byte cap fires; only then does the close arrive. This collapses the close-timing fingerprint that previously distinguished VLESS (parser bails on the 18th byte) from SS (AEAD path stalls until enough bytes for an authenticated frame) from a benign endpoint. Sinked sessions are reported in metrics as `disconnect_reason="handshake_rejected"`, split out from `error` so genuine relay errors are not skewed by the long sink-mode lifetime.

### Changed

- Renamed the per-user `vless_ws_path` config key to `ws_path_vless` for parity with `ws_path_tcp` / `ws_path_udp`. The control-plane JSON field and dashboard form use the new name as well. **Breaking change**: configs and API clients using the old name fail on `deny_unknown_fields`.
- Sharded the SS-2022 UDP session-key cache into 16 independent LRU partitions keyed by an FNV-1a mix of `(user_index, salt[..8])`. The previous single-mutex LRU serialized every UDP datagram across all worker threads — at thousands of packets per second the lock acquire itself surfaced as decrypt-path jitter, with back-to-back hits on unrelated `(user, salt)` pairs blocking each other. Lookups and inserts now touch only one shard, dropping the contention floor by 16× without any change to the public API; the configured total capacity is divided evenly between shards (rounded up).

### Fixed

- Fixed VLESS over HTTP/3: the H3 router never inspected the VLESS path set, so Extended CONNECT requests to any configured `vless_ws_path` were answered with 404. VLESS is now routed on H3 with parity to Axum (TCP, UDP, mux.cool/XUDP).
- Fixed the HTTP listener drain timer firing 10 s after startup regardless of any shutdown signal. The previous attempt to bound `axum::serve` shutdown wrapped the entire serve future in a `tokio::time::timeout`, so plain HTTP and metrics listeners died on every fresh start with `connections did not drain within shutdown timeout` in the journal. The drain bound now races the serve future against a `shutdown.cancelled().then(sleep(10s))` future, so the 10-second cap only applies after `SIGTERM`/`SIGINT` actually fires.

## 1.1.0 - 2026-04-24

### Added

- Added configurable H2/H3 resource tuning profiles (`small`, `medium`, `large`) with optional per-field `[tuning]` overrides.
- Added process-wide `udp_max_concurrent_relay_tasks` semaphore for capping concurrent UDP relay tasks.
- Added Grafana panel for UDP relay drops broken down by transport, protocol, and drop reason.
- Added cooperative graceful shutdown on `SIGTERM` and `SIGINT`.
- Added install-script version checks and nightly commit SHA resolution.
- Added regression coverage for WebSocket and HTTP/3 UDP NAT reconnect behavior.
- Added a Russian translation for `PATCHES.md`.
- Added randomized upstream IPv6 source selection from a configured prefix or interface.
- Added bounded TLS listener with graceful drain on shutdown.
- Added periodic WebSocket Ping (every 60s) over TCP to keep client `WS_READ_IDLE_TIMEOUT` alive.
- Added DNS singleflight to coalesce concurrent misses on the same host/port, with test coverage for coalescing and error recovery.
- Added a Grafana panel for UDP replay drops by user and protocol.

### Security

- Added Shadowsocks-2022 UDP anti-replay: duplicate `packet_id`s within the session window are rejected by a per-session 1024-bit sliding bitmap keyed by client session ID (so replays to a different target cannot bypass the filter). Drops are exposed as `outline_ss_udp_replay_dropped_total{user,protocol}`.
- Hardened root HTTP authentication with a constant-time password compare and removed a redundant derivation step on the auth hot path.
- Capped the Shadowsocks stream AEAD nonce counter at 2^32 invocations per direction to stay within AEAD safety limits.

### Changed

- Moved tuning parameters (`client_active_ttl_secs`, `udp_nat_idle_timeout_secs`, `udp_max_concurrent_relay_tasks`) from top-level config fields into `TuningProfile` inside `[tuning]`. **Breaking change**: configs with old top-level keys fail on `deny_unknown_fields`.
- Split the metrics module into focused submodules (`labels`, `registry`, `guards`, `sampler`, `render`).
- Consolidated transport session lifecycle and error classification into shared helpers, eliminating duplicated match blocks across TCP/UDP and WS/H3 paths.
- Split large server, transport, crypto, and config modules into smaller submodules for maintainability.
- Migrated the metrics stack to `metrics` and `metrics-exporter-prometheus`.
- Decoupled UDP NAT internals from transport-specific response handling.
- Continued hot-path optimization work across DNS cache, crypto, route maps, and metrics labels to reduce allocations and lock contention, including a cached monotonic clock (shared atomic) and read-locked fast paths for NAT entry lookup and replay-window checks.
- Unified parts of server logging and general internal naming for clarity.
- Reduced TCP upstream connect timeout from 10s to 5s.
- Relaxed systemd sandbox to allow `AF_NETLINK` so `getifaddrs` works for outbound IPv6 interface selection.
- Documented outbound IPv6 prefix/interface options in the Russian README and sample configs.

### Fixed

- Fixed H3 internal stack errors being silently classified as client disconnects; they now surface as `DisconnectReason::Error`.
- Fixed QUIC connection cycling by adding server-side keep-alive pings.
- Fixed HTTP/3 double-write paths that could trigger `H3_INTERNAL_ERROR` during write and shutdown.
- Fixed NAT entry reuse when a client session reconnects.
- Fixed TCP-over-H3 teardown symmetry when the client closes the connection.
- Treated unknown-user decrypt attempts as a handled condition instead of surfacing them as server errors.
- Fixed NAT eviction to drop uninitialised cells, keeping the active-entries metric honest.
- Fixed UDP NAT idle timer to only refresh on delivered responses, preventing stuck entries from extending their lifetime.
- Fixed HTTP/3 to send WebSocket Close 1013 on upstream connect failure (parity with TCP path).
- Fixed config validation so `h3_max_concurrent_uni_streams` must be non-zero.
- Fixed `outbound_ipv6_interface` to bind to the addresses actually assigned to the interface instead of random hosts inside their /64, so inbound return traffic works under ordinary SLAAC/DHCPv6 without AnyIP routes or NDP proxying. Pairs with kernel privacy extensions (`use_tempaddr=2`) for per-connection source rotation.

## 1.0.2 - 2026-04-12

### Added

- Added configurable HTTP root authentication realm support.
- Added `install.sh --help` output.

### Changed

- Changed the default HTTP root authentication realm text.
- Changed the installer behavior to avoid auto-starting the service on fresh installs.
- Changed installer updates to restart an already active service when appropriate.

### Fixed

- Fixed release asset URL parsing and guard logic in `install.sh`.
- Fixed deployment setups that reuse the same address for `listen` and `h3_listen`.
- Fixed the nightly release reset flow before publishing assets.
- Fixed the HTTP/2-over-TLS WebSocket listener.
- Fixed HTTP root authentication handling for root requests.
- Reduced noise from benign TLS handshake EOF logs.

## 1.0.1 - 2026-04-09

### Added

- Added installer support for release channels and pinned versions.
- Added Shadowsocks TCP handshake diagnostics.

### Changed

- Refactored the server module layout to prepare for further cleanup and reliability work.

### Fixed

- Fixed transient listener errors so they no longer terminate the accept loop.
- Hardened Shadowsocks connection acceptance.

## 1.0.0 - 2026-04-06

This release summarizes the project history from the initial commits on 2026-03-12 through the first stable tag.

### Added

- Added the initial production-oriented Rust implementation of a WebSocket-based Shadowsocks relay.
- Added WebSocket transport support for HTTP/1.1, HTTP/2 (RFC 8441), and HTTP/3 (RFC 9220).
- Added built-in TLS for HTTP/1.1 and HTTP/2, plus QUIC/TLS support for HTTP/3 deployments.
- Added multi-user routing, per-user paths, per-user cipher selection, and Linux `fwmark` support.
- Added Prometheus metrics, memory monitoring, and a ready-made Grafana dashboard.
- Added architecture documentation and a Russian `README`.
- Added Outline-compatible access key generation, including separate client config generation.
- Added Shadowsocks 2022 support and a plain Shadowsocks listener.
- Added relay regression tests and process memory metrics caching.
- Added musl build aliases and release workflow support for cross-platform builds.

### Changed

- Made listeners optional and clarified the listener configuration model.
- Refactored the NAT table and per-session caching, including deduplicated UDP NAT entry creation.
- Added DNS caching and multiple metrics-path optimizations.
- Reworked allocator and memory diagnostics, ultimately replacing jemalloc with mimalloc.
- Split the library entrypoint and tuned HTTP/2 UDP latency.
- Improved release automation, artifact naming, Zig pinning, and target installation steps.

### Fixed

- Improved QUIC and HTTP/3 throughput and reduced packet drops.
- Fixed handling of large Shadowsocks packets by splitting them correctly.
- Fixed stream nonce overflow handling.
- Removed unnecessary allocations in the TCP encryption hot path and DNS cache lookups.
- Cleaned up allocator-related linking and release workflow issues.
