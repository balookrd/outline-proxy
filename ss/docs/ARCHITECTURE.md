# Architecture

This document describes the runtime architecture of `outline-ss-rust` and how traffic flows through the server.

*Русская версия: [ARCHITECTURE.ru.md](ARCHITECTURE.ru.md)*

## Component Overview

```mermaid
flowchart TD
    CLIENT["Client"]

    subgraph FRONTEND["Ingress Transports"]
        H1["HTTP/1.1 WebSocket"]
        H2["HTTP/2 WebSocket (RFC 8441)"]
        H3["HTTP/3 WebSocket (RFC 9220)"]
    end

    subgraph CORE["outline-ss-rust"]
        ROUTER["Path Router"]
        FILTER["Per-path User Filter"]
        CRYPTO["Shadowsocks AEAD Decrypt / Encrypt"]
        VLESS["VLESS UUID Auth + mux.cool/XUDP"]
        TCPR["TCP Relay"]
        UDPR["UDP Relay"]
        METRICS["Prometheus Metrics"]
    end

    subgraph UPSTREAM["Upstream Network"]
        DNS["DNS Resolution"]
        TCPU["TCP Targets"]
        UDPU["UDP Targets"]
    end

    CLIENT --> H1
    CLIENT --> H2
    CLIENT --> H3

    H1 --> ROUTER
    H2 --> ROUTER
    H3 --> ROUTER

    ROUTER --> FILTER
    FILTER --> CRYPTO
    ROUTER --> VLESS
    CRYPTO --> TCPR
    CRYPTO --> UDPR
    VLESS --> TCPR
    VLESS --> UDPR

    TCPR --> DNS
    TCPR --> TCPU
    UDPR --> DNS
    UDPR --> UDPU

    ROUTER --> METRICS
    CRYPTO --> METRICS
    VLESS --> METRICS
    TCPR --> METRICS
    UDPR --> METRICS
```

## Listener Model

The server may run up to three listeners:

- Main TCP listener for HTTP/1.1 and HTTP/2
- Optional TLS on the main TCP listener
- Optional QUIC listener for HTTP/3

Prometheus metrics are served from a separate optional listener so that operational traffic does not share the WebSocket ingress path.

## Request Routing

The server registers all configured TCP and UDP WebSocket paths from the effective user set.

At request time:

1. The incoming request path is matched against registered TCP or UDP WebSocket routes.
2. The user list is filtered to only those users that are allowed on that path.
3. Decryption tries only the remaining user candidates.

This gives two useful properties:

- different users can be isolated on different URL paths
- user identification remains automatic even when users share a path but use different keys or different ciphers

## User Identification

There is no explicit username inside the Shadowsocks payload.

Instead, the server identifies the user by successfully decrypting:

- the first valid TCP stream chunk, or
- the first valid UDP packet

Because users may have different ciphers, the decryptor iterates across the per-path candidate set and attempts the correct cipher for each user independently.

## TCP Data Path

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    participant U as TCP Upstream

    C->>S: WebSocket connect on TCP path
    C->>S: Encrypted Shadowsocks stream
    S->>S: Identify user by successful AEAD decrypt
    S->>S: Parse target address
    S->>U: TCP connect
    C->>S: More encrypted frames
    S->>U: Plain TCP bytes
    U->>S: Plain TCP bytes
    S->>C: Encrypted WebSocket frames
```

Important behaviors:

- WebSocket message boundaries are ignored for TCP
- the server buffers decrypted bytes until a full target address is available
- once the target is known, the relay becomes a bidirectional stream bridge
- per-user `fwmark` is applied before the outbound TCP connect when configured

## UDP Data Path

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    participant U as UDP Upstream

    C->>S: WebSocket connect on UDP path
    C->>S: One encrypted SS UDP packet
    S->>S: Identify user by successful AEAD decrypt
    S->>S: Parse target address
    S->>U: sendto()
    U->>S: recvfrom()
    S->>C: One encrypted WebSocket frame per response datagram
```

Important behaviors:

- each WebSocket binary frame is expected to contain exactly one Shadowsocks UDP packet
- each upstream UDP response becomes its own encrypted WebSocket binary frame
- per-user `fwmark` is applied to the outbound UDP socket when configured
- Shadowsocks-2022 UDP traffic is protected by a sliding-window anti-replay filter keyed on the per-session `client_session_id`; duplicate `packet_id`s are dropped before the relay step, and idle sessions are reaped on the same cadence as NAT-entry eviction

## VLESS Data Path

A separate WebSocket path (`vless_ws_path`, optionally per-user) accepts VLESS streams on the main HTTP/1.1 or HTTP/2 listener, and on the QUIC HTTP/3 listener when `h3_listen` is configured. VLESS authentication is stateless UUID matching against the per-path user set; the protocol layer itself adds no encryption, so TLS on the main listener (or the QUIC HTTP/3 endpoint) is required for public deployments.

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    participant U as Upstream

    C->>S: WebSocket connect on VLESS path
    C->>S: VLESS header (version, UUID, command, target)
    S->>S: Match UUID against per-path users
    alt command == TCP CONNECT
        S->>U: TCP connect to target
        C->>S: Raw bytes
        S->>U: Raw bytes
        U->>S: Raw bytes
        S->>C: Raw bytes
    else command == UDP
        C->>S: [u16 len][datagram] frames
        S->>U: sendto(target)
        U->>S: recvfrom()
        S->>C: [u16 len][datagram] frames
    else command == Mux (0x03, mux.cool / XUDP)
        C->>S: Frame[New, sub-id, TCP|UDP target]
        S->>S: Open sub-connection (up to 8/session)
        C->>S: Frame[Keep, sub-id, data, optional per-packet addr]
        S->>U: TCP write or UDP send_to
        U->>S: TCP bytes or UDP datagram
        S->>C: Frame[Keep, sub-id, data, source addr for XUDP]
    end
```

Important behaviors:

- UUID lookup is linear over the per-path candidate set; the request is rejected and logged when the UUID is unknown
- for `COMMAND_UDP`, each client frame is length-prefixed (`u16` BE); each upstream response is re-framed the same way
- for `COMMAND_MUX` (mux.cool / XUDP), a single VLESS stream multiplexes up to 8 concurrent sub-connections, each with its own session id; sub-connections can be TCP or UDP, and UDP Keep frames carry a per-packet destination (XUDP), with replies tagged by the upstream source address
- the XUDP `GlobalID` on New frames is parsed and logged, but UDP sessions are not yet reused across WebSocket reconnects
- per-user `fwmark` is applied to both TCP connects and UDP sockets opened for a VLESS session

## Transport Support

### HTTP/1.1

Uses the standard WebSocket upgrade flow and supports plain `ws://` or `wss://`.

### HTTP/2

Uses RFC 8441 Extended CONNECT. This requires:

- server-side support for HTTP/2 CONNECT protocol enablement
- a client that implements WebSocket over HTTP/2
- any reverse proxy in front of the server to preserve Extended CONNECT rather than downgrading to HTTP/1.1

### HTTP/3

Uses RFC 9220 Extended CONNECT over QUIC. This requires:

- TLS
- UDP reachability
- HTTP/3-capable clients

The repository currently vendors and patches upstream crates to make this path practical. See [PATCHES.md](PATCHES.md).

### Raw VLESS / Shadowsocks over QUIC

Configurable via `[server.h3].alpn` (defaults to `["h3"]`). When the list also includes `"vless"` or `"ss"`, the same QUIC endpoint also accepts non-HTTP/3 protocols on the same UDP port. After the QUIC handshake, the server inspects the negotiated ALPN on `quinn::Connection::handshake_data()` and dispatches:

- `h3` — existing HTTP/3 + WebSocket-over-HTTP/3 path.
- `vless` — raw VLESS framing on QUIC bidi streams, plus QUIC datagrams for UDP. The per-connection UDP session table maps a server-allocated `session_id` (4-byte big-endian, prefixed on every datagram) to the upstream UDP socket; the originating bidi stream's recv side is the session's lifetime anchor and closing it tears the session down. The `mux.cool` command is rejected — every additional target opens its own bidi stream, letting QUIC's native multiplexing handle head-of-line isolation.
- `ss` — raw Shadowsocks AEAD on QUIC. A bidi stream carries one SS-AEAD TCP session; the handshake parser is identical to the plain `ss_listen` listener (auth by trial decrypt of the first chunk), so user identity, fwmark, NAT entries and metric labels behave the same. UDP is delivered as one QUIC datagram per SS-AEAD packet through the shared `handle_ss_udp_packet` helper, so the NAT table and replay store are reused unchanged.

The same `H3_MAX_CONCURRENT_CONNECTIONS` and `H3_MAX_CONCURRENT_STREAMS` semaphores bound the raw-QUIC paths. Datagram queues are sized off `tuning.h3_*` knobs.

## Observability Design

Metrics are intentionally low-cardinality and focused on production operations.

Labels include:

- `transport`: `tcp` or `udp`
- `protocol`: `http1`, `http2`, `http3`, `socket` (plain SS listeners), `quic` (raw VLESS/SS over QUIC)
- `user`: user identifier
- `result`: `success`, `timeout`, or `error` where applicable
- `direction`: traffic direction for byte counters

Notably absent:

- target hostname labels
- target IP labels
- per-connection identifiers

This keeps Prometheus cost predictable and avoids turning the metrics endpoint into an unbounded cardinality source.

## Failure Domains

The system can be thought of in four layers:

1. Ingress transport layer: HTTP/1.1, HTTP/2, HTTP/3, TLS, QUIC
2. User identification and decryption layer: per-path filtering and AEAD session setup
3. Relay layer: TCP connect or UDP send/receive
4. Egress routing layer: DNS, outbound reachability, and optional `fwmark`

This separation is helpful during incident response:

- handshake failures usually live in the ingress layer
- authentication mismatches live in the decryptor layer
- connection failures live in the relay or routing layer
- throughput and latency issues can be seen directly in Prometheus and Grafana

## Security Boundaries

- TLS termination for HTTP/1.1 and HTTP/2 can happen in-process
- HTTP/3 QUIC termination also happens in-process when enabled
- user isolation is based on independent secrets, optional independent ciphers, and optional independent paths
- outbound policy isolation is optionally strengthened with per-user `fwmark`

## Operational Guidance

Recommended production pattern:

1. Use built-in TLS for the main listener if you want direct `wss://` support.
2. Use a dedicated `metrics_listen` bound to loopback or a private network.
3. Keep TCP and UDP WebSocket paths distinct.
4. Use separate per-user paths when you want cleaner traffic segmentation or staged rollouts.
5. Reserve per-user cipher overrides for compatibility or migration scenarios rather than using them arbitrarily.
