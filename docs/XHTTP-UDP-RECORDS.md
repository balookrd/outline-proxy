# SS-UDP Record Framing over XHTTP

*Русская версия: [XHTTP-UDP-RECORDS.ru.md](XHTTP-UDP-RECORDS.ru.md)*

Explicit datagram boundaries for Shadowsocks UDP carried over an XHTTP carrier
(`xhttp_h1` / `xhttp_h2` / `xhttp_h3`). Without them the carrier's byte stream
silently merges and splits packets, and every per-packet AEAD decrypt on the
receiving side fails.

## Why

The datagram transports assume the carrier preserves packet boundaries: one
send is one packet, one receive is one packet — that is the contract of
`DatagramChannel` in `crates/outline-transport/src/frame_io.rs`.

A WebSocket carrier honours it: a `Message::Binary` is a real WebSocket frame,
so `from_ws_datagrams` hands the SS layer exactly what the peer wrote.

An XHTTP carrier does not. Its payload is an HTTP body, and every layer
underneath is free to re-chunk it:

- the client's downlink reader forwards whatever slice h1/h2/h3 makes
  available (`drain_hyper_body` for h1/h2, `drain_h3_body` for h3);
- the server's stream-one uplink pump forwards each request-body frame
  (`ingest_uplink_inorder`);
- a CDN or any intermediary in between may coalesce or re-split further.

So a chunk boundary is not a datagram boundary. Two encrypted packets that
arrive glued together decrypt as one oversized buffer — `aes-256-gcm
decryption failed` / `xchacha20-poly1305 decryption failed` on the client, `no
configured key matched the incoming udp data` on the server. One packet that
arrives halved decrypts as a stump — `UDP packet is too short` / `packet too
short`. In production the two symptoms appeared at roughly 5:1.

VLESS-UDP was never exposed: it writes its own `len || payload` records and its
parser is built for "one underlying datagram carrying multiple length-prefixed
records". This feature gives SS-UDP the same property.

## Record format

Each datagram goes on the wire as one record:

```text
record := len:u16 (big endian) || payload[len]
```

| Field     | Size             | Meaning                                     |
|-----------|------------------|---------------------------------------------|
| `len`     | `u16` big-endian | length of the payload that follows          |
| `payload` | `len` bytes      | one datagram as the carrier layer sees it   |

The codec lives in `crates/outline-wire/src/udp_records.rs` and is shared by
both binaries. The decoder (`UdpRecordDecoder`) is a streaming state machine:
input may be split at any byte boundary, and a chunk may hold any number of
records, whole or partial. A `len = 0` record carries nothing and is skipped
(the encoder never emits one). A datagram past the `u16` ceiling cannot be
expressed; the transport drops it, exactly as it drops any oversized UDP packet
— no real UDP datagram reaches that size.

Framing sits **outside** [carrier padding](PADDING.md): the record payload is
the padded frame when padding is on, and the bare encrypted packet when it is
off, so the two features compose in either combination.

Only the SS-UDP legs of an XHTTP carrier are framed. The TCP legs (SS-over-XHTTP,
VLESS-over-XHTTP) are byte streams by design and stay untouched, as do all
WebSocket carriers and VLESS-UDP.

## Gate: negotiated on the wire

Unlike padding — which is config-synchronised and has no on-wire bit — record
framing is negotiated per session with one header:

| Direction        | Header                        | Meaning                          |
|------------------|-------------------------------|----------------------------------|
| client → server  | `X-Outline-Udp-Records: 1`    | "this session carries datagrams" |
| server → client  | `X-Outline-Udp-Records: 1`    | "I will frame this session too"  |

The client sends the header on every request of an SS-UDP XHTTP session (the
packet-up GET and its uplink POSTs, or the stream-one POST). The server echoes
it only when the base path resolves to an SS-UDP route, latching the decision on
the session — a packet-up client's GET and POST are separate requests and either
may be the one that creates the session.

Framing is on only when **both** sides said `1`. Consequences:

- an older server never echoes → the client keeps the historical unframed wire;
- an older client never asks → the server never frames;
- a third-party client (xray, sing-box, Outline) is unaffected: it neither sends
  nor receives the header, and its wire is byte-for-byte what it was.

Negotiation is why this on-wire change is safe to roll out gradually, and it is
also why the capability must reach the server *at dial time*: warm-standby
SS-UDP streams are dialled ahead of use, so the pool dials with the flag set
(`with_datagram_records`) rather than trying to negotiate afterwards.

## Rollout order

1. **Servers first.** A server that frames only when asked is a no-op for every
   client already in the field.
2. **Clients second.** Each updated client starts asking; sessions against an
   updated server begin framing immediately, sessions against an older one keep
   the current behaviour.
3. No config change is needed on either side, and no coordinated restart: the
   negotiation is per session, so a client that reconnects after the server was
   updated picks framing up on its next dial.

Rolling back is symmetric — a downgraded server stops echoing and clients fall
back to the unframed wire on their next dial.

## Verification

The failure mode is loud, so the fix is visible in the logs: on a busy SS-UDP
XHTTP uplink, the `decryption failed` / `packet is too short` pairs on the
client and the `no configured key matched the incoming udp data` / `packet too
short` pairs on the server stop, while the same client's `ws_h3` carriers (which
never had the problem) are unchanged.
