# outline-ss-rust

Minimal Rust implementation of a WebSocket-based Shadowsocks relay inspired by `outline-ss-server`.

## What it does

- Accepts separate WebSocket endpoints for TCP and UDP traffic.
- Expects standard Shadowsocks AEAD data inside WebSocket binary frames.
- Parses the first decrypted target address and relays TCP or UDP traffic to that destination.
- Supports `chacha20-ietf-poly1305` and `aes-256-gcm`.
- Supports multiple users with different Shadowsocks keys.
- Supports per-user Linux `fwmark` on outbound TCP and UDP sockets.
- Supports IPv4 and IPv6 target addresses, listeners and client URL generation.
- Identifies the user automatically by the key that successfully decrypts the first stream chunk or UDP packet.

## What it does not do

- No management API.
- No TLS termination.
- No SIP003 plugin negotiation.
- `fwmark` requires Linux and the privileges needed for `SO_MARK`.

## Run

The server automatically reads `config.toml` from the current directory if it exists.

```bash
cargo run
```

You can also point to a specific file:

```bash
cargo run -- \
  --config ./config.toml
```

CLI flags and environment variables still work and override values from the file.

For IPv6 listeners, use normal socket notation like `listen = "[::]:3000"` in `config.toml`.
For Outline access key generation with an IPv6 public endpoint, set `public_host` with brackets, for example `"[2001:db8::10]:443"`.

For single-user mode, either use `password = "..."` in `config.toml` or the legacy flag:

```bash
cargo run -- --password change-me
```

Environment variables are also supported:

- `OUTLINE_SS_LISTEN`
- `OUTLINE_SS_WS_PATH`
- `OUTLINE_SS_UDP_WS_PATH`
- `OUTLINE_SS_METHOD`
- `OUTLINE_SS_PASSWORD`
- `OUTLINE_SS_USERS`

For `OUTLINE_SS_USERS`, use a comma-separated list like:

```bash
OUTLINE_SS_USERS=alice=secret1,bob=secret2
```

A ready-to-edit TOML config is available in [config.toml](/Users/mmalykhin/Documents/outline-ss-rust/config.toml).

Per-user `fwmark` is configured in `config.toml` inside each `[[users]]` block:

```toml
[[users]]
id = "alice"
password = "change-me"
fwmark = 1001
```

For single-user mode, use top-level `fwmark = 1001`.

## Outline Access Keys

Outline WebSocket clients use a dynamic access key that points to a YAML config, not a plain `ss://` URI.

Generate client configs and `ssconf://` links from the server config like this:

```bash
cargo run -- \
  --print-access-keys \
  --config ./config.toml
```

That command prints, for each user:

- A YAML config file body compatible with Outline WebSocket transport.
- A suggested file name like `alice.yaml`.
- A hosted config URL like `https://keys.example.com/outline/alice.yaml`.
- A client access key like `ssconf://keys.example.com/outline/alice.yaml`.

To use the generated key in Outline Client:

1. Host each printed YAML at its `config_url`.
2. Import the matching `ssconf://` URL into the client.

## Protocol assumptions

### TCP endpoint

The TCP WebSocket endpoint carries the regular Shadowsocks AEAD TCP stream:

1. Client opens a WebSocket connection.
2. Client sends binary WebSocket frames containing the encrypted Shadowsocks stream.
3. The first decrypted bytes contain the target address in Shadowsocks/SOCKS5-style form.
4. The server opens a TCP connection to the target and relays bytes in both directions.

Message boundaries of WebSocket frames are ignored; the encrypted stream can be fragmented arbitrarily.

### UDP endpoint

The UDP WebSocket endpoint expects one complete Shadowsocks AEAD UDP packet per binary WebSocket frame:

1. Client opens a WebSocket connection to the UDP path.
2. Each binary frame contains exactly one encrypted UDP packet.
3. After decryption, the packet starts with the target address followed by the UDP payload.
4. The server forwards the datagram and sends each upstream reply back as its own encrypted WebSocket binary frame.
