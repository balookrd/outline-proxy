//! Parser for VLESS share-link URIs (`vless://UUID@HOST:PORT?...#NAME`).
//!
//! Maps the standard Xray/V2Ray share-link format onto the internal VLESS
//! uplink fields (`vless_id`, `vless_ws_url` / `vless_xhttp_url`,
//! `vless_mode`). Only the parameters that have a one-to-one mapping in our
//! current transport stack are honoured; the rest are accepted-with-warning
//! (`fp`, `pbk`, `sid`, `spx`, `fragment`, `flow=""`) or rejected outright
//! (non-`none` `encryption`, non-empty `flow`, unknown `type`, divergent
//! `host`/`sni`).
//!
//! Reference: <https://github.com/XTLS/Xray-core/discussions/716>.
//!
//! ## Mapping
//!
//! | URI element                | Internal field                       |
//! |----------------------------|--------------------------------------|
//! | `UUID` userinfo            | `vless_id`                           |
//! | `HOST:PORT` authority      | URL host:port                        |
//! | `?type=ws`                 | `vless_mode = ws_*`, `vless_ws_url`  |
//! | `?type=xhttp`              | `vless_mode = xhttp_*`, `vless_xhttp_url` |
//! | `?type=quic`               | `vless_mode = quic`, `vless_ws_url`  |
//! | `?security=tls`/`reality`  | URL scheme `wss`/`https`             |
//! | `?security=none` (default) | URL scheme `ws`/`http`               |
//! | `?path=...`                | URL path                             |
//! | `?alpn=h3` / `h2` / `h1`   | picks the H1/H2/H3 mode variant      |
//! | `?mode=packet-up`/`stream-one` | propagated as XHTTP URL `?mode=` |
//! | `#NAME`                    | uplink name                          |

use anyhow::{Context, Result, anyhow, bail};
use url::Url;

use outline_transport::{TransportMode, vless::parse_uuid};

const VLESS_SCHEME: &str = "vless";

/// Parsed share-link, ready to be projected onto an `UplinkSection` /
/// `UplinkPayload` / CLI args.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessShareLink {
    /// URL-decoded fragment, or `None` when the link omitted `#NAME`.
    pub name: Option<String>,
    /// Raw UUID string from the userinfo (preserves dashes/case as written
    /// — the loader runs it through `parse_uuid` again at startup).
    pub uuid: String,
    pub mode: TransportMode,
    /// Set when `type` is `ws` or `quic`.
    pub vless_ws_url: Option<Url>,
    /// Set when `type` is `xhttp`.
    pub vless_xhttp_url: Option<Url>,
}

impl VlessShareLink {
    /// Parse a `vless://...` URI. The UUID is validated through
    /// `outline_transport::vless::parse_uuid` to fail fast on malformed
    /// input; the dashed form is returned in `uuid` so the rest of the
    /// loader pipeline can re-validate it the same way it does for TOML.
    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if !trimmed.starts_with(&format!("{VLESS_SCHEME}://")) {
            bail!("vless share link must start with `vless://`");
        }

        // `vless` is a non-special URL scheme, so `Url` keeps the host /
        // port / path verbatim and `Url::port()` returns the explicit
        // port instead of folding it against a scheme default.
        let url = Url::parse(trimmed).context("invalid vless share link URL")?;
        if url.scheme() != VLESS_SCHEME {
            bail!("vless share link must use the `vless` scheme");
        }

        let uuid_raw = url.username();
        if uuid_raw.is_empty() {
            bail!("vless share link is missing the UUID userinfo");
        }
        // Percent-encoded UUIDs are unusual but legal — accept them.
        let uuid = percent_decode(uuid_raw)
            .with_context(|| format!("invalid percent-encoding in vless uuid: {uuid_raw}"))?;
        parse_uuid(&uuid).with_context(|| format!("invalid vless uuid in share link: {uuid}"))?;

        if !url.password().unwrap_or_default().is_empty() {
            bail!("vless share link must not contain a password component");
        }

        let host = url
            .host_str()
            .ok_or_else(|| anyhow!("vless share link is missing host"))?
            .to_string();
        let port = url
            .port()
            .ok_or_else(|| anyhow!("vless share link is missing :port"))?;

        let path = url.path();
        let name = url
            .fragment()
            .map(percent_decode)
            .transpose()
            .context("invalid percent-encoding in vless link fragment")?
            .filter(|s| !s.is_empty());

        let params = QueryParams::from_url(&url);

        // Reject the bits we cannot honour rather than silently dropping them.
        if let Some(encryption) = params.first("encryption") {
            if !encryption.eq_ignore_ascii_case("none") {
                bail!("vless link encryption={encryption} is not supported (only `none`)");
            }
        }
        if let Some(flow) = params.first("flow") {
            if !flow.is_empty() {
                bail!("vless link flow={flow} is not supported (xtls flows have no client impl)");
            }
        }
        for (key, value) in [
            ("sni", params.first("sni")),
            ("host", params.first("host")),
        ] {
            if let Some(v) = value {
                if !v.is_empty() && !v.eq_ignore_ascii_case(&host) {
                    bail!(
                        "vless link {key}={v} differs from authority host {host}; \
                         the current transport stack reuses the URL host for both \
                         SNI and HTTP Host"
                    );
                }
            }
        }

        let transport = params
            .first("type")
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_else(|| "tcp".to_string());
        let security = params
            .first("security")
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_else(|| "none".to_string());
        let alpn = params.first("alpn").map(|s| s.to_ascii_lowercase());

        let (mode, scheme, target) = pick_mode_and_scheme(&transport, &security, alpn.as_deref())?;

        // Build the URL we hand to the loader. Path comes from `?path=`
        // (URL-decoded by `Url`), with the link's own path (rare but legal)
        // appended after to keep arbitrary share-link conventions working.
        let configured_path = params
            .first("path")
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                if path.is_empty() || path == "/" {
                    String::new()
                } else {
                    path.to_string()
                }
            });

        let mut composed = Url::parse(&format!("{scheme}://{host}:{port}"))
            .context("failed to compose vless dial URL from share link")?;
        if !configured_path.is_empty() {
            let normalised = if configured_path.starts_with('/') {
                configured_path
            } else {
                format!("/{configured_path}")
            };
            composed.set_path(&normalised);
        }
        // XHTTP submode is encoded via `?mode=` on the dial URL — see
        // docs/UPLINK-CONFIGURATIONS.md "Submode: packet-up vs stream-one".
        if matches!(target, UrlTarget::Xhttp) {
            if let Some(submode) = params.first("mode") {
                composed.query_pairs_mut().append_pair("mode", submode);
            }
        }

        let (vless_ws_url, vless_xhttp_url) = match target {
            UrlTarget::WsOrQuic => (Some(composed), None),
            UrlTarget::Xhttp => (None, Some(composed)),
        };

        Ok(VlessShareLink {
            name,
            uuid,
            mode,
            vless_ws_url,
            vless_xhttp_url,
        })
    }
}

#[derive(Clone, Copy)]
enum UrlTarget {
    /// Goes into `vless_ws_url` (covers WS modes and raw QUIC).
    WsOrQuic,
    /// Goes into `vless_xhttp_url`.
    Xhttp,
}

fn pick_mode_and_scheme(
    transport: &str,
    security: &str,
    alpn: Option<&str>,
) -> Result<(TransportMode, &'static str, UrlTarget)> {
    let tls = match security {
        "none" | "" => false,
        "tls" | "reality" => true,
        other => bail!("vless link security={other} is not supported"),
    };

    match transport {
        "ws" => {
            let mode = match first_alpn_token(alpn) {
                Some("h3") => TransportMode::WsH3,
                Some("h2") => TransportMode::WsH2,
                Some("h1") | Some("http/1.1") | None => TransportMode::WsH1,
                Some(other) => bail!("vless link alpn={other} is not supported for type=ws"),
            };
            let scheme = if tls { "wss" } else { "ws" };
            Ok((mode, scheme, UrlTarget::WsOrQuic))
        },
        "xhttp" => {
            let mode = match first_alpn_token(alpn) {
                Some("h3") => TransportMode::XhttpH3,
                Some("h2") | None => TransportMode::XhttpH2,
                Some("h1") | Some("http/1.1") => TransportMode::XhttpH1,
                Some(other) => bail!("vless link alpn={other} is not supported for type=xhttp"),
            };
            let scheme = if tls { "https" } else { "http" };
            Ok((mode, scheme, UrlTarget::Xhttp))
        },
        "quic" => {
            // Raw QUIC is TLS-only at the transport layer; the share-link
            // `security` flag is just metadata for our URL scheme.
            let scheme = if tls { "https" } else { "http" };
            Ok((TransportMode::Quic, scheme, UrlTarget::WsOrQuic))
        },
        "tcp" => bail!("vless link type=tcp is not supported (raw TCP carrier not implemented)"),
        "grpc" | "h2" => {
            bail!("vless link type={transport} is not supported (only ws/xhttp/quic)")
        },
        other => bail!("vless link type={other} is not recognised"),
    }
}

/// Pick the first ALPN token. Xray writes `alpn=h2,h3` / `alpn=h3,h2` to
/// indicate ordered preference; we honour the first one because our mode
/// field is single-valued.
fn first_alpn_token(raw: Option<&str>) -> Option<&str> {
    raw?.split(',').map(str::trim).find(|s| !s.is_empty())
}

/// Lightweight wrapper around `Url::query_pairs` that lets us look up the
/// first occurrence of a key without re-parsing the query for every lookup.
struct QueryParams {
    pairs: Vec<(String, String)>,
}

impl QueryParams {
    fn from_url(url: &Url) -> Self {
        let pairs = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        Self { pairs }
    }

    fn first(&self, key: &str) -> Option<&str> {
        self.pairs
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    }
}

fn percent_decode(input: &str) -> Result<String> {
    percent_encoding::percent_decode_str(input)
        .decode_utf8()
        .map(|cow| cow.into_owned())
        .map_err(|e| anyhow!("invalid utf-8 in percent-decoded segment: {e}"))
}

#[cfg(test)]
#[path = "tests/share_link.rs"]
mod tests;
