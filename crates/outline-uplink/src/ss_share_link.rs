//! Parser for Shadowsocks-over-WS/XHTTP share-link URIs
//! (`ss://BASE64(method:password)@HOST:PORT?...#NAME`).
//!
//! Mirrors [`crate::share_link::VlessShareLink`] for the SS transport: a single
//! string expands into the internal **combined-path** SS uplink fields
//! (`ss_ws_url` / `ss_xhttp_url`, `ss_mode`, plus the `method` / `password`
//! credentials). Combined-path is the SS analogue of a VLESS share link — one
//! URL carries both the TCP and UDP legs, with the server splitting them by a
//! hidden session-id / token bit. The split `tcp_*` / `udp_*` two-path layout
//! has no single-URL form and stays TOML-only.
//!
//! The userinfo follows SIP002: url-safe base64 of `method:password` (the
//! format emitted by Outline / Shadowsocks clients). Only the parameters that
//! have a one-to-one mapping in our transport stack are honoured; the rest are
//! rejected outright (`type=quic`/`tcp`/`grpc`, divergent `host`/`sni`).
//!
//! Reference (SIP002): <https://shadowsocks.org/doc/sip002.html>.
//!
//! ## Mapping
//!
//! | URI element                | Internal field                            |
//! |----------------------------|-------------------------------------------|
//! | `BASE64(method:password)`  | `method` + `password`                     |
//! | `HOST:PORT` authority      | URL host:port                             |
//! | `?type=ws` (default)       | `ss_mode = ws_*`, `ss_ws_url`             |
//! | `?type=xhttp`              | `ss_mode = xhttp_*`, `ss_xhttp_url`       |
//! | `?security=tls`/`reality`  | URL scheme `wss`/`https`                  |
//! | `?security=none` (default) | URL scheme `ws`/`http`                     |
//! | `?path=...`                | URL path                                  |
//! | `?alpn=h3` / `h2` / `h1`   | picks the H1/H2/H3 mode variant           |
//! | `?mode=packet-up`/`stream-one` | propagated as XHTTP URL `?mode=`      |
//! | `#NAME`                    | uplink name                               |

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use std::str::FromStr;
use url::Url;

use crate::config::CipherKind;
use crate::share_link::{QueryParams, first_alpn_token, percent_decode};
use outline_transport::TransportMode;

const SS_SCHEME: &str = "ss";

/// Parsed SS share-link, ready to be projected onto an `UplinkSection` /
/// `ResolvedUplinkInput` / CLI args (combined-path SS only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsShareLink {
    /// URL-decoded fragment, or `None` when the link omitted `#NAME`.
    pub name: Option<String>,
    /// SS cipher decoded from the SIP002 userinfo.
    pub cipher: CipherKind,
    /// SS password / PSK decoded from the SIP002 userinfo.
    pub password: String,
    /// Single combined-path carrier mode (both TCP and UDP legs ride it).
    pub mode: TransportMode,
    /// Set when `type` is `ws` (default).
    pub ss_ws_url: Option<Url>,
    /// Set when `type` is `xhttp`.
    pub ss_xhttp_url: Option<Url>,
}

impl SsShareLink {
    /// Parse an `ss://...` URI into the combined-path SS uplink fields.
    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if !trimmed.starts_with(&format!("{SS_SCHEME}://")) {
            bail!("ss share link must start with `ss://`");
        }

        // `ss` is a non-special URL scheme, so `Url` keeps the host / port /
        // path verbatim and `Url::port()` returns the explicit port instead
        // of folding it against a scheme default.
        let url = Url::parse(trimmed).context("invalid ss share link URL")?;
        if url.scheme() != SS_SCHEME {
            bail!("ss share link must use the `ss` scheme");
        }

        // SIP002 userinfo: url-safe base64 of `method:password`. There is no
        // separate `:password` URL component — a `:` in the authority would
        // mean the link used the legacy plaintext form we do not accept.
        let userinfo = url.username();
        if userinfo.is_empty() {
            bail!("ss share link is missing the base64 `method:password` userinfo");
        }
        if !url.password().unwrap_or_default().is_empty() {
            bail!(
                "ss share link userinfo must be SIP002 base64(method:password), \
                 not a plaintext `method:password` pair"
            );
        }
        let userinfo = percent_decode(userinfo)
            .with_context(|| format!("invalid percent-encoding in ss userinfo: {userinfo}"))?;
        let decoded = decode_sip002_userinfo(&userinfo)?;
        let (method, password) = decoded
            .split_once(':')
            .ok_or_else(|| anyhow!("ss share link userinfo must decode to `method:password`"))?;
        let cipher = CipherKind::from_str(method)
            .map_err(|_| anyhow!("ss share link method={method} is not a supported cipher"))?;
        if password.is_empty() {
            bail!("ss share link password is empty");
        }
        let password = password.to_string();

        let host = url
            .host_str()
            .ok_or_else(|| anyhow!("ss share link is missing host"))?
            .to_string();
        let port = url.port().ok_or_else(|| anyhow!("ss share link is missing :port"))?;

        let path = url.path();
        let name = url
            .fragment()
            .map(percent_decode)
            .transpose()
            .context("invalid percent-encoding in ss link fragment")?
            .filter(|s| !s.is_empty());

        let params = QueryParams::from_url(&url);

        // The current transport stack reuses the URL host for both SNI and the
        // HTTP Host header, so divergent `sni`/`host` values would be silently
        // dropped — fail fast instead.
        for (key, value) in [("sni", params.first("sni")), ("host", params.first("host"))] {
            if let Some(v) = value
                && !v.is_empty()
                && !v.eq_ignore_ascii_case(&host)
            {
                bail!(
                    "ss link {key}={v} differs from authority host {host}; \
                     the current transport stack reuses the URL host for both \
                     SNI and HTTP Host"
                );
            }
        }

        let transport = params
            .first("type")
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_else(|| "ws".to_string());
        let security = params
            .first("security")
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_else(|| "none".to_string());
        let alpn = params.first("alpn").map(|s| s.to_ascii_lowercase());

        let (mode, scheme, target) = pick_mode_and_scheme(&transport, &security, alpn.as_deref())?;

        // Build the dial URL handed to the loader. Path comes from `?path=`
        // (URL-decoded by `Url`), with the link's own path (rare but legal)
        // appended after so arbitrary share-link conventions keep working.
        let configured_path = params.first("path").map(|s| s.to_string()).unwrap_or_else(|| {
            if path.is_empty() || path == "/" {
                String::new()
            } else {
                path.to_string()
            }
        });

        let mut composed = Url::parse(&format!("{scheme}://{host}:{port}"))
            .context("failed to compose ss dial URL from share link")?;
        if !configured_path.is_empty() {
            let normalised = if configured_path.starts_with('/') {
                configured_path
            } else {
                format!("/{configured_path}")
            };
            composed.set_path(&normalised);
        }
        // XHTTP submode is encoded via `?mode=` on the dial URL — same rules as
        // the VLESS-XHTTP submode table.
        if matches!(target, UrlTarget::Xhttp)
            && let Some(submode) = params.first("mode")
        {
            composed.query_pairs_mut().append_pair("mode", submode);
        }

        let (ss_ws_url, ss_xhttp_url) = match target {
            UrlTarget::Ws => (Some(composed), None),
            UrlTarget::Xhttp => (None, Some(composed)),
        };

        Ok(SsShareLink {
            name,
            cipher,
            password,
            mode,
            ss_ws_url,
            ss_xhttp_url,
        })
    }
}

#[derive(Clone, Copy)]
enum UrlTarget {
    /// Goes into `ss_ws_url`.
    Ws,
    /// Goes into `ss_xhttp_url`.
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
        other => bail!("ss link security={other} is not supported"),
    };

    match transport {
        "ws" | "" => {
            let mode = match first_alpn_token(alpn) {
                Some("h3") => TransportMode::WsH3,
                Some("h2") => TransportMode::WsH2,
                Some("h1") | Some("http/1.1") | None => TransportMode::WsH1,
                Some(other) => bail!("ss link alpn={other} is not supported for type=ws"),
            };
            let scheme = if tls { "wss" } else { "ws" };
            Ok((mode, scheme, UrlTarget::Ws))
        },
        "xhttp" => {
            let mode = match first_alpn_token(alpn) {
                Some("h3") => TransportMode::XhttpH3,
                Some("h2") | None => TransportMode::XhttpH2,
                Some("h1") | Some("http/1.1") => TransportMode::XhttpH1,
                Some(other) => bail!("ss link alpn={other} is not supported for type=xhttp"),
            };
            let scheme = if tls { "https" } else { "http" };
            Ok((mode, scheme, UrlTarget::Xhttp))
        },
        "quic" => bail!(
            "ss link type=quic is not supported for combined-path SS \
             (raw QUIC muxes tcp+udp natively — use the long-form `transport=ss` \
             with `tcp_*`/`udp_*` config instead)"
        ),
        "tcp" => bail!("ss link type=tcp is not supported (raw TCP carrier not implemented)"),
        other => bail!("ss link type={other} is not supported (only ws/xhttp)"),
    }
}

/// Decode the SIP002 userinfo (`method:password`). SIP002 mandates url-safe
/// base64 without padding; we tolerate both url-safe and standard alphabets
/// and an optional trailing `=` pad to accept links from looser encoders.
fn decode_sip002_userinfo(userinfo: &str) -> Result<String> {
    let stripped = userinfo.trim_end_matches('=');
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(stripped)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(stripped))
        .map_err(|e| anyhow!("ss share link userinfo is not valid base64: {e}"))?;
    String::from_utf8(bytes)
        .map_err(|e| anyhow!("ss share link userinfo is not valid utf-8 after base64 decode: {e}"))
}

#[cfg(test)]
#[path = "tests/ss_share_link.rs"]
mod tests;
