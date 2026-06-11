use std::path::PathBuf;

use anyhow::Result;

use super::{
    fallback::{ProxyProtocolVersion, parse_proxy_protocol, validate_authority},
    file::{SniBackendSection, SniFallbackSection, TlsCertSection},
};

/// One additional cert/key pair selected by SNI on a TLS listener.
/// Names are resolved at TLS-config build time: if `sni` is non-empty
/// it wins as-is; otherwise the loader extracts SANs (and CN as a
/// last-resort fallback) from the certificate. See
/// `crate::server::bootstrap::tls`.
#[derive(Debug, Clone)]
pub struct TlsCertEntry {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    /// Explicit SNI override. Empty = derive from the cert.
    pub sni: Vec<String>,
}

impl TlsCertEntry {
    pub(super) fn from_section(raw: TlsCertSection, label: &str) -> Result<Self> {
        let sni = match raw.sni {
            None => Vec::new(),
            Some(list) => {
                let mut out = Vec::with_capacity(list.len());
                for entry in list {
                    let trimmed = entry.trim();
                    if trimmed.is_empty() {
                        anyhow::bail!("{label}.sni entries must be non-empty");
                    }
                    if trimmed.contains('*') {
                        anyhow::bail!(
                            "{label}.sni {entry:?} contains `*`; wildcards are not supported \
                             in the resolver — list each hostname explicitly or omit `sni` \
                             to derive names from the certificate's SAN"
                        );
                    }
                    out.push(trimmed.to_ascii_lowercase());
                }
                out
            },
        };
        Ok(Self {
            cert_path: raw.cert_path,
            key_path: raw.key_path,
            sni,
        })
    }
}

/// Resolved `[sni_fallback]` block. Always carries a non-empty
/// `match_sni` whitelist and at least one backend.
#[derive(Debug, Clone)]
pub struct SniFallbackConfig {
    /// SNIs handled locally (our own TLS terminator). Non-empty.
    pub match_sni: Vec<SniMatcher>,
    pub allow_no_sni: bool,
    pub max_client_hello_bytes: usize,
    /// Ordered list of upstream backends. First whose `match_sni`
    /// matches wins; a backend with an empty `match_sni` is a
    /// catch-all and should be last.
    pub backends: Vec<SniBackend>,
}

/// One entry in [`SniFallbackConfig::backends`].
#[derive(Debug, Clone)]
pub struct SniBackend {
    /// `host:port` of this upstream.
    pub authority: String,
    /// SNIs routed to this backend. Empty = catch-all (matches every
    /// foreign SNI not claimed by an earlier backend).
    pub match_sni: Vec<SniMatcher>,
    pub proxy_protocol: Option<ProxyProtocolVersion>,
}

/// Parsed entry from `match_sni`. Either an exact SNI to match
/// case-insensitively, or a one-label-left wildcard (`*.foo.example`
/// matches `bar.foo.example` but not `bar.baz.foo.example`).
#[derive(Debug, Clone)]
pub enum SniMatcher {
    Exact(String),
    Wildcard { suffix: String },
}

impl SniMatcher {
    fn parse(raw: &str) -> Result<Self> {
        let raw = raw.trim();
        if raw.is_empty() {
            anyhow::bail!("match_sni entries must be non-empty");
        }
        let lower = raw.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("*.") {
            if rest.is_empty() || rest.starts_with('.') {
                anyhow::bail!("match_sni wildcard {raw:?} is malformed");
            }
            if rest.contains('*') {
                anyhow::bail!("match_sni wildcard {raw:?} may only contain one leading `*.`");
            }
            Ok(Self::Wildcard { suffix: format!(".{rest}") })
        } else {
            if lower.contains('*') {
                anyhow::bail!("match_sni {raw:?} contains `*` outside the leading `*.` form");
            }
            Ok(Self::Exact(lower))
        }
    }

    /// Tests whether `sni` (already lowercased by the caller) matches.
    pub fn matches(&self, sni: &str) -> bool {
        match self {
            Self::Exact(name) => name == sni,
            Self::Wildcard { suffix } => {
                if let Some(prefix) = sni.strip_suffix(suffix.as_str()) {
                    !prefix.is_empty() && !prefix.contains('.')
                } else {
                    false
                }
            },
        }
    }
}

impl SniFallbackConfig {
    pub(super) fn from_section(section: SniFallbackSection) -> Result<Option<Self>> {
        let has_single = section
            .backend
            .as_deref()
            .map(str::trim)
            .is_some_and(|b| !b.is_empty());
        let has_multi = section.backends.as_deref().is_some_and(|v| !v.is_empty());

        if !has_single && !has_multi {
            // Section present but no backend configured — treat as opt-out.
            return Ok(None);
        }
        if has_single && has_multi {
            anyhow::bail!(
                "sni_fallback: `backend` and `backends` are mutually exclusive; \
                 use one or the other"
            );
        }
        if has_multi && section.proxy_protocol.is_some() {
            anyhow::bail!(
                "sni_fallback: top-level `proxy_protocol` is only valid in \
                 single-backend mode; set it per-entry inside `[[sni_fallback.backends]]`"
            );
        }

        let raw_match = section
            .match_sni
            .ok_or_else(|| anyhow::anyhow!("sni_fallback requires match_sni"))?;
        if raw_match.is_empty() {
            anyhow::bail!("sni_fallback.match_sni must list at least one entry");
        }
        let mut match_sni = Vec::with_capacity(raw_match.len());
        for entry in &raw_match {
            match_sni.push(SniMatcher::parse(entry)?);
        }

        let max_client_hello_bytes = section.max_client_hello_bytes.unwrap_or(8192);
        if max_client_hello_bytes < 256 {
            anyhow::bail!(
                "sni_fallback.max_client_hello_bytes must be >= 256 (got {max_client_hello_bytes})"
            );
        }

        let backends = if has_single {
            let backend_raw = section.backend.unwrap().trim().to_owned();
            validate_authority(&backend_raw, "sni_fallback.backend")?;
            let proxy_protocol = parse_proxy_protocol(
                section.proxy_protocol.as_deref(),
                "sni_fallback.proxy_protocol",
            )?;
            vec![SniBackend {
                authority: backend_raw,
                match_sni: vec![],
                proxy_protocol,
            }]
        } else {
            parse_sni_backends(section.backends.unwrap())?
        };

        Ok(Some(Self {
            match_sni,
            allow_no_sni: section.allow_no_sni.unwrap_or(false),
            max_client_hello_bytes,
            backends,
        }))
    }
}

fn parse_sni_backends(raw: Vec<SniBackendSection>) -> Result<Vec<SniBackend>> {
    if raw.is_empty() {
        anyhow::bail!("sni_fallback.backends must contain at least one entry");
    }
    let mut backends = Vec::with_capacity(raw.len());
    let last_idx = raw.len() - 1;
    for (i, entry) in raw.into_iter().enumerate() {
        let authority = entry.backend.trim().to_owned();
        if authority.is_empty() {
            anyhow::bail!("sni_fallback.backends[{i}].backend must not be empty");
        }
        validate_authority(&authority, &format!("sni_fallback.backends[{i}].backend"))?;

        let proxy_protocol = parse_proxy_protocol(
            entry.proxy_protocol.as_deref(),
            &format!("sni_fallback.backends[{i}].proxy_protocol"),
        )?;

        let match_sni = match entry.match_sni {
            None => vec![],
            Some(raw_list) => {
                let mut out = Vec::with_capacity(raw_list.len());
                for s in &raw_list {
                    out.push(SniMatcher::parse(s)?);
                }
                out
            },
        };

        if match_sni.is_empty() && i != last_idx {
            anyhow::bail!(
                "sni_fallback.backends[{i}] is a catch-all (no match_sni) but is not \
                 the last entry; unreachable backends would follow it"
            );
        }

        backends.push(SniBackend { authority, match_sni, proxy_protocol });
    }
    Ok(backends)
}
