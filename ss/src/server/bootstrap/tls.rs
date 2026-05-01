use std::{
    collections::HashMap,
    fs,
    path::Path,
    sync::{Arc, OnceLock},
};

use anyhow::{Context, Result, anyhow, bail};
use rustls::{
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use tokio_rustls::TlsAcceptor;
use tracing::warn;

use crate::config::{Config, TlsCertEntry};

pub(in crate::server) fn ensure_rustls_provider_installed() {
    static RUSTLS_PROVIDER: OnceLock<()> = OnceLock::new();
    RUSTLS_PROVIDER.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

pub(in crate::server) fn load_h3_tls_config(config: &Config) -> Result<rustls::ServerConfig> {
    // Advertise the MTU-aware sibling alongside each base ALPN
    // (vless-mtu / vless, ss-mtu / ss) — newer clients pick the
    // sibling and use the oversize-record stream fallback; older
    // clients pick the base and behave exactly as before.
    let alpn: Vec<&[u8]> =
        config.h3_alpn.iter().flat_map(|p| p.advertised_alpns().iter().copied()).collect();
    build_listener_tls_config(
        config.h3_cert_path.as_deref(),
        config.h3_key_path.as_deref(),
        &config.h3_certs,
        &alpn,
        "server.h3",
    )
    .context("failed to build HTTP/3 TLS config")
}

pub(super) fn build_tcp_tls_acceptor(config: &Config) -> Result<TlsAcceptor> {
    let tls_config = build_listener_tls_config(
        config.tls_cert_path.as_deref(),
        config.tls_key_path.as_deref(),
        &config.tls_certs,
        &[b"h2".as_slice(), b"http/1.1".as_slice()],
        "server",
    )
    .context("failed to build TCP TLS config")?;

    Ok(TlsAcceptor::from(Arc::new(tls_config)))
}

/// Build a `rustls::ServerConfig` for one listener. Three shapes:
///
/// 1. Single default cert, no array — uses `with_single_cert` (the
///    traditional rustls path) so that nothing changes for existing
///    deployments.
/// 2. Array only — every entry is registered by SNI; an unmatched SNI
///    or a SNI-less ClientHello fails the handshake.
/// 3. Default + array — registers the array and additionally sets the
///    default cert as the fallback so that unmatched SNIs still
///    handshake on the default name.
fn build_listener_tls_config(
    default_cert_path: Option<&Path>,
    default_key_path: Option<&Path>,
    extra: &[TlsCertEntry],
    alpn_protocols: &[&[u8]],
    label: &str,
) -> Result<rustls::ServerConfig> {
    ensure_rustls_provider_installed();

    let provider = CryptoProvider::get_default()
        .cloned()
        .ok_or_else(|| anyhow!("no default rustls CryptoProvider installed"))?;

    let default_cert = match (default_cert_path, default_key_path) {
        (Some(cert_path), Some(key_path)) => {
            Some(load_certified_key(cert_path, key_path, &provider)?)
        },
        (None, None) => None,
        _ => bail!("{label}.cert_path and {label}.key_path must be configured together"),
    };

    let builder = rustls::ServerConfig::builder().with_no_client_auth();
    let mut tls_config = if extra.is_empty() {
        // Preserve the previous code path bit-for-bit when no array is set.
        let ck = default_cert
            .ok_or_else(|| anyhow!("{label} TLS requires a cert/key pair or [[{label}.certs]]"))?;
        builder.with_cert_resolver(Arc::new(SingleCertResolver(Arc::new(ck))))
    } else {
        let mut entries = Vec::with_capacity(extra.len());
        for entry in extra {
            let ck = load_certified_key(&entry.cert_path, &entry.key_path, &provider)?;
            entries.push((ck, entry.sni.clone()));
        }
        let resolver = MultiCertResolver::from_entries(entries, default_cert, label)?;
        builder.with_cert_resolver(Arc::new(resolver))
    };

    tls_config.alpn_protocols = alpn_protocols.iter().map(|alpn| alpn.to_vec()).collect();
    Ok(tls_config)
}

fn load_certified_key(
    cert_path: &Path,
    key_path: &Path,
    provider: &Arc<CryptoProvider>,
) -> Result<CertifiedKey> {
    let certs = load_cert_chain(cert_path)?;
    let key = load_private_key(key_path)?;
    let signing_key = provider
        .key_provider
        .load_private_key(key)
        .with_context(|| format!("failed to load private key {}", key_path.display()))?;
    Ok(CertifiedKey::new(certs, signing_key))
}

fn load_cert_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let pem = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    if path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("der")) {
        return Ok(vec![CertificateDer::from(pem)]);
    }

    rustls_pemfile::certs(&mut pem.as_slice())
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to parse certificate chain {}", path.display()))
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let key = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    if path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("der")) {
        return PrivateKeyDer::try_from(key)
            .map_err(|error| anyhow!(error))
            .with_context(|| format!("failed to parse private key {}", path.display()));
    }

    rustls_pemfile::private_key(&mut key.as_slice())
        .with_context(|| format!("failed to parse private key {}", path.display()))?
        .ok_or_else(|| anyhow!("no private key found in {}", path.display()))
}

/// Extract the set of DNS names this end-entity cert is valid for.
/// Prefers `subjectAltName` DNS entries (the modern, mandatory source);
/// falls back to the Subject CN only when no DNS SAN is present, since
/// real-world certs from old CAs sometimes still carry a CN-only
/// hostname even though browsers stopped honouring it years ago.
/// Wildcard names (`*.foo.com`) are returned as-is — the caller decides
/// what to do with them.
fn extract_sni_names(chain: &[CertificateDer<'_>]) -> Vec<String> {
    use x509_parser::prelude::{FromDer, GeneralName, ParsedExtension, X509Certificate};

    let Some(end_entity) = chain.first() else { return Vec::new() };
    let Ok((_, parsed)) = X509Certificate::from_der(end_entity.as_ref()) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for ext in parsed.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for gn in &san.general_names {
                if let GeneralName::DNSName(name) = gn {
                    out.push(name.to_ascii_lowercase());
                }
            }
        }
    }
    if out.is_empty() {
        for cn in parsed.subject().iter_common_name() {
            if let Ok(value) = cn.as_str() {
                out.push(value.to_ascii_lowercase());
            }
        }
    }
    out
}

#[derive(Debug)]
struct SingleCertResolver(Arc<CertifiedKey>);

impl ResolvesServerCert for SingleCertResolver {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

#[derive(Debug)]
struct MultiCertResolver {
    by_sni: HashMap<String, Arc<CertifiedKey>>,
    default: Option<Arc<CertifiedKey>>,
}

impl MultiCertResolver {
    fn from_entries(
        entries: Vec<(CertifiedKey, Vec<String>)>,
        default: Option<CertifiedKey>,
        label: &str,
    ) -> Result<Self> {
        let mut by_sni: HashMap<String, Arc<CertifiedKey>> = HashMap::new();
        for (idx, (ck, sni_override)) in entries.into_iter().enumerate() {
            let ck = Arc::new(ck);
            let derived = sni_override.is_empty();
            let names = if derived { extract_sni_names(&ck.cert) } else { sni_override };

            // Resolver matches SNIs exactly. Wildcard DNS names from
            // SAN can't be registered as keys, so we skip them with a
            // warning and rely on whatever non-wildcard SANs the cert
            // also carries.
            let mut usable = Vec::with_capacity(names.len());
            for name in names {
                if name.contains('*') {
                    warn!(
                        "{label}.certs[{idx}] cert has wildcard DNS name {name:?}; \
                         skipping (resolver matches SNIs exactly — list each \
                         hostname in `sni = [...]` if you need this cert to apply)"
                    );
                    continue;
                }
                usable.push(name);
            }

            if usable.is_empty() {
                if derived {
                    bail!(
                        "{label}.certs[{idx}] has no DNS SAN/CN to derive an SNI from; \
                         set `sni = [\"...\"]` explicitly"
                    );
                } else {
                    bail!(
                        "{label}.certs[{idx}].sni is empty after filtering; list at \
                         least one non-wildcard hostname"
                    );
                }
            }

            for name in usable {
                if let Some(prev) = by_sni.insert(name.clone(), Arc::clone(&ck)) {
                    if !Arc::ptr_eq(&prev, &ck) {
                        bail!(
                            "{label}.certs[{idx}] SNI {name:?} is already claimed by an \
                             earlier entry"
                        );
                    }
                }
            }
        }
        Ok(Self { by_sni, default: default.map(Arc::new) })
    }

    fn pick(&self, sni: Option<&str>) -> Option<Arc<CertifiedKey>> {
        if let Some(name) = sni {
            let lower = name.to_ascii_lowercase();
            if let Some(ck) = self.by_sni.get(&lower) {
                return Some(Arc::clone(ck));
            }
        }
        self.default.clone()
    }
}

impl ResolvesServerCert for MultiCertResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.pick(hello.server_name())
    }
}

#[cfg(test)]
#[path = "tests/tls.rs"]
mod tests;
