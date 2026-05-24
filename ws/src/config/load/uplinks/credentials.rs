use anyhow::{anyhow, bail, Context, Result};

use outline_uplink::UplinkTransport;
use shadowsocks_crypto::CipherKind;

pub(super) struct PrimaryCredentials {
    pub(super) cipher: CipherKind,
    pub(super) password: String,
    pub(super) vless_id: Option<[u8; 16]>,
}

pub(super) fn resolve_primary_credentials(
    name: &str,
    transport: UplinkTransport,
    cipher: Option<CipherKind>,
    password: Option<String>,
    vless_id: Option<String>,
) -> Result<PrimaryCredentials> {
    let is_vless = transport == UplinkTransport::Vless;
    let cipher = cipher.unwrap_or(CipherKind::Chacha20IetfPoly1305);
    let password = if is_vless {
        // VLESS has no shared secret; keep an empty placeholder so the
        // shared `UplinkConfig` struct stays uniform.
        password.unwrap_or_default()
    } else {
        let pw = password
            .ok_or_else(|| anyhow!("missing password: set it in config.toml or pass --password"))?;
        validate_shared_secret(cipher, &pw, || {
            format!("invalid password/PSK for cipher {cipher}")
        })?;
        pw
    };

    let vless_id = if is_vless {
        let raw = vless_id
            .ok_or_else(|| anyhow!("uplink {name}: transport=vless requires `vless_id = \"…\"`"))?;
        Some(parse_vless_id(&raw, || format!("uplink {name}: invalid vless_id"))?)
    } else {
        if vless_id.is_some() {
            bail!("uplink {name}: `vless_id` is only valid for transport=vless");
        }
        None
    };

    Ok(PrimaryCredentials { cipher, password, vless_id })
}

pub(super) fn validate_shared_secret<F>(
    cipher: CipherKind,
    password: &str,
    context: F,
) -> Result<()>
where
    F: FnOnce() -> String,
{
    cipher.derive_master_key(password).with_context(context)?;
    Ok(())
}

pub(super) fn parse_vless_id<F>(raw: &str, context: F) -> Result<[u8; 16]>
where
    F: FnOnce() -> String,
{
    outline_transport::vless::parse_uuid(raw).with_context(context)
}
