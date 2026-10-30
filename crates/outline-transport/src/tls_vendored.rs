//! Gate for the patched `rustls` API (see PATCHES.md). Production code reaches the
//! patch only through this module, so a rebase of the vendored crate touches one file.

use std::sync::Arc;

pub(crate) use rustls::client::{ClientHelloShape, ExtensionOrder};

/// Shape the ClientHello like a browser (client-only; `None` keeps upstream rustls).
pub(crate) fn set_client_hello_shape(config: &mut rustls::ClientConfig, shape: ClientHelloShape) {
    config.client_hello_shape = Some(Arc::new(shape));
}

/// `secp521r1` key exchange (aws-lc-rs), offered by Safari and Firefox.
pub(crate) fn secp521r1() -> &'static dyn rustls::crypto::SupportedKxGroup {
    rustls::crypto::aws_lc_rs::kx_group::SECP521R1
}

/// Shape `config`'s ClientHello like the browser of `profile` (TCP and QUIC).
pub(crate) fn apply_tls_hello_profile(
    config: &mut rustls::ClientConfig,
    profile: &crate::tls_hello::HelloProfile,
) {
    use crate::tls_hello::ShapeOrder;
    let extra_extensions: Vec<(u16, Vec<u8>)> = profile
        .extra_extensions
        .iter()
        .map(|(typ, body)| (*typ, body.to_vec()))
        .collect();
    let shape = ClientHelloShape {
        omit_extended_master_secret: profile.omit_extended_master_secret,
        // A TLS 1.2 extension: the browsers send it over TCP, where they offer TLS 1.2,
        // and never over QUIC.
        omit_ec_point_formats: !profile.advertise_tls12,
        omit_status_request: profile.omit_status_request,
        extra_extensions,
        grease: profile.grease,
        extension_order: match profile.order {
            ShapeOrder::Shuffled => ExtensionOrder::Upstream,
            ShapeOrder::ShuffledWithEch => ExtensionOrder::ShuffledWithEch,
            ShapeOrder::Fixed(order) => ExtensionOrder::Fixed(order.to_vec()),
        },
        extra_key_share_groups: profile.extra_key_shares.to_vec(),
        ech_grease_payload_lengths: profile.ech_grease_payload_lengths.to_vec(),
        wire_cipher_suites: profile.wire_cipher_suites.to_vec(),
        advertise_tls12: profile.advertise_tls12,
        grease_signature_algorithms: profile.grease_signature_algorithms,
        // rustls lists only the protocols the hello's ALPN offers (Chrome: ALPS for h2
        // only when it offers h2) and answers the server's ALPS with these settings.
        alps: profile
            .alps
            .iter()
            .map(|(protocol, settings)| {
                // The client EncryptedExtensions carrying these settings has u16 length
                // fields (the extension list adds 4 bytes of header); fail loudly here
                // rather than let rustls truncate them on the wire.
                assert!(
                    settings.len() <= MAX_ALPS_SETTINGS_LEN,
                    "{}: ALPS settings of {} bytes do not fit the u16 length fields",
                    profile.name,
                    settings.len()
                );
                (protocol.to_vec(), settings.to_vec())
            })
            .collect(),
    };
    set_client_hello_shape(config, shape);
}

/// Longest ALPS client settings the u16 length fields of the client EncryptedExtensions
/// can carry (the extension header takes 4 of the 65535 bytes).
const MAX_ALPS_SETTINGS_LEN: usize = u16::MAX as usize - 4;

#[cfg(test)]
#[path = "tests/tls_vendored.rs"]
mod tests;
