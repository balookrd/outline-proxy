//! Gate for the patched `rustls` API (see PATCHES.md). Production code reaches the
//! patch only through this module, so a rebase of the vendored crate touches one file.

use std::sync::Arc;

pub(crate) use rustls::client::{ClientHelloShape, ExtensionOrder};

/// Shape the QUIC ClientHello like a browser (client-only; `None` keeps upstream rustls).
pub(crate) fn set_client_hello_shape(config: &mut rustls::ClientConfig, shape: ClientHelloShape) {
    config.client_hello_shape = Some(Arc::new(shape));
}

/// `secp521r1` key exchange (aws-lc-rs), offered by Safari and Firefox.
pub(crate) fn secp521r1() -> &'static dyn rustls::crypto::SupportedKxGroup {
    rustls::crypto::aws_lc_rs::kx_group::SECP521R1
}

/// Shape `config`'s ClientHello like the browser of `profile` (QUIC only).
pub(crate) fn apply_quic_tls_profile(
    config: &mut rustls::ClientConfig,
    profile: &crate::quic::tls_profile::QuicTlsProfile,
) {
    use crate::quic::tls_profile::ShapeOrder;
    let shape = ClientHelloShape {
        omit_extended_master_secret: profile.omit_extended_master_secret,
        // None of the three browsers sends it over QUIC.
        omit_ec_point_formats: true,
        omit_status_request: profile.omit_status_request,
        extra_extensions: profile
            .extra_extensions
            .iter()
            .map(|(typ, body)| (*typ, body.to_vec()))
            .collect(),
        grease: profile.grease,
        extension_order: match profile.order {
            ShapeOrder::Shuffled => ExtensionOrder::Upstream,
            ShapeOrder::ShuffledWithEch => ExtensionOrder::ShuffledWithEch,
            ShapeOrder::Fixed(order) => ExtensionOrder::Fixed(order.to_vec()),
        },
        extra_key_share_groups: profile.extra_key_shares.to_vec(),
        ech_grease_payload_lengths: profile.ech_grease_payload_lengths.to_vec(),
    };
    set_client_hello_shape(config, shape);
}
