use alloc::boxed::Box;
use alloc::vec::Vec;

use super::ResolvesClientCert;
use crate::crypto::SecureRandom;
use crate::log::{debug, trace};
use crate::msgs::enums::ExtensionType;
use crate::msgs::handshake::{CertificateChain, DistinguishedName, ProtocolName, ServerExtensions};
use crate::rand::GetRandomFailed;
use crate::sync::Arc;
use crate::{SignatureScheme, compress, sign};

#[derive(Debug)]
pub(super) struct ServerCertDetails<'a> {
    pub(super) cert_chain: CertificateChain<'a>,
    pub(super) ocsp_response: Vec<u8>,
}

impl<'a> ServerCertDetails<'a> {
    pub(super) fn new(cert_chain: CertificateChain<'a>, ocsp_response: Vec<u8>) -> Self {
        Self {
            cert_chain,
            ocsp_response,
        }
    }

    pub(super) fn into_owned(self) -> ServerCertDetails<'static> {
        let Self {
            cert_chain,
            ocsp_response,
        } = self;
        ServerCertDetails {
            cert_chain: cert_chain.into_owned(),
            ocsp_response,
        }
    }
}

/// ALPS `application_settings`, new codepoint (client-hello-shape patch).
pub(super) const ALPS_EXTENSION: u16 = 0x44cd;

pub(super) struct ClientHelloDetails {
    pub(super) alpn_protocols: Vec<ProtocolName>,
    pub(super) sent_extensions: Vec<ExtensionType>,
    pub(super) extension_order_seed: u16,
    pub(super) offered_cert_compression: bool,
    /// GREASE values of a shaped ClientHello, kept for a HelloRetryRequest
    /// (client-hello-shape patch).
    pub(super) grease: Option<GreaseValues>,
    /// ALPN protocols listed in the ClientHello's ALPS extension, when it came
    /// from `ClientHelloShape::alps` (client-hello-shape patch).
    pub(super) alps_protocols: Vec<ProtocolName>,
}

impl ClientHelloDetails {
    pub(super) fn new(alpn_protocols: Vec<ProtocolName>, extension_order_seed: u16) -> Self {
        Self {
            alpn_protocols,
            sent_extensions: Vec::new(),
            extension_order_seed,
            offered_cert_compression: false,
            grease: None,
            alps_protocols: Vec::new(),
        }
    }

    pub(super) fn server_sent_unsolicited_extensions(
        &self,
        received_exts: &ServerExtensions<'_>,
        allowed_unsolicited: &[ExtensionType],
    ) -> bool {
        let mut extensions = received_exts.collect_used();
        extensions.extend(
            received_exts
                .unknown_extensions
                .iter()
                .map(|ext| ExtensionType::from(*ext)),
        );
        for ext_type in extensions {
            if !self.sent_extensions.contains(&ext_type) && !allowed_unsolicited.contains(&ext_type)
            {
                trace!("Unsolicited extension {ext_type:?}");
                return true;
            }
        }

        false
    }
}

pub(super) enum ClientAuthDetails {
    /// Send an empty `Certificate` and no `CertificateVerify`.
    Empty { auth_context_tls13: Option<Vec<u8>> },
    /// Send a non-empty `Certificate` and a `CertificateVerify`.
    Verify {
        certkey: Arc<sign::CertifiedKey>,
        signer: Box<dyn sign::Signer>,
        auth_context_tls13: Option<Vec<u8>>,
        compressor: Option<&'static dyn compress::CertCompressor>,
    },
}

impl ClientAuthDetails {
    pub(super) fn resolve(
        resolver: &dyn ResolvesClientCert,
        canames: Option<&[DistinguishedName]>,
        sigschemes: &[SignatureScheme],
        auth_context_tls13: Option<Vec<u8>>,
        compressor: Option<&'static dyn compress::CertCompressor>,
    ) -> Self {
        let acceptable_issuers = canames
            .unwrap_or_default()
            .iter()
            .map(|p| p.as_ref())
            .collect::<Vec<&[u8]>>();

        if let Some(certkey) = resolver.resolve(&acceptable_issuers, sigschemes) {
            if let Some(signer) = certkey.key.choose_scheme(sigschemes) {
                debug!("Attempting client auth");
                return Self::Verify {
                    certkey,
                    signer,
                    auth_context_tls13,
                    compressor,
                };
            }
        }

        debug!("Client auth requested but no cert/sigscheme available");
        Self::Empty { auth_context_tls13 }
    }
}

/// RFC 8701 GREASE values of one shaped ClientHello (client-hello-shape patch).
#[derive(Clone, Copy, Debug)]
pub(super) struct GreaseValues {
    pub(super) cipher_suite: u16,
    pub(super) group: u16,
    pub(super) version: u16,
    pub(super) first_extension: u16,
    pub(super) last_extension: u16,
    pub(super) signature_algorithm: u16,
}

impl GreaseValues {
    /// Draws the values BoringSSL-style: `0x?A?A` from one random byte each,
    /// the two extension values forced apart.
    pub(super) fn new(secure_random: &dyn SecureRandom) -> Result<Self, GetRandomFailed> {
        let mut seed = [0u8; 6];
        secure_random.fill(&mut seed)?;
        let grease = |b: u8| {
            let v = u16::from((b & 0xf0) | 0x0a);
            (v << 8) | v
        };
        let first_extension = grease(seed[3]);
        let mut last_extension = grease(seed[4]);
        if last_extension == first_extension {
            last_extension ^= 0x1010;
        }
        Ok(Self {
            cipher_suite: grease(seed[0]),
            group: grease(seed[1]),
            version: grease(seed[2]),
            first_extension,
            last_extension,
            signature_algorithm: grease(seed[5]),
        })
    }
}
