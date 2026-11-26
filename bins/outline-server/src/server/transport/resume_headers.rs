//! `X-Outline-*` session-resumption negotiation: request-side parsing
//! ([`ResumeContext`]) and the response-side echo
//! ([`ResumeResponseEcho`]). Shared by every transport that negotiates
//! resumption — WS upgrades (h1/h2), Extended CONNECT (h3), and the
//! XHTTP handlers — so the negotiation gates live in exactly one
//! place. The header names themselves are wire vocabulary shared with
//! the client and live in `outline_wire::resume`.

use tracing::debug;

#[cfg(test)]
pub(in crate::server) use outline_wire::resume::{
    ACK_PREFIX_HEADER, DOWN_ACKED_HEADER, RESUME_CAPABLE_HEADER, RESUME_REQUEST_HEADER,
    SYMMETRIC_REPLAY_HEADER,
};
use outline_wire::resume::{ResumeRequestHeaders, ResumeResponseHeaders};

use super::super::cluster::{RouteDecision, decide};
use super::super::resumption::{ClusterIdentity, OrphanRegistry, SessionId};

/// Per-request resumption negotiation state, parsed once at WS Upgrade
/// time from `X-Outline-*` headers and threaded into the relay loop.
#[derive(Default)]
pub(in crate::server) struct ResumeContext {
    /// Session ID the client asked us to resume. Validated against the
    /// orphan registry only after authentication succeeds, since the
    /// upgrade handler does not know `user_id` yet.
    pub(in crate::server) requested_resume: Option<SessionId>,
    /// Session ID we minted (and surfaced to the client via the
    /// `X-Outline-Session` response header) so that, on disconnect, the
    /// upstream can be parked under a key the client already knows.
    pub(in crate::server) issued_session_id: Option<SessionId>,
    /// Whether the client advertised the Ack-Prefix Protocol capability
    /// (`X-Outline-Resume-Ack-Prefix: 1`). When true on a successful
    /// resume hit the server emits a 14-byte control frame ahead of the
    /// upstream→client relay so the client can replay only the bytes
    /// the upstream `TcpStream` has not yet acked.
    /// See `docs/SESSION-RESUMPTION.md` § Ack-Prefix Protocol (v1).
    pub(in crate::server) ack_prefix_requested: bool,
    /// Whether the client advertised the Symmetric Downlink Replay
    /// (v2) capability (`X-Outline-Resume-Symmetric-Replay: 1`). Per
    /// spec, v2 cannot be active without v1, and the server side must
    /// also have a non-zero `downlink_buffer_bytes`; both gates are
    /// applied at parse time, so a `true` value here already implies
    /// `ack_prefix_requested == true` AND the registry has v2 capacity
    /// configured. See `docs/SESSION-RESUMPTION.md` § Symmetric
    /// Downlink Replay (v2).
    pub(in crate::server) symmetric_replay_requested: bool,
    /// Client-reported `X-Outline-Resume-Down-Acked` offset on a v2
    /// resume request. Counts plaintext downstream bytes the client
    /// has successfully forwarded to its SOCKS5 client over the
    /// session lifetime. Defaults to `0` when:
    ///
    /// - the request is not a resume request,
    /// - v2 capability is not requested,
    /// - the header is absent, or
    /// - the header is malformed (per spec the server treats malformed
    ///   as `0` and proceeds — equivalent to "replay everything still
    ///   in the ring").
    pub(in crate::server) client_acked_offset: u64,
}

impl ResumeContext {
    /// Builds a [`ResumeContext`] by inspecting incoming HTTP request
    /// headers and, when applicable, minting a fresh server-issued
    /// Session ID. When resumption is disabled in config — or when the
    /// client neither offered `Resume` nor advertised `Resume-Capable` —
    /// both fields are left `None` and the relay path runs unchanged.
    pub(in crate::server) fn from_request_headers(
        headers: &axum::http::HeaderMap,
        registry: &OrphanRegistry,
    ) -> Self {
        let raw = ResumeRequestHeaders::parse_raw(headers);
        let requested_resume_raw = raw.resume_request;
        let resume_capable = raw.resume_capable;
        // Cluster edge routing: a resume id whose shard is not ours belongs to
        // another home. Reaching it is the mesh relay's job, and that decision is
        // taken separately by [`edge_route`] before this local negotiation runs —
        // so *here* the foreign id is simply not resumable, and we drop it and
        // serve a fresh local session (this edge becomes the new home). Reaching
        // this arm therefore means one of: not clustered on the relay path, the
        // home refused, or the relay could not be opened. Own-shard / unknown ids
        // stay local.
        let requested_resume = match decide(registry.cluster_identity(), requested_resume_raw) {
            RouteDecision::Relay(shard) => {
                debug!(
                    shard = shard.get(),
                    "resume id targets a foreign shard the mesh relay did not take; \
                     serving a fresh local session",
                );
                None
            },
            RouteDecision::Local => requested_resume_raw,
        };
        // Mint on the *original* resume attempt so a relayed-away client still
        // gets a fresh session id to park under locally.
        let issued_session_id =
            if registry.enabled() && (resume_capable || requested_resume_raw.is_some()) {
                registry.mint_session_id()
            } else {
                None
            };
        // Ack-Prefix Protocol capability advertisement. Pre-auth header
        // read is safe: only the boolean capability bit is exposed, no
        // session-id existence is leaked. The actual control-frame emit
        // gates on the post-auth orphan-take hit + this flag.
        let ack_prefix_requested = registry.enabled() && raw.ack_prefix;
        // v2 Symmetric Downlink Replay capability. Per spec, v2 cannot
        // exist without v1, and the server side must have a non-zero
        // `downlink_buffer_bytes` to participate. Both gates are
        // applied here so downstream code can trust a `true` flag
        // unconditionally.
        let symmetric_replay_requested =
            ack_prefix_requested && registry.symmetric_replay_enabled() && raw.symmetric_replay;
        // Client-reported downstream-ack offset. Only meaningful on a
        // resume request that also advertises v2; all other paths see
        // `0`. Per spec a malformed value is treated as `0` (replay
        // everything still in the server's ring) — we log at debug to
        // avoid a noisy WARN on a header an old proxy might forward
        // unfiltered, but the parse failure is observable.
        let client_acked_offset = if symmetric_replay_requested && requested_resume.is_some() {
            if raw.malformed_down_acked {
                debug!(
                    "malformed X-Outline-Resume-Down-Acked; \
                     treating as 0 per spec",
                );
            }
            raw.down_acked
        } else {
            0
        };
        Self {
            requested_resume,
            issued_session_id,
            ack_prefix_requested,
            symmetric_replay_requested,
            client_acked_offset,
        }
    }

    /// Full response-side echo: the minted Session ID plus the v1/v2
    /// capability confirmations the parsing layer already gated. Used by
    /// the transports that emit the resume control frames (SS-WS and
    /// VLESS-WS upgrades, XHTTP h1/h2 handlers).
    pub(in crate::server) fn response_echo(&self) -> ResumeResponseEcho {
        ResumeResponseEcho {
            session_id: self.issued_session_id,
            ack_prefix: self.ack_prefix_requested,
            symmetric_replay: self.symmetric_replay_requested,
        }
    }
}

/// The client's raw resume advertisement, read straight from the request
/// headers with **no** local-registry gating. Used by the cluster edge to
/// build the mesh OPEN header: the home re-derives resumption policy from its
/// own registry, and in a symmetric cluster (shared PSK and matching config)
/// that is equivalent to gating here — so the edge forwards exactly what the
/// client advertised.
pub(in crate::server) struct EdgeResumeAdvert {
    /// The foreign-shard resume id the client presented.
    pub(in crate::server) session_id: SessionId,
    /// Client advertised `X-Outline-Resume-Capable`.
    pub(in crate::server) resume_capable: bool,
    /// Client advertised the Ack-Prefix (v1) capability.
    pub(in crate::server) ack_prefix: bool,
    /// Client advertised Symmetric Downlink Replay (v2).
    pub(in crate::server) symmetric_replay: bool,
    /// Client-reported downstream-acked offset (v2), else `0`.
    pub(in crate::server) down_acked: u64,
    /// `true` when this relay was triggered by `x-outline-home-affinity` for a
    /// brand-new session rather than `x-outline-resume` for a parked session.
    pub(in crate::server) home_affinity: bool,
}

/// Routes an incoming carrier by the shard embedded in its resume id and, when
/// the session belongs to a foreign home, returns the advertisement to relay
/// there over the mesh.
///
/// A [`RouteDecision::Relay`] always yields `Some(advert)` — a relay decision
/// implies the client presented a resume id. [`RouteDecision::Local`] (no
/// cluster identity, a first connect, or an own-shard id) yields `None`, and
/// the caller serves the carrier locally. Total and side-effect-free. Takes the
/// identity (not the registry) so it stays trivially testable, mirroring
/// [`decide`].
pub(in crate::server) fn edge_route(
    headers: &axum::http::HeaderMap,
    identity: Option<&ClusterIdentity>,
) -> (RouteDecision, Option<EdgeResumeAdvert>) {
    let raw = ResumeRequestHeaders::parse_raw(headers);
    let requested = raw.resume_request;
    match decide(identity, requested) {
        RouteDecision::Relay(shard) => {
            let session_id =
                requested.expect("a Relay decision implies the client presented a resume id");
            let advert = EdgeResumeAdvert {
                session_id,
                resume_capable: raw.resume_capable,
                ack_prefix: raw.ack_prefix,
                symmetric_replay: raw.symmetric_replay,
                down_acked: raw.down_acked,
                home_affinity: false,
            };
            (RouteDecision::Relay(shard), Some(advert))
        },
        RouteDecision::Local => {
            if requested.is_none()
                && let Some(id) = identity
                && let Some(affinity_id) = raw.home_affinity
                && let RouteDecision::Relay(shard) = decide(Some(id), Some(affinity_id))
            {
                let fresh_id = SessionId::random_with_shard(&mut rand::rng(), &id.key, shard);
                let advert = EdgeResumeAdvert {
                    session_id: fresh_id,
                    resume_capable: raw.resume_capable,
                    ack_prefix: raw.ack_prefix,
                    symmetric_replay: raw.symmetric_replay,
                    down_acked: 0,
                    home_affinity: true,
                };
                return (RouteDecision::Relay(shard), Some(advert));
            }
            (RouteDecision::Local, None)
        },
    }
}

/// Response-side resume echo, captured by value (the fields are `Copy`)
/// before `ResumeContext` moves into an upgrade closure. The headers it
/// writes are exactly what the client-side dial plan reads back to decide
/// whether the v1/v2 resume protocols are active on the session.
#[derive(Clone, Copy, Default)]
pub(in crate::server) struct ResumeResponseEcho {
    pub(in crate::server) session_id: Option<SessionId>,
    pub(in crate::server) ack_prefix: bool,
    pub(in crate::server) symmetric_replay: bool,
}

impl ResumeResponseEcho {
    pub(in crate::server) fn apply(&self, headers: &mut axum::http::HeaderMap) {
        ResumeResponseHeaders {
            session_id: self.session_id,
            ack_prefix: self.ack_prefix,
            symmetric_replay: self.symmetric_replay,
            ..Default::default()
        }
        .write_to(headers);
    }
}

#[cfg(test)]
#[path = "tests/resume_headers.rs"]
mod tests;
