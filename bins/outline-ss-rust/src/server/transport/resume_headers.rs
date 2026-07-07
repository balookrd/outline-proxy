//! `X-Outline-*` session-resumption negotiation: request-side parsing
//! ([`ResumeContext`]) and the response-side echo
//! ([`ResumeResponseEcho`]). Shared by every transport that negotiates
//! resumption — WS upgrades (h1/h2), Extended CONNECT (h3), and the
//! XHTTP handlers — so the negotiation gates live in exactly one
//! place. The header names themselves are wire vocabulary shared with
//! the client and live in `outline_wire::resume`.

use tracing::debug;

pub(in crate::server) use outline_wire::resume::{
    ACK_PREFIX_HEADER, DOWN_ACKED_HEADER, RESUME_CAPABLE_HEADER, RESUME_REQUEST_HEADER,
    SESSION_RESPONSE_HEADER, SYMMETRIC_REPLAY_HEADER,
};

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
        let requested_resume_raw = headers
            .get(RESUME_REQUEST_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(SessionId::parse_hex);
        let resume_capable = headers
            .get(RESUME_CAPABLE_HEADER)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.trim() == "1");
        // Cluster edge routing: a resume id whose shard is not ours belongs to
        // another home. Until the mesh relay exists (phase 5) we cannot reach
        // it, so drop the resume request and serve a fresh local session (this
        // edge becomes the new home). Own-shard / unknown ids stay local.
        let requested_resume = match decide(registry.cluster_identity(), requested_resume_raw) {
            RouteDecision::Relay(shard) => {
                debug!(
                    shard = shard.get(),
                    "resume id targets a foreign shard; relay not yet implemented \
                     (phase 5), serving a fresh local session",
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
        let ack_prefix_requested = registry.enabled()
            && headers
                .get(ACK_PREFIX_HEADER)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.trim() == "1");
        // v2 Symmetric Downlink Replay capability. Per spec, v2 cannot
        // exist without v1, and the server side must have a non-zero
        // `downlink_buffer_bytes` to participate. Both gates are
        // applied here so downstream code can trust a `true` flag
        // unconditionally.
        let symmetric_replay_requested = ack_prefix_requested
            && registry.symmetric_replay_enabled()
            && headers
                .get(SYMMETRIC_REPLAY_HEADER)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.trim() == "1");
        // Client-reported downstream-ack offset. Only meaningful on a
        // resume request that also advertises v2; all other paths see
        // `0`. Per spec a malformed value is treated as `0` (replay
        // everything still in the server's ring) — we log at debug to
        // avoid a noisy WARN on a header an old proxy might forward
        // unfiltered, but the parse failure is observable.
        let client_acked_offset = if symmetric_replay_requested && requested_resume.is_some() {
            match headers
                .get(DOWN_ACKED_HEADER)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim())
            {
                Some(value) if !value.is_empty() => match value.parse::<u64>() {
                    Ok(n) => n,
                    Err(error) => {
                        debug!(
                            ?error,
                            value,
                            "malformed X-Outline-Resume-Down-Acked; \
                             treating as 0 per spec",
                        );
                        0
                    },
                },
                _ => 0,
            }
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

    /// Session-ID-only echo, for paths that do not (yet) confirm the
    /// v1/v2 capabilities in their responses: the UDP-WS upgrade and the
    /// h3 CONNECT / XHTTP-h3 handlers.
    pub(in crate::server) fn session_echo(&self) -> ResumeResponseEcho {
        ResumeResponseEcho {
            session_id: self.issued_session_id,
            ..ResumeResponseEcho::default()
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
    let requested = headers
        .get(RESUME_REQUEST_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(SessionId::parse_hex);
    match decide(identity, requested) {
        RouteDecision::Relay(shard) => {
            let session_id =
                requested.expect("a Relay decision implies the client presented a resume id");
            let advert = EdgeResumeAdvert {
                session_id,
                resume_capable: header_is_one(headers, RESUME_CAPABLE_HEADER),
                ack_prefix: header_is_one(headers, ACK_PREFIX_HEADER),
                symmetric_replay: header_is_one(headers, SYMMETRIC_REPLAY_HEADER),
                down_acked: headers
                    .get(DOWN_ACKED_HEADER)
                    .and_then(|v| v.to_str().ok())
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0),
            };
            (RouteDecision::Relay(shard), Some(advert))
        },
        RouteDecision::Local => (RouteDecision::Local, None),
    }
}

/// Whether `name`'s value is the ASCII flag `1` (after trimming). Mirrors the
/// capability gating in [`ResumeContext::from_request_headers`].
fn header_is_one(headers: &axum::http::HeaderMap, name: &str) -> bool {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim() == "1")
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
        if let Some(id) = self.session_id
            && let Ok(value) = axum::http::HeaderValue::from_str(&id.to_hex())
        {
            headers.insert(SESSION_RESPONSE_HEADER, value);
        }
        if self.ack_prefix {
            headers.insert(ACK_PREFIX_HEADER, axum::http::HeaderValue::from_static("1"));
        }
        if self.symmetric_replay {
            headers.insert(SYMMETRIC_REPLAY_HEADER, axum::http::HeaderValue::from_static("1"));
        }
    }
}

#[cfg(test)]
#[path = "tests/resume_headers.rs"]
mod tests;
