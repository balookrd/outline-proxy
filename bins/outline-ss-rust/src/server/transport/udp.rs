use std::collections::HashSet;
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use axum::extract::ws::WebSocket;
use bytes::Bytes;
use futures_util::{FutureExt, StreamExt, future::BoxFuture, stream::FuturesUnordered};
use metrics::Counter;
use outline_wire::padding::{PaddingDecoder, PaddingScheme};
use parking_lot::Mutex;
use quinn::{RecvStream, SendStream, VarInt};
use tokio::sync::{OnceCell, OwnedSemaphorePermit, Semaphore, mpsc};
use tracing::{debug, info, warn};

use super::carrier_padding;
use crate::server::h3::vendored::{H3Stream, H3Transport, H3WebSocketStream};
use crate::{
    crypto::{
        CryptoError, SessionKeyCache, UdpCipherMode, UdpPacket, UserKey,
        decrypt_udp_packet_with_hint, diagnose_udp_packet, encrypt_udp_packet_for_response,
    },
    metrics::{AppProtocol, Metrics, PerUserCounters, Protocol, Transport},
    protocol::parse_target_addr,
    server::nat::{
        NatKey, NatScope, NatTable, ServerSessionId, UdpResponseCoding, UdpResponseSender,
        random_session_id,
    },
    server::replay::{self, ReplayCheck, ReplayStore},
};

use super::super::abort::AbortOnDrop;
use super::super::cluster::mesh::{CloseIntent, read_datagram, write_datagram};
use super::super::connect::resolve_udp_target;
use super::super::constants::{
    MAX_UDP_PAYLOAD_SIZE, UDP_CACHED_USER_INDEX_EMPTY, UDP_MAX_CONCURRENT_RELAY_TASKS,
    WS_CTRL_CHANNEL_CAPACITY,
};
use super::super::dns_cache::DnsCache;
use super::super::resumption::{
    OrphanRegistry, Parked, ParkedSsUdpStream, ResumeOutcome, SessionId,
};
use super::resume_headers::ResumeContext;
use super::upstream_source::{MeshDatagramHalves, MeshUpstreamSetup, UpstreamSource};
use super::ws_socket::{AxumWs, H3Ws, WsFrame, WsSocket};
use super::ws_writer;

/// Process-wide counter that hands out a unique 64-bit identifier to
/// every SS-UDP-over-WS stream. The id is stored on each registered
/// `ActiveSession` so that `detach_session_for_stream` only releases
/// the slot when we are still its owner — no risk of trampling a
/// concurrently-reconnected stream's sender.
static SS_UDP_STREAM_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

pub(in crate::server::transport) fn next_ss_udp_stream_id() -> u64 {
    SS_UDP_STREAM_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Process-wide singletons shared by every UDP relay task.
pub(in crate::server) struct UdpServerCtx {
    pub(in crate::server) metrics: Arc<Metrics>,
    pub(in crate::server) nat_table: Arc<NatTable>,
    pub(in crate::server) replay_store: Arc<ReplayStore>,
    pub(in crate::server) dns_cache: Arc<DnsCache>,
    pub(in crate::server) prefer_ipv4_upstream: bool,
    pub(in crate::server) relay_semaphore: Option<Arc<Semaphore>>,
    /// Cross-transport session-resumption registry. No-op when
    /// disabled in config; used by the SS-UDP-over-WS path to park
    /// the set of active NAT keys on disconnect and re-attach them
    /// to a resuming stream.
    pub(in crate::server) orphan_registry: Arc<OrphanRegistry>,
    /// Bounded LRU mapping `(user_index, salt) -> derived AEAD key`. Read on
    /// every UDP datagram before falling back to blake3/HKDF + ring's AES-GCM
    /// key schedule; on a hit, the per-packet derivation collapses into a
    /// hashmap lookup.
    pub(in crate::server) session_key_cache: Arc<SessionKeyCache>,
    /// Per-session bounded mpsc capacity for the NAT-reader → WS-writer
    /// fan-in. Resolved from `tuning.ws_data_channel_capacity` so the
    /// same knob governs both TCP and UDP relay backpressure.
    pub(in crate::server) ws_data_channel_capacity: usize,
}

/// Per-path state for a single UDP WebSocket session.
pub(in crate::server) struct UdpRouteCtx {
    pub(in crate::server) users: Arc<[UserKey]>,
    pub(in crate::server) protocol: Protocol,
    pub(in crate::server) path: Arc<str>,
    pub(in crate::server) candidate_users: Arc<[Arc<str>]>,
    /// Carrier-padding scheme resolved for this path at handshake time
    /// ([`carrier_padding::scheme_for_path`]). Disabled → plain wire (the
    /// unpadded carrier stays byte-for-byte identical). When enabled, inbound
    /// datagrams are decoded before SS decryption and downlink datagrams are
    /// framed by the response sender. For a combined-SS path the UDP leg
    /// resolves the same base path as the TCP leg, so listing the combined base
    /// path in `[padding] paths` pads both legs uniformly.
    pub(in crate::server) padding: PaddingScheme,
}

/// Set size at (and above) which [`StreamNatKeys::track`] reconciles the
/// tracked keys against the live NAT table. Also the floor of the adaptive
/// threshold: a stream fanning out to many *live* targets re-arms at twice its
/// live-key count, so the O(n) sweep stays amortised O(1) per datagram.
const NAT_KEYS_RECONCILE_FLOOR: usize = 64;

/// NAT keys one SS-UDP stream is the active outbound responder of.
///
/// Inserted on every successful `register_session`; drained on park-on-drop.
/// `HashSet` collapses the dedup check into a single hash lookup — the original
/// `Vec<NatKey>` form did a linear `contains()` under the lock on every
/// datagram.
///
/// Bounded-resource guard: a NAT entry that goes idle is evicted from
/// [`NatTable`] on its own timer, which used to leave its key behind here
/// forever, so a long-lived stream's set grew with every unique target it ever
/// touched. [`Self::track`] therefore reconciles against the live table once
/// the set crosses [`NAT_KEYS_RECONCILE_FLOOR`], dropping keys whose entry is
/// gone. The set is thus bounded by the stream's live NAT entries (themselves
/// capped by `udp_nat_max_entries`) plus the keys inserted since the last
/// reconcile.
#[derive(Default)]
pub(in crate::server::transport) struct StreamNatKeys {
    keys: HashSet<NatKey>,
    /// Set size that arms the next reconcile pass.
    reconcile_at: usize,
}

impl StreamNatKeys {
    pub(in crate::server::transport) fn new() -> Self {
        Self {
            keys: HashSet::new(),
            reconcile_at: NAT_KEYS_RECONCILE_FLOOR,
        }
    }

    /// Records `key` as owned by this stream, reconciling the set against the
    /// live NAT table when it has grown past the current threshold. `is_live`
    /// reports whether a key still has an entry in the table.
    fn track(&mut self, key: NatKey, is_live: impl Fn(&NatKey) -> bool) {
        self.keys.insert(key);
        if self.keys.len() < self.reconcile_at {
            return;
        }
        self.keys.retain(|key| is_live(key));
        self.reconcile_at = self.keys.len().saturating_mul(2).max(NAT_KEYS_RECONCILE_FLOOR);
    }

    /// Adopts keys re-pointed at this stream by a resume hit. Their entries
    /// were just confirmed live by the resume path, so no reconcile is needed.
    pub(in crate::server::transport) fn adopt(&mut self, keys: impl IntoIterator<Item = NatKey>) {
        self.keys.extend(keys);
    }

    /// Drains every tracked key (park-on-drop).
    pub(in crate::server::transport) fn take(&mut self) -> HashSet<NatKey> {
        self.reconcile_at = NAT_KEYS_RECONCILE_FLOOR;
        std::mem::take(&mut self.keys)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.keys.len()
    }
}

/// Re-points every parked NAT entry that is still live at `sender`, under
/// `coding` and this stream's `stream_id`, and returns the keys that actually
/// had one. Keys whose entry was idle-evicted while the session was parked are
/// reported (at debug) and dropped — there is nothing left to address.
///
/// Shared by the direct SS-UDP resume (`resolve_nat_scope`) and the v5 mesh
/// splice, which differ only in the coding they re-point the slot with: the
/// direct path seals responses itself, the relayed one hands plaintext to its
/// edge.
pub(in crate::server::transport) fn reattach_parked_nat_keys(
    nat_table: &NatTable,
    keys: impl IntoIterator<Item = NatKey>,
    sender: &UdpResponseSender,
    coding: &UdpResponseCoding,
    stream_id: u64,
) -> Vec<NatKey> {
    let mut reattached = Vec::new();
    for key in keys {
        match nat_table.try_get(&key) {
            Some(entry) => {
                entry.register_session(sender.clone(), coding.clone(), stream_id);
                reattached.push(key);
            },
            None => {
                debug!(
                    user = %key.user_id,
                    target = %key.target,
                    "ss-udp resume: parked NAT entry already evicted; skipping"
                );
            },
        }
    }
    reattached
}

/// Releases this stream's response sender from every NAT entry it registered on
/// and returns the keys it was still the owner of — the set a park may preserve.
///
/// The detach is what keeps a departed carrier's writer task from being held
/// open by a NAT entry's sender clone; see [`release_ss_udp_stream_on_drop`].
/// Entries a newer stream has already taken over (`stream_id` mismatch) are left
/// alone and excluded: they are not ours to clear, nor ours to park.
pub(in crate::server::transport) fn detach_stream_nat_keys(
    nat_table: &NatTable,
    stream_id: u64,
    keys: HashSet<NatKey>,
) -> Vec<NatKey> {
    let mut detached = Vec::with_capacity(keys.len());
    for key in keys {
        if let Some(entry) = nat_table.try_get(&key) {
            if entry.detach_session_for_stream(stream_id) {
                detached.push(key);
            } else {
                debug!(
                    target = %key.target,
                    "ss-udp teardown: NAT entry already taken over by another stream; skipping"
                );
            }
        }
    }
    detached
}

/// Per-session mutable state shared across concurrent datagram tasks. Shared as
/// a single `Arc` — the per-datagram fan-out clones that one handle rather than
/// deep-cloning a struct of six `Arc` fields (six atomic increments per
/// datagram, six decrements when the relay future completes).
struct UdpSessionState {
    session_recorded: AtomicBool,
    cached_user_index: AtomicUsize,
    /// Stream-unique identifier issued at WS-Upgrade time and used by
    /// the SS-UDP park / resume paths to address NAT entries' sender
    /// slots without trampling a concurrently-reconnected stream.
    stream_id: u64,
    /// NAT keys this stream owns. `parking_lot::Mutex` since the hot path is
    /// per-datagram and async-await isn't needed.
    nat_keys: Mutex<StreamNatKeys>,
    /// User the stream authenticated as (set once on the first
    /// successful AEAD decrypt). Captured early so park-on-drop can
    /// stash it as the parked entry's owner. `OnceLock` keeps the
    /// per-datagram read on the hot path lock-free (plain atomic
    /// acquire load); the one-time write CAS is taken at most once
    /// per stream.
    authenticated_user_id: OnceLock<Arc<str>>,
    /// Session ID the client offered for resumption, parsed at
    /// WS-Upgrade. Consumed (`take()`) on the first authenticated
    /// datagram by the resume path; subsequent datagrams see `None`
    /// and skip the resume attempt unconditionally.
    pending_resume_request: Mutex<Option<SessionId>>,
    /// Session ID the server minted for this stream (the
    /// `X-Outline-Session` response header value). Used as the
    /// registry key on park.
    issued_session_id: Option<SessionId>,
    /// This stream's NAT scope ([`NatKey::scope`]), resolved exactly
    /// once on the first datagram and shared by every subsequent one so
    /// all of a stream's NAT keys line up. `get_or_init` also folds in
    /// the first-frame resume attempt: on a resume hit it re-points the
    /// parked entries and yields the *parked* scope (so the resumed
    /// carrier keeps addressing the original entries); otherwise it
    /// yields the issued session id, keeping two independent sessions on
    /// distinct entries. `None` inside means the historical shared-entry
    /// behaviour (resumption disabled / no issued id). The `OnceCell`
    /// serialises concurrent in-flight datagrams so none races ahead
    /// with the wrong scope.
    nat_scope: OnceCell<Option<NatScope>>,
}

/// Resolves this stream's NAT scope ([`NatKey::scope`]) once, folding in the
/// first-frame resume attempt. Called through `nat_scope.get_or_init`, so it
/// runs exactly once per stream and every concurrent datagram observes the same
/// result.
///
/// On a resume hit it re-points the parked SS-UDP stream's surviving NAT entries
/// at this stream's `sender` and returns the **parked** scope, so the resumed
/// carrier keeps addressing the original entries (and hence the same upstream
/// sockets / source ports). Otherwise — resumption disabled, no resume request,
/// a miss, or every parked entry already evicted — it returns the **issued**
/// session id, which keeps two independent sessions to the same target on
/// distinct entries. `None` (no issued id) preserves the historical shared
/// last-writer-wins entry.
///
/// Cross-shape mismatches (resume id minted under TCP / VLESS-UDP / VLESS mux)
/// are reported as a security event and treated as a quiet miss — the stream
/// falls back to its issued scope.
async fn resolve_nat_scope(
    server: &UdpServerCtx,
    session: &UdpSessionState,
    user_id: &Arc<str>,
    coding: &UdpResponseCoding,
    sender: &UdpResponseSender,
    path: &str,
) -> Option<NatScope> {
    // Fresh sessions pin to their issued id: distinct between two independent
    // sessions, and echoed back to the client so a later resume presents it.
    let issued_scope = session.issued_session_id.map(|id| *id.as_bytes());
    if !server.orphan_registry.enabled() {
        return issued_scope;
    }
    let resume_id = match session.pending_resume_request.lock().take() {
        Some(id) => id,
        None => return issued_scope,
    };
    let outcome = server.orphan_registry.take_for_resume(resume_id, user_id).await;
    let parked = match outcome {
        ResumeOutcome::Hit(Parked::SsUdpStream(parked)) => parked,
        ResumeOutcome::Hit(other) => {
            warn!(
                user = %user_id,
                path,
                parked_kind = other.kind(),
                "rejecting ss-udp resume: parked entry is not an ss-udp stream"
            );
            return issued_scope;
        },
        ResumeOutcome::Miss(_) => return issued_scope,
    };
    // Every parked key of one session shares its scope; adopt it so this
    // carrier's own datagrams line up with the re-pointed entries.
    let parked_scope = parked.nat_keys.first().and_then(|key| key.scope);
    let keys_for_self = reattach_parked_nat_keys(
        &server.nat_table,
        parked.nat_keys,
        sender,
        coding,
        session.stream_id,
    );
    let reattached = keys_for_self.len();
    if reattached > 0 {
        session.nat_keys.lock().adopt(keys_for_self);
        info!(
            user = %user_id,
            path,
            reattached,
            "ss-udp stream resumed from orphan registry"
        );
        parked_scope
    } else {
        // Hit but every parked entry already evicted: nothing to address, so
        // start fresh under the issued scope (self-consistent with a later
        // resume, which will re-pin to whatever this stream parks under).
        issued_scope
    }
}

/// Opens and vets one inbound SS-UDP datagram: everything both upstream shapes
/// do before they diverge — cipher selection, SS-2022 replay defence, the
/// per-session client metrics and the one-time user capture.
///
/// `Ok(None)` is a datagram legitimately dropped here (a replay, or the replay
/// store at capacity); the caller must not forward it. `Err` is a datagram this
/// route cannot authenticate.
///
/// Split out of the direct relay because a **cluster edge** needs exactly this
/// half and none of the next one: it terminates the client's crypto but owns no
/// NAT entry, so what it does with the opened packet is forward its plaintext to
/// the home that does.
fn authenticate_udp_datagram(
    server: &UdpServerCtx,
    route: &UdpRouteCtx,
    session: &UdpSessionState,
    data: &[u8],
) -> Result<Option<UdpPacket>> {
    let preferred_user_index = match session.cached_user_index.load(Ordering::Relaxed) {
        UDP_CACHED_USER_INDEX_EMPTY => None,
        index => Some(index),
    };
    let (packet, user_index) = match decrypt_udp_packet_with_hint(
        route.users.as_ref(),
        data,
        preferred_user_index,
        Some(server.session_key_cache.as_ref()),
    ) {
        Ok(result) => result,
        Err(CryptoError::UnknownUser) => {
            debug!(
                path = %route.path,
                candidates = ?route.candidate_users,
                attempts = ?diagnose_udp_packet(route.users.as_ref(), data),
                "udp authentication failed for all path candidates"
            );
            return Err(anyhow!(
                "no configured key matched the incoming udp data on path {} candidates={:?}",
                route.path,
                route.candidate_users,
            ));
        },
        Err(error) => return Err(anyhow!(error)),
    };
    session.cached_user_index.store(user_index, Ordering::Relaxed);
    let user_id = packet.user.id_arc();
    // Capture the authenticated user id once. Subsequent datagrams
    // hit the lock-free `OnceLock::get_or_init` fast path: a single
    // atomic acquire load with no Arc clone when already populated.
    session.authenticated_user_id.get_or_init(|| Arc::clone(&user_id));
    if let Some((csid, pid)) = replay::replay_key(&packet.session, packet.packet_id) {
        match server.replay_store.check_and_mark(csid, pid) {
            ReplayCheck::Fresh => {},
            ReplayCheck::Replay => {
                server
                    .metrics
                    .record_udp_replay_dropped(Arc::clone(&user_id), route.protocol);
                warn!(
                    user = packet.user.id(),
                    path = %route.path,
                    packet_id = pid,
                    "dropping replayed ss-2022 udp datagram"
                );
                return Ok(None);
            },
            ReplayCheck::StoreFull => {
                server
                    .metrics
                    .record_udp_replay_store_full_dropped(Arc::clone(&user_id), route.protocol);
                warn!(
                    user = packet.user.id(),
                    path = %route.path,
                    packet_id = pid,
                    "dropping ss-2022 udp datagram: replay store at capacity"
                );
                return Ok(None);
            },
        }
    }
    if session.session_recorded.swap(true, Ordering::Relaxed) {
        server.metrics.record_client_last_seen(Arc::clone(&user_id));
    } else {
        server.metrics.record_client_session(
            Arc::clone(&user_id),
            route.protocol,
            Transport::Udp,
            AppProtocol::Shadowsocks,
        );
    }
    debug!(
        user = packet.user.id(),
        cipher = packet.user.cipher().as_str(),
        path = %route.path,
        "udp shadowsocks user authenticated"
    );
    Ok(Some(packet))
}

/// Relays one inbound SS-UDP datagram through this node's own NAT table.
/// `response_sender` is the stream's downlink handle (see [`run_udp_relay`]): a
/// clone of one `Arc` shared by every datagram of the stream, re-registered on
/// the NAT entry alongside this datagram's `UdpCipherMode`.
async fn handle_udp_datagram_common(
    server: &UdpServerCtx,
    route: &UdpRouteCtx,
    session: &UdpSessionState,
    data: Bytes,
    response_sender: UdpResponseSender,
) -> Result<()> {
    let started_at = std::time::Instant::now();
    let Some(packet) = authenticate_udp_datagram(server, route, session, &data)? else {
        return Ok(());
    };
    let user_id = packet.user.id_arc();

    let coding = UdpResponseCoding::Ss {
        user: packet.user.clone(),
        session: packet.session.clone(),
    };

    // Resolve this stream's NAT scope before keying the entry — on the first
    // datagram this also runs the first-frame resume (re-pointing every
    // surviving parked entry at `response_sender`). `get_or_init` runs the
    // closure once and makes concurrent in-flight datagrams await the same
    // scope, so none races ahead and keys an entry under a stale scope.
    let scope = *session
        .nat_scope
        .get_or_init(|| {
            resolve_nat_scope(server, session, &user_id, &coding, &response_sender, &route.path)
        })
        .await;

    relay_socks5_datagram(
        server,
        &UdpDatagramCtx {
            user_id,
            fwmark: packet.user.fwmark(),
            scope,
            stream_id: session.stream_id,
            coding,
            nat_keys: &session.nat_keys,
            protocol: route.protocol,
            path: &route.path,
            started_at,
        },
        &packet.payload,
        response_sender,
    )
    .await
}

/// Everything the post-decryption half of the UDP relay needs and cannot read
/// out of the datagram itself.
///
/// The split exists because a **v5 mesh home** has no decrypted packet to derive
/// any of it from: the edge terminated the client's crypto, so the identity
/// arrives once per stream in the OPEN/USER exchange while only the *target*
/// still rides inside each datagram. Everything here is therefore supplied by
/// the caller, and that is also the ownership rule — `user_id`, `fwmark` and
/// `scope` come from the session, never from the datagram, so a datagram can
/// only ever reach a NAT entry keyed to the session that sent it.
pub(in crate::server::transport) struct UdpDatagramCtx<'a> {
    /// Authenticated user the NAT entry is keyed to. The direct path reads it
    /// off the packet it just opened; the v5 home takes the edge's attestation.
    pub(in crate::server::transport) user_id: Arc<str>,
    /// Routing mark applied to the NAT socket, a per-user config property.
    pub(in crate::server::transport) fwmark: Option<u32>,
    /// Session discriminator every key of this stream shares; see [`NatScope`].
    pub(in crate::server::transport) scope: Option<NatScope>,
    pub(in crate::server::transport) stream_id: u64,
    /// How the NAT entry must encode responses back to this carrier.
    pub(in crate::server::transport) coding: UdpResponseCoding,
    /// Keys this stream owns, for park-on-drop.
    pub(in crate::server::transport) nat_keys: &'a Mutex<StreamNatKeys>,
    pub(in crate::server::transport) protocol: Protocol,
    /// Route path (direct) or a stable relay label (mesh); logs and nothing else.
    pub(in crate::server::transport) path: &'a str,
    /// When this datagram entered the relay, for the request-latency histogram.
    pub(in crate::server::transport) started_at: std::time::Instant,
}

/// Relays one SOCKS5-wrapped datagram — `TargetAddr || payload`, the body of an
/// SS-UDP packet — to its target through the NAT table, and registers this
/// carrier as the entry's responder.
///
/// The identity-supplied entry point both UDP paths share: the direct path
/// reaches it with values it decrypted itself, the v5 mesh splice with values
/// the edge attested. Nothing below this line knows which.
pub(in crate::server::transport) async fn relay_socks5_datagram(
    server: &UdpServerCtx,
    ctx: &UdpDatagramCtx<'_>,
    datagram: &[u8],
    response_sender: UdpResponseSender,
) -> Result<()> {
    let Some((target, consumed)) = parse_target_addr(datagram)? else {
        return Err(anyhow!("udp packet is missing a complete target address"));
    };
    let payload = &datagram[consumed..];

    let resolved =
        resolve_udp_target(server.dns_cache.as_ref(), &target, server.prefer_ipv4_upstream).await?;
    debug!(
        user = %ctx.user_id,
        fwmark = ?ctx.fwmark,
        path = ctx.path,
        target = %target,
        resolved = %resolved,
        "udp datagram relay"
    );

    let nat_key = NatKey {
        user_id: Arc::clone(&ctx.user_id),
        fwmark: ctx.fwmark,
        target: resolved,
        scope: ctx.scope,
    };
    let entry = server
        .nat_table
        .get_or_create(
            nat_key.clone(),
            ServerSessionId::for_coding(&ctx.coding),
            Arc::clone(&server.metrics),
        )
        .await
        .with_context(|| format!("failed to create NAT entry for {resolved}"))?;

    entry.register_session(response_sender, ctx.coding.clone(), ctx.stream_id);
    // Per-user accounting belongs to the node that terminates the client
    // session; see [`UdpResponseCoding::terminates_client_session`]. On the v5
    // relayed path that is the edge, so the home stays silent on every
    // `user`-labelled byte/request series and counts this traffic only on its
    // `role="home"` mesh counters — the same split `splice_plaintext_tcp`
    // makes. Node-local drops below are recorded either way.
    let accounts_per_user = ctx.coding.terminates_client_session();
    let record_request = |result: &'static str| {
        if accounts_per_user {
            server.metrics.record_udp_request(
                Arc::clone(&ctx.user_id),
                ctx.protocol,
                AppProtocol::Shadowsocks,
                result,
                ctx.started_at.elapsed().as_secs_f64(),
            );
        }
    };
    // Track the NAT key as one this stream owns, for park-on-drop. Insertion is
    // a no-op on duplicates; past the reconcile threshold the set is swept
    // against the live NAT table so idle-evicted targets do not accumulate.
    ctx.nat_keys
        .lock()
        .track(nat_key, |key| server.nat_table.contains(key));

    if payload.len() > MAX_UDP_PAYLOAD_SIZE {
        server.metrics.record_udp_oversized_datagram_dropped(
            Arc::clone(&ctx.user_id),
            ctx.protocol,
            AppProtocol::Shadowsocks,
            "up",
        );
        warn!(
            user = %ctx.user_id,
            path = ctx.path,
            target = %resolved,
            plaintext_bytes = payload.len(),
            max_udp_payload_bytes = MAX_UDP_PAYLOAD_SIZE,
            "dropping oversized udp datagram before upstream send"
        );
        record_request("error");
        return Ok(());
    }
    if accounts_per_user {
        entry
            .user_counters()
            .udp_in(AppProtocol::Shadowsocks, ctx.protocol)
            .increment(payload.len() as u64);
    }
    if let Err(error) = entry.socket().send_to(payload, resolved).await {
        record_request("error");
        return Err(error).with_context(|| format!("failed to send UDP datagram to {resolved}"));
    }
    entry.touch();
    record_request("success");

    Ok(())
}

// ── Cluster edge (v5): the home owns the NAT, this node owns the crypto ───────

/// The client crypto a v5 SS-UDP edge seals relayed responses under.
///
/// The home never sees the client's key — that is the whole point of terminating
/// crypto on the edge — so it hands back the SOCKS5-wrapped plaintext its NAT
/// reader produced ([`UdpResponseCoding::Plaintext`]) and the edge seals it here.
/// Mirrors the `ActiveSession` snapshot the direct path's NAT reader takes: the
/// keys are refreshed by every uplink datagram, because an SS-2022 client may
/// rotate its session id mid-stream, and read once per response.
struct EdgeSeal {
    /// `None` only in the window before the first authenticated datagram, which
    /// no response can precede — the mesh relay is not even attached yet.
    keys: Mutex<Option<SealKeys>>,
    /// One server session id per relayed carrier, where the direct path has one
    /// per NAT entry. Required by the SS-2022 arms of
    /// [`encrypt_udp_packet_for_response`] and ignored by the legacy one; `None`
    /// only if the RNG failed, in which case an SS-2022 response cannot be
    /// sealed and is dropped rather than sent malformed.
    ///
    /// Per carrier is safe — and strictly gentler on the client than per target
    /// — because a client re-arms its downlink replay window whenever the server
    /// session id changes, and this carrier numbers every response from one
    /// monotonic counter under one id.
    server_session_id: Option<[u8; 8]>,
    /// Packet counter within `server_session_id`; strictly increasing, which is
    /// exactly what the client's replay window requires.
    next_packet_id: AtomicU64,
}

/// The per-datagram half of [`EdgeSeal`]: what the client's own packets said its
/// key and cipher session are.
#[derive(Clone)]
struct SealKeys {
    user: UserKey,
    session: UdpCipherMode,
}

impl EdgeSeal {
    fn new() -> Self {
        Self {
            keys: Mutex::new(None),
            // A failure here is not fatal to the session: a legacy-cipher client
            // never needs the id, and an SS-2022 one loses its responses (logged
            // at the seal site) rather than the whole carrier.
            server_session_id: random_session_id().ok(),
            next_packet_id: AtomicU64::new(0),
        }
    }

    /// Records the crypto the latest authenticated client datagram carried.
    fn observe(&self, packet: &UdpPacket) {
        *self.keys.lock() = Some(SealKeys {
            user: packet.user.clone(),
            session: packet.session.clone(),
        });
    }

    /// Seals one relayed response — `TargetAddr(source) || payload`, exactly the
    /// body the direct path's NAT reader would have encrypted — for the client.
    /// `None` when the datagram is unusable (no keys yet, a malformed wrapper, or
    /// an SS-2022 seal with no server session id to name).
    fn seal(&self, wrapped: &[u8]) -> Option<SealedResponse> {
        let keys = self.keys.lock().clone()?;
        let (source, consumed) = match parse_target_addr(wrapped) {
            Ok(Some(parsed)) => parsed,
            other => {
                warn!(?other, "dropping a relayed udp response with no target address");
                return None;
            },
        };
        let payload = &wrapped[consumed..];
        match encrypt_udp_packet_for_response(
            &keys.user,
            &source,
            payload,
            &keys.session,
            self.server_session_id,
            self.next_packet_id.fetch_add(1, Ordering::Relaxed),
        ) {
            Ok(bytes) => Some(SealedResponse { bytes, payload_len: payload.len() }),
            Err(error) => {
                warn!(%error, "failed to seal a relayed udp response for the client");
                None
            },
        }
    }
}

/// One sealed downlink datagram, plus the length of the payload the *target*
/// actually sent — the figure the direct path bills the user for, with the
/// home's SOCKS5 wrapper excluded as the transport framing it is.
struct SealedResponse {
    bytes: Vec<u8>,
    payload_len: usize,
}

/// Owns the mesh downlink half so that dropping the pump says *why* the edge
/// stopped reading.
///
/// The `STOP_SENDING(CarrierEnded)` this sends is what makes the home re-park
/// the session instead of tearing it down — the same signal the byte-stream
/// [`super::upstream_source::MeshUpstream`] emits on drop, spelled out here so it
/// stays deliberate rather than incidental (quinn's own drop would send code `0`,
/// which [`CloseIntent::from_code`] reads the same way).
struct EdgeDownlinkHalf(RecvStream);

impl Drop for EdgeDownlinkHalf {
    fn drop(&mut self) {
        // Fails only on a stream already finished or reset, where there is
        // nothing left to tell the home.
        let _ = self.0.stop(VarInt::from_u32(CloseIntent::CarrierEnded.code()));
    }
}

/// Everything the downlink pump needs; bundled so the spawn site stays readable.
struct EdgeDownlinkCtx {
    seal: Arc<EdgeSeal>,
    sender: UdpResponseSender,
    metrics: Arc<Metrics>,
    user_id: Arc<str>,
    user_counters: Arc<PerUserCounters>,
    protocol: Protocol,
    down_bytes: Counter,
    down_datagrams: Counter,
    /// Keeps the relay's pool slot counted for as long as this half lives.
    _permit: Arc<OwnedSemaphorePermit>,
}

/// Drains relayed responses off the mesh and seals each one for the client.
///
/// One datagram in is one datagram out — the length framing on the mesh is what
/// preserves the boundary an SS-UDP packet's AEAD depends on, and coalescing two
/// would decrypt as garbage on the client. Bounded on every axis: the read caps
/// each datagram at the framing's own maximum, one reusable buffer serves the
/// whole pump, and the client-facing send rides the carrier's bounded channel.
///
/// Per-user accounting happens **here**, not on the home: this is the node that
/// terminates the client session, and the home deliberately stays silent on the
/// `user`-labelled series for a `Plaintext` attachment (see
/// [`UdpResponseCoding::terminates_client_session`]).
async fn run_edge_udp_downlink(mut recv: EdgeDownlinkHalf, ctx: EdgeDownlinkCtx) {
    let mut buf = Vec::new();
    loop {
        let len = match read_datagram(&mut recv.0, &mut buf).await {
            // The home finished the stream: the relayed session is over.
            Ok(None) => break,
            Ok(Some(len)) => len,
            Err(error) => {
                debug!(?error, "relayed udp downlink read from the mesh ended");
                break;
            },
        };
        ctx.down_bytes.increment(len as u64);
        ctx.down_datagrams.increment(1);
        let Some(sealed) = ctx.seal.seal(&buf[..len]) else {
            continue;
        };
        ctx.user_counters
            .udp_out(AppProtocol::Shadowsocks, ctx.protocol)
            .increment(sealed.payload_len as u64);
        ctx.metrics.record_udp_response_datagrams(
            Arc::clone(&ctx.user_id),
            ctx.protocol,
            AppProtocol::Shadowsocks,
            1,
        );
        if !ctx.sender.send_bytes(Bytes::from(sealed.bytes)).await {
            debug!("relayed udp response dropped: the client carrier is gone");
            break;
        }
    }
}

/// The edge half of a v5 relayed SS-UDP session: the mesh stream that stands in
/// for this node's NAT table.
///
/// The relay must **never park** such a session — the entries it would hand on
/// live on the home — which [`super::mesh_relay::edge_upstream`] already enforces
/// by issuing no session id.
struct MeshUdpEdge {
    /// Consumed by the first authenticated datagram: the second phase attests a
    /// user, and the edge learns one only by decrypting. `None` afterwards.
    setup: Option<MeshUpstreamSetup>,
    /// What the downlink pump seals with; shared with it from before it starts.
    seal: Arc<EdgeSeal>,
    /// Present once the hand-off completed.
    attached: Option<AttachedMeshUdp>,
}

/// The live half of [`MeshUdpEdge`], after the USER frame was accepted.
struct AttachedMeshUdp {
    /// The ONLY writer to the mesh stream: the relay loop forwards inline rather
    /// than fanning out, so datagrams cannot interleave mid-frame. Nothing here
    /// blocks long enough to want concurrency — the edge resolves no DNS and
    /// binds no socket; the home does both.
    send: SendStream,
    /// The user this carrier attested in its USER frame, and therefore the only
    /// identity the home will route this stream's datagrams under. Every later
    /// datagram is checked against it ([`MeshUdpEdge::forward`]).
    attested_user: Arc<str>,
    /// Whether the mismatch above was already logged for this carrier. The
    /// counter carries the volume; the warning fires once, so a client cannot
    /// amplify its own datagrams into the log.
    mismatch_warned: bool,
    budget: Duration,
    up_bytes: Counter,
    up_datagrams: Counter,
    user_counters: Arc<PerUserCounters>,
    /// The downlink pump. Aborted on drop as a backstop; the ordinary path is
    /// [`AttachedMeshUdp::shutdown`], which also *waits* for it.
    pump: AbortOnDrop<()>,
}

impl AttachedMeshUdp {
    /// Ends the relay: FIN on the uplink so the home re-parks the session, then
    /// stop the downlink pump and wait for it.
    ///
    /// The wait is load-bearing, not tidiness. The pump holds a clone of the
    /// response sender, and with it a clone of the carrier writer's data channel;
    /// returning while it still lived would leave that channel open and the
    /// writer task would never observe its close — the same hang
    /// [`release_ss_udp_stream_on_drop`] exists to prevent on the NAT side.
    async fn shutdown(mut self) {
        let _ = self.send.finish();
        let pump = self.pump.into_inner();
        pump.abort();
        let _ = pump.await;
    }
}

impl MeshUdpEdge {
    fn new(setup: MeshUpstreamSetup) -> Self {
        Self {
            setup: Some(setup),
            seal: Arc::new(EdgeSeal::new()),
            attached: None,
        }
    }

    /// Forwards one authenticated client datagram to the home.
    ///
    /// `Err` means the mesh itself is unusable — the edge has no other upstream,
    /// so the caller tears the carrier down and the client redials (the home
    /// still holds the park). Everything a single datagram can get wrong — a
    /// missing target address, an oversized payload, an identity this carrier
    /// never attested — is handled here and reported, exactly as the direct path
    /// reports it, without ending the session.
    async fn forward(
        &mut self,
        server: &UdpServerCtx,
        route: &UdpRouteCtx,
        packet: &UdpPacket,
        response_sender: &UdpResponseSender,
        started_at: std::time::Instant,
    ) -> Result<()> {
        let user_id = packet.user.id_arc();

        // Everything below mirrors `relay_socks5_datagram`'s bookkeeping, which
        // the home no longer does for a relayed session: per-user accounting
        // belongs to the node that terminates the client, and that is this one.
        // Note it names the *packet's* user, not the attested one — the guard
        // right below is what keeps the two the same for anything forwarded.
        let record_request = |result: &'static str| {
            server.metrics.record_udp_request(
                Arc::clone(&user_id),
                route.protocol,
                AppProtocol::Shadowsocks,
                result,
                started_at.elapsed().as_secs_f64(),
            );
        };

        // One carrier, one identity. The USER frame attested a single user to
        // the home, and the home routes every datagram of this stream under that
        // user's NAT identity, fwmark and policy routing — it re-authenticates
        // nothing, because only this node holds the keys. So a datagram that
        // opened under a *different* credential must not ride this stream: it
        // would egress as somebody else and be billed to them.
        //
        // Dropped rather than refused: a client only reaches here with a second
        // valid credential for this path, and tearing the carrier down would let
        // whoever holds it end the attested user's live session at will. The
        // drop is per datagram, counted, and leaves the session untouched.
        if let Some(attached) = self.attached.as_mut()
            && *attached.attested_user != *user_id
        {
            server.metrics.record_udp_relay_drop(
                Transport::Udp,
                route.protocol,
                AppProtocol::Shadowsocks,
                "relayed_user_mismatch",
            );
            if !std::mem::replace(&mut attached.mismatch_warned, true) {
                warn!(
                    user = %user_id,
                    attested_user = %attached.attested_user,
                    path = %route.path,
                    "dropping a relayed udp datagram: its user is not the one this carrier attested"
                );
            }
            record_request("error");
            return Ok(());
        }
        // Past the guard, so the response seal can only ever take keys from the
        // attested user: sealing under another user's key would hand this
        // carrier's responses to a client that cannot open them — or, worse,
        // hand the attested user's responses to one that can.
        self.seal.observe(packet);
        if self.attached.is_none() {
            let setup = self
                .setup
                .take()
                .context("the mesh relay setup was already consumed")?;
            self.attached =
                Some(self.attach(setup, server, route, response_sender, &user_id).await?);
        }
        let attached = self
            .attached
            .as_mut()
            .expect("the hand-off above populates it or returns");

        let Some((target, consumed)) = parse_target_addr(&packet.payload)? else {
            record_request("error");
            return Err(anyhow!("udp packet is missing a complete target address"));
        };
        let payload_len = packet.payload.len() - consumed;
        if payload_len > MAX_UDP_PAYLOAD_SIZE {
            server.metrics.record_udp_oversized_datagram_dropped(
                Arc::clone(&user_id),
                route.protocol,
                AppProtocol::Shadowsocks,
                "up",
            );
            warn!(
                user = %user_id,
                path = %route.path,
                target = %target,
                plaintext_bytes = payload_len,
                max_udp_payload_bytes = MAX_UDP_PAYLOAD_SIZE,
                "dropping oversized udp datagram before relaying it to the home"
            );
            record_request("error");
            return Ok(());
        }
        attached
            .user_counters
            .udp_in(AppProtocol::Shadowsocks, route.protocol)
            .increment(payload_len as u64);

        // One client packet is one mesh datagram: the boundary the home's router
        // keys on, and the one a byte splice would destroy. Bounded by the health
        // budget — a home that stops draining fills the QUIC send window, and a
        // write stuck past the budget is a dead relay, not a slow one.
        let write = write_datagram(&mut attached.send, &packet.payload);
        match tokio::time::timeout(attached.budget, write).await {
            Ok(Ok(())) => {},
            Ok(Err(error)) => {
                record_request("error");
                return Err(error.context("relaying an ss-udp datagram to the home"));
            },
            Err(_elapsed) => {
                record_request("error");
                return Err(anyhow!("the mesh relay stalled past the health budget"));
            },
        }
        attached.up_bytes.increment(packet.payload.len() as u64);
        attached.up_datagrams.increment(1);
        record_request("success");
        Ok(())
    }

    /// Runs the second phase of the v5 hand-off and starts the downlink pump.
    async fn attach(
        &self,
        setup: MeshUpstreamSetup,
        server: &UdpServerCtx,
        route: &UdpRouteCtx,
        response_sender: &UdpResponseSender,
        user_id: &Arc<str>,
    ) -> Result<AttachedMeshUdp> {
        let MeshDatagramHalves {
            send,
            recv,
            budget,
            up_bytes,
            up_datagrams,
            down_bytes,
            down_datagrams,
            permit,
        } = setup
            .attach_datagrams(user_id)
            .await
            .context("attesting the ss-udp user to the home")?;
        let user_counters = server.metrics.user_counters(user_id);
        debug!(
            user = %user_id,
            path = %route.path,
            "ss-udp session relayed to its home; this node terminates the client crypto",
        );
        let pump = tokio::spawn(run_edge_udp_downlink(
            EdgeDownlinkHalf(recv),
            EdgeDownlinkCtx {
                seal: Arc::clone(&self.seal),
                sender: response_sender.clone(),
                metrics: Arc::clone(&server.metrics),
                user_id: Arc::clone(user_id),
                user_counters: Arc::clone(&user_counters),
                protocol: route.protocol,
                down_bytes,
                down_datagrams,
                _permit: permit,
            },
        ));
        Ok(AttachedMeshUdp {
            send,
            attested_user: Arc::clone(user_id),
            mismatch_warned: false,
            budget,
            up_bytes,
            up_datagrams,
            user_counters,
            pump: AbortOnDrop::new(pump),
        })
    }

    /// Ends the relay, if one was ever established.
    async fn shutdown(self) {
        if let Some(attached) = self.attached {
            attached.shutdown().await;
        }
    }
}

pub(in crate::server::transport) async fn run_udp_relay<T: WsSocket>(
    socket: T,
    server: Arc<UdpServerCtx>,
    route: Arc<UdpRouteCtx>,
    resume: ResumeContext,
    injected_monitor: Option<Arc<super::throughput_monitor::ThroughputMonitor>>,
    upstream: UpstreamSource,
) -> Result<()> {
    // Cluster edge (v5): the session being served lives on another node, so this
    // relay owns the client's crypto and nothing else — no NAT entry, no park.
    // `Direct` is every other case, including a v4 relayed carrier on the *home*
    // (which decrypts and owns its NAT exactly as a local session does).
    let mut mesh = match upstream {
        UpstreamSource::Direct => None,
        UpstreamSource::Mesh(setup) => Some(MeshUdpEdge::new(setup)),
    };
    let (mut reader, writer) = socket.split_io();
    let (outbound_data_tx, outbound_data_rx) =
        mpsc::channel::<T::Msg>(server.ws_data_channel_capacity);
    let (outbound_ctrl_tx, outbound_ctrl_rx) = mpsc::channel::<T::Msg>(WS_CTRL_CHANNEL_CAPACITY);
    let session = Arc::new(UdpSessionState {
        session_recorded: AtomicBool::new(false),
        cached_user_index: AtomicUsize::new(UDP_CACHED_USER_INDEX_EMPTY),
        stream_id: next_ss_udp_stream_id(),
        nat_keys: Mutex::new(StreamNatKeys::new()),
        authenticated_user_id: OnceLock::new(),
        pending_resume_request: Mutex::new(resume.requested_resume),
        issued_session_id: resume.issued_session_id,
        nat_scope: OnceCell::new(),
    });
    let mut in_flight: FuturesUnordered<BoxFuture<'static, ()>> = FuturesUnordered::new();
    // Per-carrier downstream-throttle monitor. A direct carrier (`None`) builds
    // it from the route and drives the local detection tick (`Some` only on a
    // padded SS-UDP path with detection enabled — the notice rides a cover
    // datagram only our own padded clients can receive; else `None` keeps the
    // plain wire unchanged). A relayed carrier (`Some`) uses the home monitor
    // the mesh receiver pings from an edge THROTTLE_HINT and runs NO local tick —
    // the home's send counters measure the fast home→mesh hop, not the throttled
    // edge→client last mile.
    let (throttle_monitor, run_local_tick) = match injected_monitor {
        Some(m) => (Some(m), false),
        None => (
            carrier_padding::throttle_params_for_path(&route.path)
                .map(super::throughput_monitor::ThroughputMonitor::new),
            true,
        ),
    };
    // The stream's downlink handle. Every field a response sender carries — the
    // outbound channel, protocol, app protocol, padding scheme and throttle
    // monitor — is fixed for the life of the stream; the only per-datagram part
    // is the `UdpCipherMode`, which the NAT entry stores next to the sender. So
    // build it once here and let each datagram clone the `Arc` instead of
    // allocating a fresh `Arc<dyn ResponseSender>` per packet.
    let response_sender = T::make_udp_response_sender(
        outbound_data_tx.clone(),
        route.protocol,
        AppProtocol::Shadowsocks,
        route.padding,
        throttle_monitor.clone(),
    );
    let writer_task = tokio::spawn(ws_writer::run_ws_writer::<T>(
        writer,
        outbound_ctrl_rx,
        outbound_data_rx,
        server.metrics.clone(),
        Transport::Udp,
        route.protocol,
        AppProtocol::Shadowsocks,
        // Idle cover traffic on the downlink when this path opts into it. Covers
        // SS-UDP-over-WS and SS-UDP-over-XHTTP alike (both ride this writer); a
        // quiet datagram channel still produces random-sized writes. `None` on
        // an unpadded path keeps the plain wire unchanged.
        carrier_padding::cover_for_path(&route.path),
        throttle_monitor.clone(),
    ));
    // Detection tick (direct carriers only). Bounded: aborted when this handle
    // drops at carrier teardown, so it never outlives the carrier.
    let _throttle_tick = run_local_tick
        .then(|| {
            throttle_monitor.clone().map(|m| {
                crate::server::abort::AbortOnDrop::new(tokio::spawn(
                    super::throughput_monitor::run_throttle_tick(m),
                ))
            })
        })
        .flatten();

    // Strip carrier padding from inbound datagrams before SS decryption when
    // this path pads. One WS Binary frame carries exactly one padding frame
    // (the client emits one per packet), so the decoder always lands on a frame
    // boundary; a `real_len = 0` cover frame decodes to nothing and is dropped.
    // Decoding runs here in the relay loop — serially, before the per-datagram
    // relay future is spawned — so the decoder needs no cross-task locking.
    let mut padding_decoder = route.padding.is_enabled().then(PaddingDecoder::new);

    let mut loop_result = Ok(());
    loop {
        // The read is pinned for the whole wait and only ever *polled* by the
        // inner select, never dropped by it. A carrier's `recv` is not required
        // to be cancel-safe, and the mesh SS-UDP one is not: `MeshUdpCarrier`
        // consumes a 4-byte length prefix and then the body, so dropping it
        // part-way would leave the QUIC stream mid-datagram and mis-frame every
        // read after it. (The direct carriers are cancel-safe — axum's and the
        // vendored H3 split reader both keep their partial state in the reader,
        // and the XHTTP duplex consumes nothing until a whole record is ready —
        // but the loop is shared, so it must hold to the stricter contract.)
        // Draining `in_flight` concurrently is still required — a
        // `FuturesUnordered` advances only while polled, so an otherwise idle
        // session would stall its own DNS and sends until the next datagram
        // arrived — and this is how the two coexist.
        let msg = {
            let read = T::recv(&mut reader);
            tokio::pin!(read);
            loop {
                tokio::select! {
                    Some(()) = in_flight.next(), if !in_flight.is_empty() => {},
                    result = &mut read => break result,
                }
            }
        };
        let frame = match msg {
            Ok(Some(m)) => m,
            Ok(None) => break,
            Err(error) => {
                loop_result = Err(error);
                break;
            },
        };
        match T::classify(frame) {
            WsFrame::Binary(data) => {
                // Strip the padding frame (when this path pads) before anything
                // else touches the datagram. A cover frame (real_len = 0)
                // decodes to nothing — drop it and read the next frame. The
                // decoded buffer is the bare SS packet the relay expects.
                let data = match padding_decoder.as_mut() {
                    Some(decoder) => {
                        let mut decoded = Vec::with_capacity(data.len());
                        decoder.push(&data, &mut decoded);
                        if decoded.is_empty() {
                            continue;
                        }
                        Bytes::from(decoded)
                    },
                    None => data,
                };
                server.metrics.record_websocket_binary_frame(
                    Transport::Udp,
                    route.protocol,
                    AppProtocol::Shadowsocks,
                    "up",
                    data.len(),
                );
                // Cluster edge: forward inline instead of fanning out. The edge
                // resolves no DNS and binds no socket — the home does both — so
                // the only awaited work is the mesh write, and doing it in the
                // read loop is what keeps one client packet one mesh datagram
                // (concurrent writers would interleave mid-frame). Backpressure
                // rides the QUIC send window, exactly as the v4 splice's single
                // uplink writer did.
                if let Some(edge) = mesh.as_mut() {
                    let started_at = std::time::Instant::now();
                    match authenticate_udp_datagram(&server, &route, &session, &data) {
                        Ok(Some(packet)) => {
                            if let Err(error) = edge
                                .forward(&server, &route, &packet, &response_sender, started_at)
                                .await
                            {
                                // The mesh is this carrier's only upstream, so a
                                // broken one ends the session: the client redials
                                // and the home still holds the park.
                                loop_result = Err(error);
                                break;
                            }
                        },
                        // Dropped on purpose (a replay, or the replay store full).
                        Ok(None) => {},
                        Err(error) => warn!(?error, "udp datagram relay failed"),
                    }
                    continue;
                }
                if in_flight.len() >= UDP_MAX_CONCURRENT_RELAY_TASKS {
                    server.metrics.record_udp_relay_drop(
                        Transport::Udp,
                        route.protocol,
                        AppProtocol::Shadowsocks,
                        "concurrency_limit",
                    );
                    warn!("udp concurrent relay limit reached, dropping datagram");
                    continue;
                }
                // Reserve a slot against the process-wide cap so that fan-out
                // across WebSocket sessions cannot blow up the total in-flight
                // task count. Drop the datagram with a distinct label when the
                // global ceiling is reached.
                let global_permit = match server
                    .relay_semaphore
                    .as_ref()
                    .map(|sem| Arc::clone(sem).try_acquire_owned())
                {
                    Some(Ok(permit)) => Some(permit),
                    Some(Err(_)) => {
                        server.metrics.record_udp_relay_drop(
                            Transport::Udp,
                            route.protocol,
                            AppProtocol::Shadowsocks,
                            "global_concurrency_limit",
                        );
                        warn!("global udp concurrent relay limit reached, dropping datagram");
                        continue;
                    },
                    None => None,
                };
                let server = Arc::clone(&server);
                let route = Arc::clone(&route);
                let session = Arc::clone(&session);
                let response_sender = response_sender.clone();
                in_flight.push(
                    async move {
                        if let Err(error) = handle_udp_datagram_common(
                            &server,
                            &route,
                            &session,
                            data,
                            response_sender,
                        )
                        .await
                        {
                            warn!(?error, "udp datagram relay failed");
                        }
                        // Hold the permit until the relay future completes so
                        // the semaphore accurately reflects in-flight work;
                        // dropping here releases the slot.
                        drop(global_permit);
                    }
                    .boxed(),
                );
            },
            WsFrame::Close => {
                debug!("client closed udp websocket");
                break;
            },
            WsFrame::Ping(payload) => {
                if outbound_ctrl_tx.send(T::pong_msg(payload)).await.is_err() {
                    loop_result = Err(anyhow!("failed to queue websocket pong"));
                    break;
                }
            },
            WsFrame::Pong => {},
            WsFrame::Text => {
                loop_result = Err(anyhow!("text websocket frames are not supported"));
                break;
            },
        }
    }

    while in_flight.next().await.is_some() {}

    // Cluster edge: end the relay before the writer is drained. The downlink
    // pump holds a clone of the response sender — and with it a clone of the
    // writer's data channel — so it has to be gone before the drops below can
    // close that channel.
    if let Some(edge) = mesh.take() {
        edge.shutdown().await;
    }

    // Release-on-drop: detach our sender from every NAT entry this stream
    // registered on and, when the stream issued a Session ID, park the bundle in
    // the orphan registry. The NAT entries themselves stay alive in `NatTable`
    // and continue aging by their normal idle timeout — only the
    // response-sender slot is released so upstream packets don't try to push to
    // a dead channel.
    release_ss_udp_stream_on_drop(&server, &route, &session).await;

    drop(outbound_ctrl_tx);
    drop(outbound_data_tx);
    // The stream-scoped sender holds its own clone of the data channel, so it
    // must go too — otherwise the writer task never sees the channel close.
    drop(response_sender);
    writer_task.await.context("websocket writer task join failed")??;
    loop_result
}

/// Teardown: detach this stream's response sender from every NAT entry it
/// registered on, then park the detached keys when the stream negotiated
/// resumption.
///
/// The detach is unconditional, because a NAT entry holds a clone of the
/// stream's response sender — and that sender holds a clone of the WS writer's
/// data channel. Leaving it in place keeps `outbound_data_rx` open, so the
/// writer task (and with it the carrier's write half and the client's read half)
/// survives its own stream until the entry is idle-evicted, tens of seconds
/// later. A talkative upstream self-heals on the first send to the departed
/// client, but a silent one — the classic case being DNS over UDP, one reply and
/// then nothing — never triggers that. Streams that cannot park at all
/// (resumption disabled, or a third-party client that offered no
/// `X-Outline-Resume-*` header and so was issued no Session ID) need exactly the
/// same release, which is why it is not gated on the park.
async fn release_ss_udp_stream_on_drop(
    server: &UdpServerCtx,
    route: &UdpRouteCtx,
    session: &UdpSessionState,
) {
    // Whether this stream can park, and under which id/owner. `None` for an
    // unauthenticated stream too — it has nothing to park.
    let park_target = session
        .issued_session_id
        .filter(|_| server.orphan_registry.enabled())
        .zip(session.authenticated_user_id.get().map(Arc::clone));
    // Reserve the id so a racing resume of this SS-UDP stream waits for the park
    // to land rather than missing it (the detach + park below is brief but still
    // concurrent with a redial on another task). The guard clears on every
    // return; the park commits under it.
    let _reservation = park_target
        .as_ref()
        .map(|(session_id, _)| server.orphan_registry.reserve_park(*session_id));
    let nat_keys: HashSet<NatKey> = session.nat_keys.lock().take();
    if nat_keys.is_empty() {
        return;
    }
    let detached_keys = detach_stream_nat_keys(&server.nat_table, session.stream_id, nat_keys);
    let Some((session_id, owner)) = park_target else {
        return;
    };
    if detached_keys.is_empty() {
        return;
    }
    debug!(
        user = %owner,
        path = %route.path,
        keys = detached_keys.len(),
        "parking ss-udp stream into orphan registry"
    );
    server.orphan_registry.park(
        session_id,
        Parked::SsUdpStream(ParkedSsUdpStream { nat_keys: detached_keys, owner }),
    );
}

pub(super) async fn handle_udp_connection(
    socket: WebSocket,
    server: Arc<UdpServerCtx>,
    route: Arc<UdpRouteCtx>,
    resume: ResumeContext,
    upstream: UpstreamSource,
) -> Result<()> {
    // Client-facing carrier either way: no injected monitor, so local throttle
    // detection runs — this node owns the last mile whether the upstream is its
    // own NAT or a home's.
    run_udp_relay::<AxumWs>(AxumWs(socket), server, route, resume, None, upstream).await
}

pub(in crate::server) async fn handle_udp_h3_connection(
    socket: H3WebSocketStream<H3Stream<H3Transport>>,
    server: Arc<UdpServerCtx>,
    route: Arc<UdpRouteCtx>,
    resume: ResumeContext,
    upstream: UpstreamSource,
) -> Result<()> {
    run_udp_relay::<H3Ws>(H3Ws(socket), server, route, resume, None, upstream).await
}

#[cfg(test)]
#[path = "tests/udp.rs"]
mod tests;
