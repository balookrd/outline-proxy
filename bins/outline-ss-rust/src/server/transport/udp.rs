use std::collections::HashSet;
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};

use anyhow::{Context, Result, anyhow};
use axum::extract::ws::WebSocket;
use bytes::Bytes;
use futures_util::{FutureExt, StreamExt, future::BoxFuture, stream::FuturesUnordered};
use outline_wire::padding::{PaddingDecoder, PaddingScheme};
use parking_lot::Mutex;
use tokio::sync::{OnceCell, Semaphore, mpsc};
use tracing::{debug, info, warn};

use super::carrier_padding;
use crate::server::h3::vendored::{H3Stream, H3Transport, H3WebSocketStream};
use crate::{
    crypto::{
        CryptoError, SessionKeyCache, UserKey, decrypt_udp_packet_with_hint, diagnose_udp_packet,
    },
    metrics::{AppProtocol, Metrics, Protocol, Transport},
    protocol::parse_target_addr,
    server::nat::{
        NatKey, NatScope, NatTable, ServerSessionId, UdpResponseCoding, UdpResponseSender,
    },
    server::replay::{self, ReplayCheck, ReplayStore},
};

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

/// Relays one inbound SS-UDP datagram. `response_sender` is the stream's
/// downlink handle (see [`run_udp_relay`]): a clone of one `Arc` shared by every
/// datagram of the stream, re-registered on the NAT entry alongside this
/// datagram's `UdpCipherMode`.
async fn handle_udp_datagram_common(
    server: &UdpServerCtx,
    route: &UdpRouteCtx,
    session: &UdpSessionState,
    data: Bytes,
    response_sender: UdpResponseSender,
) -> Result<()> {
    let started_at = std::time::Instant::now();
    let preferred_user_index = match session.cached_user_index.load(Ordering::Relaxed) {
        UDP_CACHED_USER_INDEX_EMPTY => None,
        index => Some(index),
    };
    let (packet, user_index) = match decrypt_udp_packet_with_hint(
        route.users.as_ref(),
        &data,
        preferred_user_index,
        Some(server.session_key_cache.as_ref()),
    ) {
        Ok(result) => result,
        Err(CryptoError::UnknownUser) => {
            debug!(
                path = %route.path,
                candidates = ?route.candidate_users,
                attempts = ?diagnose_udp_packet(route.users.as_ref(), &data),
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
                return Ok(());
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
                return Ok(());
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
        server.metrics.record_udp_request(
            Arc::clone(&ctx.user_id),
            ctx.protocol,
            AppProtocol::Shadowsocks,
            "error",
            ctx.started_at.elapsed().as_secs_f64(),
        );
        return Ok(());
    }
    entry
        .user_counters()
        .udp_in(AppProtocol::Shadowsocks, ctx.protocol)
        .increment(payload.len() as u64);
    if let Err(error) = entry.socket().send_to(payload, resolved).await {
        server.metrics.record_udp_request(
            Arc::clone(&ctx.user_id),
            ctx.protocol,
            AppProtocol::Shadowsocks,
            "error",
            ctx.started_at.elapsed().as_secs_f64(),
        );
        return Err(error).with_context(|| format!("failed to send UDP datagram to {resolved}"));
    }
    entry.touch();
    server.metrics.record_udp_request(
        Arc::clone(&ctx.user_id),
        ctx.protocol,
        AppProtocol::Shadowsocks,
        "success",
        ctx.started_at.elapsed().as_secs_f64(),
    );

    Ok(())
}

pub(in crate::server::transport) async fn run_udp_relay<T: WsSocket>(
    socket: T,
    server: Arc<UdpServerCtx>,
    route: Arc<UdpRouteCtx>,
    resume: ResumeContext,
    injected_monitor: Option<Arc<super::throughput_monitor::ThroughputMonitor>>,
) -> Result<()> {
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
        tokio::select! {
            Some(()) = in_flight.next(), if !in_flight.is_empty() => {}
            msg = T::recv(&mut reader) => {
                let frame = match msg {
                    Ok(Some(m)) => m,
                    Ok(None) => break,
                    Err(error) => {
                        loop_result = Err(error);
                        break;
                    }
                };
                match T::classify(frame) {
                    WsFrame::Binary(data) => {
                        // Strip the padding frame (when this path pads) before
                        // anything else touches the datagram. A cover frame
                        // (real_len = 0) decodes to nothing — drop it and read
                        // the next frame. The decoded buffer is the bare SS
                        // packet the relay expects.
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
                        // Reserve a slot against the process-wide cap so that
                        // fan-out across WebSocket sessions cannot blow up the
                        // total in-flight task count. Drop the datagram with a
                        // distinct label when the global ceiling is reached.
                        let global_permit = match server.relay_semaphore
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
                                warn!(
                                    "global udp concurrent relay limit reached, dropping datagram"
                                );
                                continue;
                            }
                            None => None,
                        };
                        let server = Arc::clone(&server);
                        let route = Arc::clone(&route);
                        let session = Arc::clone(&session);
                        let response_sender = response_sender.clone();
                        in_flight.push(async move {
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
                            // Hold the permit until the relay future completes
                            // so the semaphore accurately reflects in-flight
                            // work; dropping here releases the slot.
                            drop(global_permit);
                        }.boxed());
                    }
                    WsFrame::Close => {
                        debug!("client closed udp websocket");
                        break;
                    }
                    WsFrame::Ping(payload) => {
                        if outbound_ctrl_tx
                            .send(T::pong_msg(payload))
                            .await
                            .is_err()
                        {
                            loop_result = Err(anyhow!("failed to queue websocket pong"));
                            break;
                        }
                    }
                    WsFrame::Pong => {}
                    WsFrame::Text => {
                        loop_result = Err(anyhow!("text websocket frames are not supported"));
                        break;
                    }
                }
            }
        }
    }

    while in_flight.next().await.is_some() {}

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
) -> Result<()> {
    // Direct carrier: no injected monitor — local detection runs (`None`).
    run_udp_relay::<AxumWs>(AxumWs(socket), server, route, resume, None).await
}

pub(in crate::server) async fn handle_udp_h3_connection(
    socket: H3WebSocketStream<H3Stream<H3Transport>>,
    server: Arc<UdpServerCtx>,
    route: Arc<UdpRouteCtx>,
    resume: ResumeContext,
) -> Result<()> {
    run_udp_relay::<H3Ws>(H3Ws(socket), server, route, resume, None).await
}

#[cfg(test)]
#[path = "tests/udp.rs"]
mod tests;
