use std::time::Duration;

use metrics::{describe_counter, describe_gauge, describe_histogram};
use metrics_exporter_prometheus::{
    Matcher, PrometheusBuilder, PrometheusHandle, PrometheusRecorder,
};
use metrics_util::MetricKindMask;

const TCP_CONNECT_BUCKETS: &[f64] =
    &[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0];
const UDP_RELAY_BUCKETS: &[f64] = &[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0];
const WS_SESSION_BUCKETS: &[f64] = &[1.0, 5.0, 15.0, 60.0, 300.0, 900.0, 3600.0, 14400.0];
// Power-of-two ladder from 256 B to 64 KiB. The hot regime for diagnosing
// throughput issues is the 1–16 KiB band: a healthy bulk-relay session
// concentrates near the upper end (LEGACY_MAX_CHUNK_SIZE = 16383), while a
// non-batched relay smears down toward TCP-segment size (~1.4 KiB).
const WS_FRAME_SIZE_BUCKETS: &[f64] =
    &[256.0, 512.0, 1024.0, 2048.0, 4096.0, 8192.0, 16384.0, 32768.0, 65536.0];
// `tuning.ws_data_channel_capacity` defaults to 128 (LARGE) and may be
// raised to 256/512 in pathological deployments. Buckets cover the
// full 0..max range with finer granularity near the saturation tail —
// that is where backpressure-induced stalls become visible.
const WS_DATA_CHANNEL_FILL_BUCKETS: &[f64] =
    &[0.0, 8.0, 32.0, 64.0, 96.0, 120.0, 128.0, 192.0, 256.0, 384.0, 512.0];

pub(super) fn build_recorder(idle_timeout: Duration) -> (PrometheusRecorder, PrometheusHandle) {
    let recorder = PrometheusBuilder::new()
        .set_buckets_for_metric(
            Matcher::Full("outline_ss_tcp_upstream_connect_duration_seconds".into()),
            TCP_CONNECT_BUCKETS,
        )
        .expect("invalid TCP connect bucket config")
        .set_buckets_for_metric(
            Matcher::Full("outline_ss_udp_relay_duration_seconds".into()),
            UDP_RELAY_BUCKETS,
        )
        .expect("invalid UDP relay bucket config")
        .set_buckets_for_metric(
            Matcher::Full("outline_ss_websocket_session_duration_seconds".into()),
            WS_SESSION_BUCKETS,
        )
        .expect("invalid WebSocket session bucket config")
        .set_buckets_for_metric(
            Matcher::Full("outline_ss_websocket_frame_size_bytes".into()),
            WS_FRAME_SIZE_BUCKETS,
        )
        .expect("invalid WebSocket frame size bucket config")
        .set_buckets_for_metric(
            Matcher::Full("outline_ss_websocket_data_channel_fill".into()),
            WS_DATA_CHANNEL_FILL_BUCKETS,
        )
        .expect("invalid WS data channel fill bucket config")
        // Only evict idle histograms. Counters in Prometheus are monotonic
        // by contract: evicting and re-creating one between scrapes appears
        // to PromQL as a `rate()` reset, dropping every accumulated value.
        // The previous `MetricKindMask::ALL` setting made per-user payload
        // counters disappear after `idle_timeout` of inactivity even though
        // the underlying traffic was being relayed (and ws-side counters,
        // which are not user-keyed, kept reflecting it) — burst users would
        // lose `target_to_client` series entirely while sustained-traffic
        // users kept theirs. Histograms keep idle eviction because their
        // per-bucket storage actually does compound the cardinality cost.
        .idle_timeout(MetricKindMask::HISTOGRAM, Some(idle_timeout))
        .build_recorder();
    let handle = recorder.handle();
    (recorder, handle)
}

pub(super) fn register_descriptions() {
    describe_gauge!("outline_ss_build_info", "Build metadata for the running binary.");
    describe_gauge!(
        "outline_ss_config_info",
        "Static server configuration flags exposed as labels."
    );
    describe_gauge!("outline_ss_uptime_seconds", "Seconds since the process started.");
    describe_counter!(
        "outline_ss_metrics_scrapes_total",
        "Number of successful Prometheus scrapes."
    );
    describe_counter!("outline_ss_websocket_upgrades_total", "Total accepted websocket upgrades.");
    describe_counter!(
        "outline_ss_websocket_disconnects_total",
        "Websocket session completions grouped by outcome."
    );
    describe_gauge!("outline_ss_active_websocket_sessions", "Currently active websocket sessions.");
    describe_histogram!(
        "outline_ss_websocket_session_duration_seconds",
        "Wall-clock websocket session duration."
    );
    describe_counter!("outline_ss_websocket_frames_total", "Binary websocket frames transferred.");
    describe_counter!(
        "outline_ss_websocket_bytes_total",
        "Encrypted websocket payload bytes transferred."
    );
    describe_histogram!(
        "outline_ss_websocket_frame_size_bytes",
        "Distribution of binary websocket frame payload sizes by app_protocol/direction."
    );
    describe_counter!(
        "outline_ss_websocket_pong_deadline_total",
        "Sessions torn down by the server because no inbound frame arrived within the pong deadline."
    );
    describe_histogram!(
        "outline_ss_websocket_data_channel_fill",
        "Depth of the upstream→ws-writer mpsc channel sampled at every push, by app_protocol/transport."
    );
    describe_counter!(
        "outline_ss_client_sessions_total",
        "Authenticated client sessions by user, transport and protocol."
    );
    describe_gauge!(
        "outline_ss_client_last_seen_seconds",
        "Unix timestamp of the most recent successful client activity by user."
    );
    describe_gauge!(
        "outline_ss_client_active",
        "Client active state by user using the configured TTL."
    );
    describe_gauge!(
        "outline_ss_client_up",
        "Alias of outline_ss_client_active for online-state dashboards."
    );
    describe_counter!(
        "outline_ss_tcp_authenticated_sessions_total",
        "Authenticated TCP relay sessions by user and client protocol."
    );
    describe_counter!(
        "outline_ss_tcp_upstream_connects_total",
        "TCP upstream connect attempts by result."
    );
    describe_gauge!(
        "outline_ss_active_tcp_upstream_connections",
        "Currently active outbound TCP connections."
    );
    describe_histogram!(
        "outline_ss_tcp_upstream_connect_duration_seconds",
        "TCP upstream connect latency."
    );
    describe_counter!(
        "outline_ss_tcp_payload_bytes_total",
        "Plain TCP payload bytes relayed after Shadowsocks decryption."
    );
    describe_counter!(
        "outline_ss_tcp_aead_overhead_bytes_total",
        "AEAD framing overhead (response salt + per-chunk length frame + tag) \
         emitted alongside each plaintext chunk in the upstream→client direction. \
         payload + overhead reconciles with outline_ss_websocket_bytes_total \
         {transport=\"tcp\",direction=\"down\"} for the same labels."
    );
    describe_counter!("outline_ss_udp_requests_total", "UDP relay requests by result.");
    describe_histogram!(
        "outline_ss_udp_relay_duration_seconds",
        "End-to-end UDP request handling duration."
    );
    describe_counter!(
        "outline_ss_udp_payload_bytes_total",
        "Plain UDP payload bytes relayed after Shadowsocks decryption."
    );
    describe_counter!(
        "outline_ss_udp_response_datagrams_total",
        "UDP response datagrams sent back to the client."
    );
    describe_counter!(
        "outline_ss_udp_relay_drops_total",
        "UDP datagrams dropped before relay because of transport backpressure, concurrency limits, \
         or an identity the carrier never attested to its cluster home."
    );
    describe_counter!(
        "outline_ss_udp_oversized_datagrams_dropped_total",
        "UDP datagrams dropped because they exceeded the maximum payload size supported by the transport path."
    );
    describe_counter!(
        "outline_ss_udp_replay_dropped_total",
        "UDP datagrams dropped by the SS-2022 anti-replay window (a repeated or \
         out-of-window sequence number). Shadowsocks-only."
    );
    describe_counter!(
        "outline_ss_udp_replay_store_full_dropped_total",
        "UDP datagrams dropped because the SS-2022 anti-replay store was at capacity \
         and could not admit a new sequence number. Shadowsocks-only."
    );
    describe_counter!(
        "outline_ss_xhttp_sessions_rejected_total",
        "XHTTP session-creating requests rejected before a registry entry or relay task \
         was allocated, because a process-wide cap was reached (reason=\"max_sessions\" or \
         \"max_relay_tasks\"). Bounds the pre-auth session/task footprint."
    );
    describe_gauge!(
        "outline_ss_udp_nat_active_entries",
        "Current number of active UDP NAT table entries."
    );
    describe_counter!(
        "outline_ss_udp_nat_entries_created_total",
        "Total UDP NAT table entries ever created."
    );
    describe_counter!(
        "outline_ss_udp_nat_entries_evicted_total",
        "Total UDP NAT table entries evicted due to idle timeout."
    );
    describe_counter!(
        "outline_ss_udp_nat_responses_dropped_total",
        "UDP upstream responses dropped because no WebSocket session was registered."
    );
    describe_counter!(
        "outline_ss_udp_nat_capacity_dropped_total",
        "UDP datagrams to new targets dropped because the NAT table was at \
         udp_nat_max_entries capacity, or the user was at its \
         udp_nat_max_entries_per_user share."
    );
    describe_counter!(
        "outline_ss_maintenance_task_panics_total",
        "Background maintenance tasks that panicked and triggered a graceful \
         shutdown. Only reachable under panic=unwind (debug/test); the release \
         profile uses panic=abort, where such a panic aborts the process."
    );
    describe_counter!(
        "outline_ss_orphan_park_total",
        "Sessions moved into the cross-transport resumption orphan registry, by kind."
    );
    describe_counter!(
        "outline_ss_orphan_resume_hit_total",
        "Successful cross-transport session resumes, by parked-payload kind."
    );
    describe_counter!(
        "outline_ss_orphan_resume_cross_protocol_total",
        "Resume hits where the parked session and the carrier that claimed it \
         were authenticated under different proxy protocols, by parked and \
         resumed protocol. A subset of outline_ss_orphan_resume_hit_total, \
         counted on the node that owns the park (so a relayed crossing lands on \
         the home). Expected to be non-zero wherever a client rotates its active \
         wire across a set mixing SS and VLESS wires; both legs are the same \
         account, which the owner check enforces."
    );
    describe_counter!(
        "outline_ss_orphan_resume_miss_total",
        "Failed cross-transport session resumes, by reason."
    );
    describe_counter!(
        "outline_ss_orphan_evicted_total",
        "Orphan entries evicted before being resumed, by kind and reason."
    );
    describe_gauge!(
        "outline_ss_orphan_current",
        "Currently parked orphan sessions awaiting cross-transport resumption, by kind."
    );
    describe_counter!(
        "outline_ss_mesh_relay_opened_total",
        "Edge attempts to open a cluster mesh relay to a home shard, by outcome \
         (ok = the relay was established and the home acked it; fail = the edge \
         never got its OPEN to a home — no peer configured for that shard, the \
         dial failed, or this edge is at its own outbound relay-stream cap; \
         refused = the OPEN reached a home that answered nothing usable. The \
         ordinary case behind refused is a home holding no park under the relayed \
         resume id (an expired or never-parked session); the same value also \
         covers a home at its inbound relayed-session cap and a peer on a wire \
         version this cluster has moved past, both of which reset the stream \
         before any ack — so version skew during a rolling upgrade shows up here, \
         not on fail. All non-ok outcomes degrade to a fresh local session)."
    );
    describe_counter!(
        "outline_ss_mesh_relay_rejected_total",
        "Relay streams a home node refused before serving them, by reason \
         (capacity = already at its concurrent relayed-session cap; \
         no_session = no park exists \
         under the relayed resume id, or it expired between the two setup phases; \
         unknown_user = a park exists but is owned by a different user name than \
         the edge attested — user names may disagree across the cluster, it may \
         be a genuine security event, or the user may have [users.aliases] and be \
         connecting from a matching subnet (an SS-TCP park is keyed on the base \
         id while the attestation uses the effective label, so that case \
         mismatches with nothing wrong in the config); \
         park_shape = a park exists under that id but is not a shape this relay \
         could splice — an SS-UDP park asked for under a VLESS resume id, or a \
         byte-stream park asked for with datagram framing and the other way \
         round — an ordinary outcome, and refused without consuming the park, on \
         either of the two probes that bracket the setup (distinct from \
         no_session, which means nothing is there at all); \
         protocol_mismatch = a datagram or mux park was claimed under the other \
         proxy protocol (SS vs VLESS). Those parks hold framing state the other \
         protocol cannot express — a mux sub-connection map, a half-decoded \
         length-prefixed frame, NAT responder slots — unlike a byte-stream park, \
         which crosses freely and is counted on \
         outline_ss_orphan_resume_cross_protocol_total instead. Not reachable \
         through the shape probe, so a non-zero value means a forged peer or the \
         reservation window; park_identity = an SS-UDP park holds no NAT key belonging to the \
         user the edge attested, so there is no identity to route its datagrams \
         under; park_incomplete = a VLESS-mux park holds no sub-connection left \
         to re-attach, so the bundle is refused whole rather than half-spliced; \
         framing_mismatch = the park under that id is not the kind the \
         acked shape needs, which only the reservation window can still produce — \
         the park is put back untouched, so the client keeps its continuity; \
         bad_setup = the setup itself was unusable — an OPEN whose framing and \
         protocol name no park shape, or an acked peer whose second-phase USER \
         frame was malformed or never arrived. The edge \
         degrades to a fresh local session)."
    );
    describe_counter!(
        "outline_ss_mesh_relay_outcome_total",
        "Relayed sessions a home node resolved, by outcome (hit = the parked \
         session was found and spliced onto the relay; miss = no park matched — \
         nothing under that id, or one this relay refused without consuming, so \
         it is still there — and the edge serves its client a fresh local \
         session; unusable = a park matched and was consumed but could not be \
         spliced at all (an SS-UDP park holding no NAT key of the attested user, \
         a VLESS-mux bundle holding no sub-connection), so it is destroyed and \
         the client's session is over; error = setup failed \
         before any park could be resolved) and by close (client_done = the edge \
         said its client is finished, so the upstream was half-closed instead of \
         re-parked; carrier_ended = the edge only switched carriers, so the \
         session went back into the registry; none = no splice ran, or it failed \
         before any close). A hit is recorded when its splice ends, which is when \
         the close is known — use outline_ss_mesh_relay_active for relays still \
         running. Every v5 relay stream that reaches the v5 handler records \
         exactly one outcome when it ends, so the served total is \
         sum(outcome_total) + outline_ss_mesh_relay_active — the direct signal \
         that cluster relaying works, which \
         byte counters alone never gave, while the client_done/carrier_ended \
         ratio shows whether edges emit the close intent at all. Streams refused \
         before the handler ever runs record none — see the capacity reason on \
         outline_ss_mesh_relay_rejected_total."
    );
    describe_gauge!(
        "outline_ss_mesh_relay_active",
        "Relayed sessions this home node is currently serving over the cluster mesh."
    );
    describe_counter!(
        "outline_ss_mesh_bytes_total",
        "Plaintext application bytes moved over the cluster mesh, by role \
         (edge = this node forwarding a client to a foreign home; home = this node \
         serving a relay for a foreign edge), direction (up = toward home/target, \
         down = toward client) and transport. Edge and home count the same relayed \
         session from opposite ends: a node's edge series is the traffic it sends \
         into the cluster, its home series the traffic it receives from other edges."
    );
    describe_counter!(
        "outline_ss_mesh_datagrams_total",
        "Datagrams moved over the cluster mesh, by role and direction — both the \
         SS-UDP and the single-target VLESS-UDP relays feed it, one increment per \
         datagram on each hop. Pairs with the transport=\"udp\" slice of \
         outline_ss_mesh_bytes_total to give the mean relayed datagram size."
    );
    describe_counter!(
        "outline_ss_orphan_downlink_replay_bytes_total",
        "Plaintext bytes replayed to resuming clients via the v2 Symmetric \
         Downlink Replay protocol (`ORDR` frame payload), by transport."
    );
    describe_counter!(
        "outline_ss_orphan_downlink_replay_truncated_total",
        "Resume hits where the v2 downlink replay frame carried REPLAY_TRUNCATED \
         — the requested offset preceded the ring's oldest retained byte, \
         the parked ring was absent, or the client claimed bytes the server \
         never emitted. By transport."
    );
    describe_gauge!(
        "outline_ss_orphan_downlink_buf_bytes",
        "Sum of bytes currently retained in v2 Symmetric Downlink Replay \
         ring buffers across parked TCP orphan sessions."
    );
    describe_counter!(
        "outline_ss_tls_handshake_failed_total",
        "TLS handshake failures on the TCP listener grouped by classified reason."
    );
    describe_counter!(
        "outline_ss_sni_peek_failed_total",
        "Inbound streams the [sni_fallback] ClientHello peek gave up on, by reason. \
         peer_closed is routine (TCP liveness probes, scanners, aborted clients) and is \
         logged only at debug; malformed / oversized / read_failed stay at warn."
    );
    describe_counter!(
        "outline_ss_tls_handshake_no_cert_chain_total",
        "Subset of TLS handshake failures where the cert resolver returned None, broken down by the rejected SNI. \
         Special label values: <none> (no SNI sent), <invalid> (non-ASCII/control bytes), <long> (>253 chars), \
         <overflow> (cardinality cap reached)."
    );
}
