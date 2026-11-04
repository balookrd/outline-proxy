//! Path MTU cache for H3 dials.
//!
//! DPLPMTUD with no prior knowledge probes a fixed ladder of sizes after every
//! handshake (1326, 1389, 1420, ...), identical on every connection and visible
//! to a passive observer. The cache remembers the MTU a path settled at, keyed
//! by server, port, fwmark and a hash of the local source address (a stand-in
//! for "which network we are on"), and the next dial probes that size first
//! (`MtuDiscoveryConfig::first_probe`): one probe when the path is unchanged.
//!
//! A live entry is a capping first probe; an expired one (younger than
//! `PMTU_SEED_MAX_AGE`) is a seed that searches on above itself, so the periodic
//! re-check of an entry finds an unchanged or grown path without the ladder (a
//! path that shrank costs one rejected size and a search below it).
//!
//! The cached value is never used as the starting MTU: a stale entry costs one
//! rejected probe size, never lost data.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};

use parking_lot::Mutex;
use tracing::{debug, warn};

use super::vendored::FirstProbe;

/// An entry at the H3 upper bound expires this long after the path first
/// settled at it, so a changed path is re-checked by a seeded search.
const PMTU_CACHE_TTL: Duration = Duration::from_secs(3 * 24 * 3600);
/// TTL for a value below the H3 upper bound. A spurious probe loss can make a
/// search settle low (1417 on a 1452 path); the next dial confirms that value
/// as its first probe and it becomes the connection's ceiling, so a low value
/// is re-checked by a seeded search after this long instead of after days.
const PMTU_CACHE_SHORT_TTL: Duration = Duration::from_secs(3600);
/// An expired entry younger than this still seeds the next dial's search
/// (`FirstProbe::seed`): on an unchanged or grown path that replaces the ladder,
/// with no ceiling, so a path that grew or shrank is still found. Older entries (a network
/// not seen for a month) give no hint at all.
const PMTU_SEED_MAX_AGE: Duration = Duration::from_secs(30 * 24 * 3600);
/// QUIC floor and the H3 upper bound: anything else is not a value we probe.
const MIN_PMTU: u16 = 1200;
const MAX_PMTU: u16 = 1452;
/// Bound on entries; the oldest confirmation is evicted first.
const MAX_ENTRIES: usize = 256;
/// How often the recorder looks at a connection's path state.
const RECORD_INTERVAL: Duration = Duration::from_secs(10);

static CACHE: OnceLock<Arc<PmtuCache>> = OnceLock::new();

/// Initialise the path MTU cache once; `path` persists it across restarts,
/// `None` keeps it in memory only.
///
/// Must be called before the first H3 dial: a dial that gets there first
/// creates an in-memory cache through `cache()`, and a later call is a no-op.
pub fn init_pmtu_cache(path: Option<PathBuf>) {
    CACHE.get_or_init(|| Arc::new(PmtuCache::new(path, PMTU_CACHE_TTL)));
}

fn cache() -> &'static Arc<PmtuCache> {
    CACHE.get_or_init(|| Arc::new(PmtuCache::new(None, PMTU_CACHE_TTL)))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PmtuKey {
    pub(crate) server: String,
    pub(crate) port: u16,
    pub(crate) fwmark: Option<u32>,
    pub(crate) net: u64,
}

impl PmtuKey {
    /// Key for a dial to `server_addr`; the network part is the hash of the
    /// local address the kernel would pick for it (0 if it cannot tell).
    pub(crate) fn for_dial(
        server_name: &str,
        server_addr: SocketAddr,
        fwmark: Option<u32>,
    ) -> Self {
        let net = local_source_ip(server_addr, fwmark).map(network_hash).unwrap_or(0);
        Self {
            server: server_name.to_owned(),
            port: server_addr.port(),
            fwmark,
            net,
        }
    }

    pub(crate) fn as_str(&self) -> String {
        let fw = self.fwmark.map_or_else(|| "-".to_owned(), |m| m.to_string());
        format!("{}:{}|fw={fw}|net={:016x}", self.server, self.port, self.net)
    }
}

/// Source address the kernel picks for `server_addr` under `fwmark`, found by
/// connecting a throwaway UDP socket: `connect` on UDP only consults the
/// routing table and sends nothing.
fn local_source_ip(server_addr: SocketAddr, fwmark: Option<u32>) -> Option<IpAddr> {
    let socket = crate::bind_udp_socket(crate::bind_addr_for(server_addr), fwmark).ok()?;
    socket.connect(server_addr).ok()?;
    socket.local_addr().ok().map(|addr| addr.ip())
}

/// FNV-1a over the address octets: stable across builds, unlike `DefaultHasher`.
pub(crate) fn network_hash(ip: IpAddr) -> u64 {
    let octets: Vec<u8> = match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    };
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in octets {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

#[derive(Clone, Copy)]
struct Entry {
    mtu: u16,
    confirmed_at: u64,
}

pub(crate) struct PmtuCache {
    path: Option<PathBuf>,
    ttl: Duration,
    entries: Mutex<HashMap<String, Entry>>,
    /// Held across write + rename so concurrent flushes cannot interleave on
    /// the shared `.tmp` file.
    flush_lock: Mutex<()>,
}

fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

impl PmtuCache {
    pub(crate) fn new(path: Option<PathBuf>, ttl: Duration) -> Self {
        let entries = path.as_deref().map(load).unwrap_or_default();
        Self {
            path,
            ttl,
            entries: Mutex::new(entries),
            flush_lock: Mutex::new(()),
        }
    }

    /// Lifetime of a stored `mtu`: the long TTL only for the H3 upper bound,
    /// the short one for anything below it (never longer than the long TTL).
    fn ttl_for(&self, mtu: u16) -> Duration {
        if mtu >= MAX_PMTU {
            self.ttl
        } else {
            self.ttl.min(PMTU_CACHE_SHORT_TTL)
        }
    }

    /// Live means confirmed within its TTL; an entry confirmed "in the
    /// future" (the clock went back since) is not trusted until the clock
    /// catches up, so a stale cap cannot outlive its TTL that way.
    fn is_live(&self, entry: &Entry, now_secs: u64) -> bool {
        entry.confirmed_at <= now_secs
            && now_secs < entry.confirmed_at.saturating_add(self.ttl_for(entry.mtu).as_secs())
    }

    /// First probe for `key`: a live entry caps the connection at its value, an
    /// expired one younger than `PMTU_SEED_MAX_AGE` only seeds the search.
    pub(crate) fn hint(&self, key: &str, now: SystemTime) -> Option<FirstProbe> {
        let entry = *self.entries.lock().get(key)?;
        let now_secs = unix_secs(now);
        if self.is_live(&entry, now_secs) {
            Some(FirstProbe::capped(entry.mtu))
        } else if entry.confirmed_at <= now_secs
            && now_secs < entry.confirmed_at.saturating_add(PMTU_SEED_MAX_AGE.as_secs())
        {
            Some(FirstProbe::seed(entry.mtu))
        } else {
            None
        }
    }

    /// Store `mtu` for `key`; returns whether the stored value changed (and the
    /// file needs a flush). The same value keeps its original `confirmed_at`.
    pub(crate) fn record(&self, key: &str, mtu: u16, now: SystemTime) -> bool {
        if !(MIN_PMTU..=MAX_PMTU).contains(&mtu) {
            return false;
        }
        let now_secs = unix_secs(now);
        let mut entries = self.entries.lock();
        let live = entries.get(key).filter(|e| self.is_live(e, now_secs));
        if live.is_some_and(|e| e.mtu == mtu) {
            return false;
        }
        entries.insert(key.to_owned(), Entry { mtu, confirmed_at: now_secs });
        if entries.len() > MAX_ENTRIES
            && let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, e)| e.confirmed_at)
                .map(|(k, _)| k.clone())
        {
            entries.remove(&oldest);
        }
        true
    }

    /// Write the cache atomically (sibling `.tmp`, then rename). No-op in memory.
    pub(crate) fn flush(&self) -> std::io::Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        let _flush = self.flush_lock.lock();
        let mut text = String::new();
        for (key, entry) in self.entries.lock().iter() {
            text.push_str(&format!("{key}\t{}\t{}\n", entry.mtu, entry.confirmed_at));
        }
        let tmp = path.with_extension("tmp");
        write_private(&tmp, &text)?;
        std::fs::rename(&tmp, path)
    }
}

/// Create the file with owner-only permissions, like the neighbouring state file.
fn write_private(path: &std::path::Path, text: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)?.write_all(text.as_bytes())
}

fn load(path: &std::path::Path) -> HashMap<String, Entry> {
    let Ok(text) = std::fs::read_to_string(path) else { return HashMap::new() };
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split('\t');
            let key = fields.next()?;
            let mtu = fields.next()?.parse::<u16>().ok()?;
            let confirmed_at = fields.next()?.parse::<u64>().ok()?;
            (MIN_PMTU..=MAX_PMTU)
                .contains(&mtu)
                .then(|| (key.to_owned(), Entry { mtu, confirmed_at }))
        })
        .collect()
}

/// First probe for a dial on `key`: capping if the path has a live cached MTU,
/// a seed if the entry has expired but is younger than `PMTU_SEED_MAX_AGE`,
/// `None` otherwise.
pub(crate) fn first_probe_for(key: &PmtuKey) -> Option<FirstProbe> {
    cache().hint(&key.as_str(), SystemTime::now())
}

/// Whether a settled `settled_mtu` is worth storing for a dial that used
/// `first_probe`. A connection that settled exactly at its confirmed capping
/// first probe only proves that size works: that probe is its ceiling, so it
/// says nothing about larger sizes and must not refresh the entry (otherwise a
/// low value would never be re-checked while such a carrier lives). A seed
/// searched above itself, so wherever it settled is a real observation, as is a
/// full search (no hint) or a result different from the hint.
pub(crate) fn should_record(first_probe: Option<FirstProbe>, settled_mtu: u16) -> bool {
    !first_probe.is_some_and(|p| p.caps && p.size == settled_mtu)
}

/// Watch `connection` and store the MTU its path settles at under `key`.
/// Skips samples taken mid-search, connections that saw a black hole and
/// connections that settled at their own capping `first_probe` (see `should_record`).
///
/// Probe dials (no cache key, carrier dropped right after the probe) usually
/// abort the recorder before it samples, so they rarely contribute.
///
/// The task holds a strong `quinn::Connection`, so the caller keeps the
/// returned handle in the carrier and dropping the carrier aborts it. A
/// connection that closes while its carrier is alive (peer close, idle timeout)
/// still gets a final sample; one closed by dropping the carrier does not, as
/// the abort lands before the task runs again. That loses at most the last
/// `RECORD_INTERVAL` of a path that settles within seconds of the handshake.
#[must_use = "dropping the handle aborts the recorder"]
pub(crate) fn spawn_recorder(
    connection: quinn::Connection,
    key: PmtuKey,
    first_probe: Option<FirstProbe>,
) -> crate::AbortOnDrop {
    crate::AbortOnDrop::new(tokio::spawn(async move {
        let key = key.as_str();
        loop {
            let closed = tokio::select! {
                _ = connection.closed() => true,
                () = tokio::time::sleep(RECORD_INTERVAL) => false,
            };
            let path = connection.stats().path;
            if super::vendored::path_mtu_settled(&path)
                && path.black_holes_detected == 0
                && should_record(first_probe, path.current_mtu)
                && cache().record(&key, path.current_mtu, SystemTime::now())
            {
                debug!(key = %key, mtu = path.current_mtu, "path MTU cached");
                let cache = Arc::clone(cache());
                if let Err(error) = tokio::task::spawn_blocking(move || cache.flush())
                    .await
                    .unwrap_or_else(|e| Err(std::io::Error::other(e)))
                {
                    warn!(error = %error, "failed to persist path MTU cache");
                }
            }
            if closed {
                return;
            }
        }
    }))
}

#[cfg(test)]
#[path = "tests/pmtu_cache.rs"]
mod tests;
