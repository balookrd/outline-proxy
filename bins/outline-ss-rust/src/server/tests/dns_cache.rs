use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use super::super::DnsCache;

/// Distinct one-address entry per index, so a hit identifies which host was
/// stored.
fn entry(i: u32) -> Arc<[SocketAddr]> {
    let octets = i.to_be_bytes();
    let addr = SocketAddr::from((Ipv4Addr::new(10, octets[1], octets[2], octets[3]), 443));
    Arc::from(vec![addr].into_boxed_slice())
}

/// Number of the `0..count` hosts still resolvable — the observable stand-in
/// for `len()` (the core's is `#[cfg(test)]`-private to `outline-net`).
fn live_entries(cache: &DnsCache, count: u32) -> usize {
    (0..count)
        .filter(|i| cache.lookup_all(&format!("h{i}.example"), 443, false).is_some())
        .count()
}

#[test]
fn dns_cache_bounded_evicts_lru_and_never_exceeds_capacity() {
    const CAP: usize = 4;
    const HOSTS: u32 = 32;

    // The host half of the cache key is client-controlled, so the production
    // cache is bounded: a client spraying unique names must not grow the map.
    let cache = DnsCache::with_capacity(std::time::Duration::from_secs(30), CAP);

    for i in 0..HOSTS {
        // Keep h0 the most-recently-used key: with a cap this small the core's
        // eviction sample covers the whole map, so LRU must spare it.
        assert!(
            cache.lookup_all("h0.example", 443, false).is_some() || i == 0,
            "hot key evicted at insert {i}",
        );
        cache.store(&format!("h{i}.example"), 443, false, entry(i));
        assert!(live_entries(&cache, HOSTS) <= CAP, "cache grew past its capacity at insert {i}",);
    }

    assert_eq!(live_entries(&cache, HOSTS), CAP, "cache should stay full, not shrink");
    assert!(
        cache.lookup_all("h0.example", 443, false).is_some(),
        "the hot key must survive a flood of one-shot names",
    );
    // The just-inserted key is the newest, so it is never the eviction victim.
    let last = HOSTS - 1;
    assert_eq!(
        cache.lookup_all(&format!("h{last}.example"), 443, false).as_deref(),
        Some(entry(last).as_ref()),
    );
}

#[test]
fn dns_cache_zero_capacity_stays_unbounded() {
    const HOSTS: u32 = 64;

    // `tuning.dns_cache_max_entries = 0` is the documented opt-out: the cache
    // keeps everything and relies on the periodic stale-grace sweep instead.
    let cache = DnsCache::with_capacity(std::time::Duration::from_secs(30), 0);
    for i in 0..HOSTS {
        cache.store(&format!("h{i}.example"), 443, false, entry(i));
    }

    assert_eq!(live_entries(&cache, HOSTS), HOSTS as usize, "no entry may be evicted");
}

#[test]
fn dns_cache_returns_fresh_entries_and_expires() {
    let cache = DnsCache::new(std::time::Duration::from_millis(5));
    let resolved = SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53));
    let entry: Arc<[SocketAddr]> = Arc::from(vec![resolved].into_boxed_slice());

    cache.store("dns.google", 53, false, entry);
    assert_eq!(cache.lookup_one("dns.google", 53, false), Some(resolved));

    std::thread::sleep(std::time::Duration::from_millis(10));
    assert_eq!(cache.lookup_one("dns.google", 53, false), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dns_cache_singleflight_coalesces_concurrent_misses() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let cache = DnsCache::new(std::time::Duration::from_secs(30));
    let invocations = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(tokio::sync::Barrier::new(16));

    let resolved: Arc<[SocketAddr]> =
        Arc::from(vec![SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 443))].into_boxed_slice());

    let mut handles = Vec::new();
    for _ in 0..16 {
        let cache = Arc::clone(&cache);
        let invocations = Arc::clone(&invocations);
        let barrier = Arc::clone(&barrier);
        let resolved = Arc::clone(&resolved);
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            cache
                .resolve_or_join("slow.example", 443, false, |cache| {
                    let invocations = Arc::clone(&invocations);
                    let resolved = Arc::clone(&resolved);
                    async move {
                        invocations.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        cache.store("slow.example", 443, false, Arc::clone(&resolved));
                        Ok(resolved)
                    }
                })
                .await
                .expect("resolve succeeds")
        }));
    }

    for handle in handles {
        let addrs = handle.await.expect("task joins");
        assert_eq!(addrs.as_ref(), resolved.as_ref());
    }

    assert_eq!(invocations.load(Ordering::SeqCst), 1, "loader must run once");
}

#[tokio::test]
async fn dns_cache_singleflight_propagates_errors() {
    let cache = DnsCache::new(std::time::Duration::from_secs(30));
    let err = cache
        .resolve_or_join(
            "fail.example",
            443,
            false,
            |_| async move { Err(anyhow::anyhow!("boom")) },
        )
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("boom"));

    let resolved: Arc<[SocketAddr]> =
        Arc::from(vec![SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 1))].into_boxed_slice());
    let resolved2 = Arc::clone(&resolved);
    let ok = cache
        .resolve_or_join("fail.example", 443, false, move |_| {
            let resolved2 = Arc::clone(&resolved2);
            async move { Ok(resolved2) }
        })
        .await
        .expect("second call succeeds");
    assert_eq!(ok.as_ref(), resolved.as_ref());
}
