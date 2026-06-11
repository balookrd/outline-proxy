use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use super::super::DnsCache;

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
