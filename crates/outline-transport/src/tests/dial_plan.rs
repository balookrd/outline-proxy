use std::net::TcpListener;

use url::Url;

use super::*;
use crate::dns_cache::{DEFAULT_DNS_CACHE_TTL, DnsCache};

#[tokio::test]
async fn h2_l4_connect_error_skips_h1_and_tags_endpoint_unreachable() {
    // Bind and immediately drop a local TCP listener to get an unused closed port.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);

    let cache = DnsCache::new(DEFAULT_DNS_CACHE_TTL);
    let url = Url::parse(&format!("wss://127.0.0.1:{port}/ws")).expect("valid url");
    let opts = TransportDialOptions::new(&cache, &url, TransportMode::WsH2, "test");

    let start = std::time::Instant::now();
    let err = connect_transport(opts).await.err().expect("closed port must fail");
    let elapsed = start.elapsed();

    assert!(
        crate::find_typed::<crate::L4ConnectError>(&err).is_some(),
        "expected L4ConnectError in error chain, got: {err:#}"
    );
    assert!(
        crate::find_typed::<crate::EndpointUnreachable>(&err).is_some(),
        "expected EndpointUnreachable in error chain, got: {err:#}"
    );
    // Should fail immediately with ConnectionRefused without retrying HTTP/1.
    assert!(elapsed < std::time::Duration::from_secs(2), "took too long: {elapsed:?}");
}
