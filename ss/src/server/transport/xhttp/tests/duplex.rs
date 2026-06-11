use super::*;

use std::sync::Arc;
use std::time::{Duration, Instant};

/// The relay's keepalive tick reaches the XHTTP carrier as
/// `XhttpMsg::Noop`. It must `touch()` the session so the registry
/// janitor does not evict an idle-but-live UDP datagram relay — an
/// eviction the client observes as a spurious `ws closed`.
#[tokio::test]
async fn noop_keepalive_touches_session() {
    let session = Arc::new(XhttpSession::new(Arc::from("test-session"), None));

    // Let real wall-clock advance so a cutoff can sit strictly between
    // session creation and the keepalive touch. `touch`/`is_idle_since`
    // read `std::time::Instant`, which tokio's paused clock does not
    // move — a short real sleep is the simplest reliable lever.
    tokio::time::sleep(Duration::from_millis(40)).await;

    // Never touched: last activity == creation (~40 ms ago), older than
    // a 20-ms-ago cutoff → reads as idle.
    let cutoff_before = Instant::now() - Duration::from_millis(20);
    assert!(
        session.is_idle_since(cutoff_before),
        "a never-touched session should read as idle past the cutoff"
    );

    let duplex = XhttpDuplex { session: Arc::clone(&session) };
    let (_reader, mut writer) = duplex.split_io();
    XhttpDuplex::send(&mut writer, XhttpMsg::Noop)
        .await
        .expect("Noop keepalive send must succeed");

    // Touched: last activity is now ~now, newer than a 20-ms-ago cutoff
    // → no longer idle. This is what keeps the janitor off a live relay
    // during a lull between datagrams.
    let cutoff_after = Instant::now() - Duration::from_millis(20);
    assert!(
        !session.is_idle_since(cutoff_after),
        "Noop keepalive must touch the session so the janitor spares a live relay"
    );
}

/// A `Close` on the XHTTP carrier still tears the session down — the
/// keepalive change must not blunt the close path.
#[tokio::test]
async fn close_still_closes_session() {
    let session = Arc::new(XhttpSession::new(Arc::from("test-session"), None));
    let duplex = XhttpDuplex { session: Arc::clone(&session) };
    let (_reader, mut writer) = duplex.split_io();

    XhttpDuplex::send(&mut writer, XhttpMsg::Close).await.unwrap();
    assert!(session.is_closed(), "Close must close the session");
}
