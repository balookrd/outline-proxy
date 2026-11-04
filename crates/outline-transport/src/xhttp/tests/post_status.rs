use super::*;

fn refused(status: StatusCode) -> Result<()> {
    check_post_status("xhttp", 7, status)
}

#[test]
fn only_503_is_busy() {
    assert!(is_busy(&refused(StatusCode::SERVICE_UNAVAILABLE).unwrap_err()));
    assert!(
        !is_busy(&refused(StatusCode::CONFLICT).unwrap_err()),
        "409 is a torn-down seq gap"
    );
    assert!(!is_busy(&refused(StatusCode::GONE).unwrap_err()), "410 is a closed session");
    assert!(!is_busy(&anyhow::anyhow!("send_request failed")), "a transport error is final");
    assert!(refused(StatusCode::OK).is_ok());
}

#[test]
fn the_message_names_the_carrier_seq_and_status() {
    let error = refused(StatusCode::SERVICE_UNAVAILABLE).unwrap_err();
    assert_eq!(error.to_string(), "xhttp POST seq=7 returned 503 Service Unavailable");
}

#[tokio::test(start_paused = true)]
async fn retries_busy_with_a_doubling_capped_pause() {
    let mut retry = BusyRetry::new();
    let busy = refused(StatusCode::SERVICE_UNAVAILABLE);
    let mut pauses = Vec::new();
    for _ in 0..8 {
        let start = tokio::time::Instant::now();
        assert!(retry.again(&busy).await);
        pauses.push(start.elapsed().as_millis());
    }
    assert_eq!(pauses, [5, 10, 20, 40, 80, 160, 200, 200]);
    assert!(!retry.again(&Ok(())).await, "success is final");
    assert!(!retry.again(&refused(StatusCode::GONE)).await, "410 is final");
}

#[tokio::test(start_paused = true)]
async fn gives_up_on_a_server_that_stays_busy() {
    let mut retry = BusyRetry::new();
    let busy = refused(StatusCode::SERVICE_UNAVAILABLE);
    let start = tokio::time::Instant::now();
    while retry.again(&busy).await {}
    let waited = start.elapsed();
    assert!(waited >= RETRY_BUDGET, "gave up after {waited:?}");
    assert!(waited < RETRY_BUDGET + RETRY_MAX_DELAY * 2, "overshot: {waited:?}");
}

/// The budget is wall-clock time since the first attempt, not the sum of the
/// pauses: a server that holds each POST for 10 s before answering 503 (its
/// uplink-room patience) must not stretch the retries to minutes.
#[tokio::test(start_paused = true)]
async fn slow_attempts_spend_the_budget_too() {
    let mut retry = BusyRetry::new();
    let busy = refused(StatusCode::SERVICE_UNAVAILABLE);
    let start = tokio::time::Instant::now();
    let mut attempts = 0u32;
    loop {
        tokio::time::advance(Duration::from_secs(10)).await;
        attempts += 1;
        if !retry.again(&busy).await {
            break;
        }
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed < RETRY_BUDGET + Duration::from_secs(10) + RETRY_MAX_DELAY,
        "kept retrying for {elapsed:?} over {attempts} attempts"
    );
    assert!(attempts <= 4, "{attempts} attempts of 10 s each exceed the 30 s budget");
}
