use super::*;

/// A dashboard activate request without `soft` defaults to a hard switch, so the
/// aggregator forwards no `soft` field and the plain-activate wire shape is
/// unchanged.
#[test]
fn activate_request_defaults_soft_to_false() {
    let req: DashboardActivateRequest =
        serde_json::from_str(r#"{"targets":[{"instance":"i","group":"g","uplink":"u"}]}"#).unwrap();
    assert!(!req.soft, "soft must default to a hard switch");
}

/// The Soft switch control sends `soft: true`, which the aggregator forwards to
/// `/control/activate`.
#[test]
fn activate_request_parses_soft_true() {
    let req: DashboardActivateRequest = serde_json::from_str(
        r#"{"targets":[{"instance":"i","group":"g","uplink":"u"}],"soft":true}"#,
    )
    .unwrap();
    assert!(req.soft);
}
