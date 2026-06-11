//! HTML shell for the dashboard UI.

const DASHBOARD_TEMPLATE: &str = include_str!("dashboard.html");
const UPLINKS_TEMPLATE: &str = include_str!("uplinks.html");

pub fn dashboard_html(refresh_interval_secs: u64) -> String {
    let refresh_ms = refresh_interval_secs.saturating_mul(1000);
    DASHBOARD_TEMPLATE.replace("__DASHBOARD_REFRESH_MS__", &refresh_ms.to_string())
}

pub fn uplinks_html() -> String {
    UPLINKS_TEMPLATE.to_string()
}
