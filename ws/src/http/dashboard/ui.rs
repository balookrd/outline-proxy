//! HTML shell for the dashboard UI.

const TEMPLATE: &str = include_str!("dashboard.html");

pub fn dashboard_html(refresh_interval_secs: u64) -> String {
    let refresh_ms = refresh_interval_secs.saturating_mul(1000);
    TEMPLATE.replace("__DASHBOARD_REFRESH_MS__", &refresh_ms.to_string())
}
