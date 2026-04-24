//! HTML shell for the control dashboard UI.

const TEMPLATE: &str = include_str!("dashboard.html");

pub(super) fn dashboard_html() -> &'static str {
    TEMPLATE
}
