use super::*;

#[test]
fn substitutes_the_base_prefix() {
    let out = render("const API_BASE = \"__BASE__\";", "/ws", 5000);

    assert_eq!(out, "const API_BASE = \"/ws\";");
}

#[test]
fn substitutes_the_refresh_interval() {
    let out = render("const MS = __DASHBOARD_REFRESH_MS__;", "/ws", 5000);

    assert_eq!(out, "const MS = 5000;");
}

/// A surviving placeholder means the browser would fetch a literal `__BASE__`
/// path and every call would 404 — worth failing loudly on.
#[test]
fn leaves_no_placeholder_behind() {
    let out = render("a __BASE__ b __DASHBOARD_REFRESH_MS__ c __BASE__", "/ss", 1000);

    assert!(!out.contains("__BASE__"), "unsubstituted base: {out}");
    assert!(!out.contains("__DASHBOARD_REFRESH_MS__"), "unsubstituted refresh: {out}");
}

/// The index is what `/` serves; if it ever stops naming both trees the
/// operator loses the only in-app way to reach one of them.
#[test]
fn index_links_both_trees() {
    let body = INDEX_TEMPLATE;

    assert!(body.contains("/ws/dashboard"), "index must link the client dashboard");
    assert!(body.contains("/ss/dashboard"), "index must link the server dashboard");
}
