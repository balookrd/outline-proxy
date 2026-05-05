use std::path::{Path, PathBuf};

use super::groups::merge_probe_section;
use super::routing::resolve_config_path;
use super::super::schema::{
    DnsProbeSection, HttpProbeSection, ProbeSection, TcpProbeSection, WsProbeSection,
};

fn probe(interval: Option<u64>, timeout: Option<u64>) -> ProbeSection {
    ProbeSection {
        interval_secs: interval,
        timeout_secs: timeout,
        max_concurrent: None,
        max_dials: None,
        min_failures: None,
        attempts: None,
        ws: None,
        http: None,
        dns: None,
        tcp: None,
    }
}

// ── merge_probe_section ───────────────────────────────────────────────────

#[test]
fn merge_both_none_yields_none() {
    assert!(merge_probe_section(None, None).is_none());
}

#[test]
fn merge_only_template_returns_template() {
    let t = probe(Some(60), Some(5));
    let r = merge_probe_section(Some(&t), None).unwrap();
    assert_eq!(r.interval_secs, Some(60));
    assert_eq!(r.timeout_secs, Some(5));
}

#[test]
fn merge_only_override_returns_override() {
    let o = probe(Some(120), Some(10));
    let r = merge_probe_section(None, Some(&o)).unwrap();
    assert_eq!(r.interval_secs, Some(120));
    assert_eq!(r.timeout_secs, Some(10));
}

#[test]
fn merge_override_wins_when_both_set() {
    let t = probe(Some(60), Some(5));
    let o = probe(Some(120), Some(10));
    let r = merge_probe_section(Some(&t), Some(&o)).unwrap();
    assert_eq!(r.interval_secs, Some(120));
    assert_eq!(r.timeout_secs, Some(10));
}

#[test]
fn merge_template_fills_unset_override_fields() {
    let t = probe(Some(60), Some(5));
    let o = probe(None, Some(10)); // override sets only timeout
    let r = merge_probe_section(Some(&t), Some(&o)).unwrap();
    assert_eq!(r.interval_secs, Some(60), "template interval should fill in");
    assert_eq!(r.timeout_secs, Some(10), "override timeout should win");
}

#[test]
fn merge_override_sub_table_replaces_template_not_merges() {
    let mut t = probe(Some(60), Some(5));
    t.http = Some(HttpProbeSection {
        url: Some("http://template.example.com/probe".parse().unwrap()),
        urls: None,
    });
    t.dns = Some(DnsProbeSection {
        server: "8.8.8.8".to_string(),
        port: Some(53),
        name: None,
    });

    let mut o = probe(None, None);
    o.http = Some(HttpProbeSection {
        url: Some("http://override.example.com/probe".parse().unwrap()),
        urls: None,
    });
    // o.dns is not set — template's dns must survive

    let r = merge_probe_section(Some(&t), Some(&o)).unwrap();
    assert_eq!(
        r.http.unwrap().url.as_ref().unwrap().as_str(),
        "http://override.example.com/probe",
        "override http must replace template http"
    );
    assert_eq!(
        r.dns.unwrap().server,
        "8.8.8.8",
        "template dns must survive when override does not set dns"
    );
}

#[test]
fn merge_override_tcp_replaces_template_tcp() {
    let mut t = probe(None, None);
    t.tcp = Some(TcpProbeSection { host: "template.host".to_string(), port: Some(80) });
    let mut o = probe(None, None);
    o.tcp = Some(TcpProbeSection { host: "override.host".to_string(), port: Some(443) });
    let r = merge_probe_section(Some(&t), Some(&o)).unwrap();
    assert_eq!(r.tcp.unwrap().host, "override.host");
}

#[test]
fn merge_ws_section_override_wins() {
    let mut t = probe(None, None);
    t.ws = Some(WsProbeSection { enabled: Some(true) });
    let mut o = probe(None, None);
    o.ws = Some(WsProbeSection { enabled: Some(false) });
    let r = merge_probe_section(Some(&t), Some(&o)).unwrap();
    assert_eq!(r.ws.unwrap().enabled, Some(false));
}

#[test]
fn resolve_config_path_rejects_parent_components() {
    let err = resolve_config_path(Path::new("../etc/passwd"), Path::new("/etc/outline"))
        .unwrap_err()
        .to_string();
    assert!(err.contains("must not contain `..`"), "got: {err}");
}

#[test]
fn resolve_config_path_rejects_embedded_parent() {
    let err =
        resolve_config_path(Path::new("lists/../../etc/passwd"), Path::new("/etc/outline"))
            .unwrap_err()
            .to_string();
    assert!(err.contains("must not contain `..`"), "got: {err}");
}

#[test]
fn resolve_config_path_keeps_absolute() {
    let p =
        resolve_config_path(Path::new("/var/lib/outline/ru.lst"), Path::new("/etc/outline"))
            .unwrap();
    assert_eq!(p, PathBuf::from("/var/lib/outline/ru.lst"));
}

#[test]
fn resolve_config_path_joins_relative_with_config_dir() {
    let p = resolve_config_path(Path::new("lists/ru.lst"), Path::new("/etc/outline")).unwrap();
    assert_eq!(p, PathBuf::from("/etc/outline/lists/ru.lst"));
}
