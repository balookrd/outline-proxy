use std::path::{Path, PathBuf};

use super::groups::merge_probe_section;
use super::routing::resolve_config_path;

mod groups;
mod uplinks;
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
        tls: None,
        skip_when_active: None,
        liveness_interval_secs: None,
        endpoint_check: None,
        endpoint_check_timeout_ms: None,
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
    t.tcp = Some(TcpProbeSection {
        host: "template.host".to_string(),
        port: Some(80),
    });
    let mut o = probe(None, None);
    o.tcp = Some(TcpProbeSection {
        host: "override.host".to_string(),
        port: Some(443),
    });
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
    let err = resolve_config_path(Path::new("lists/../../etc/passwd"), Path::new("/etc/outline"))
        .unwrap_err()
        .to_string();
    assert!(err.contains("must not contain `..`"), "got: {err}");
}

#[test]
fn resolve_config_path_keeps_absolute() {
    let p = resolve_config_path(Path::new("/var/lib/outline/ru.lst"), Path::new("/etc/outline"))
        .unwrap();
    assert_eq!(p, PathBuf::from("/var/lib/outline/ru.lst"));
}

#[test]
fn resolve_config_path_joins_relative_with_config_dir() {
    let p = resolve_config_path(Path::new("lists/ru.lst"), Path::new("/etc/outline")).unwrap();
    assert_eq!(p, PathBuf::from("/etc/outline/lists/ru.lst"));
}

#[cfg(feature = "tun")]
#[test]
fn load_tun_config_normalizes_sniff_override_include_and_exclude() {
    use super::super::schema::TunSection;
    use super::tun::load_tun_config;
    use crate::config::args::Args;
    use clap::Parser;

    let tun = TunSection {
        path: Some("/dev/net/tun".into()),
        name: None,
        mtu: None,
        max_flows: None,
        max_carrier_flows: None,
        idle_timeout_secs: None,
        max_concurrent_upstream_dials: None,
        tcp: None,
        defrag_max_fragment_sets: None,
        defrag_max_fragments_per_set: None,
        defrag_max_total_bytes: None,
        defrag_max_bytes_per_set: None,
        ipsec_bypass: None,
        pmtud_emit_below_quic_initial: None,
        sniff_quic: None,
        route_by_sni: None,
        sniff_override_include: Some(vec![
            "*.YOUTUBE.COM".into(),
            ".instagram.com.".into(),
            "".into(),
        ]),
        sniff_override_include_file: None,
        sniff_override_include_files: None,
        sniff_override_exclude: Some(vec!["strava.com".into()]),
        sniff_override_exclude_file: None,
        sniff_override_exclude_files: None,
        gso: None,
        gro: None,
        uso: None,
    };

    let args = Args::parse_from(["test"]);
    let cfg = load_tun_config(Some(&tun), &args, Path::new(".")).unwrap().unwrap();
    assert_eq!(
        cfg.sniff_override_include.as_ref(),
        &["youtube.com".into(), "instagram.com".into()][..]
    );
    assert_eq!(cfg.sniff_override_exclude.as_ref(), &["strava.com".into()][..]);
    assert_eq!(
        cfg.tcp.sniff_override_include.as_ref(),
        &["youtube.com".into(), "instagram.com".into()][..]
    );
}

#[cfg(feature = "tun")]
#[test]
fn load_tun_config_reads_sniff_override_from_files() {
    use super::super::schema::TunSection;
    use super::tun::load_tun_config;
    use crate::config::args::Args;
    use clap::Parser;

    let tmp_dir =
        std::env::temp_dir().join(format!("outline-tun-cfg-test-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let inc_file = tmp_dir.join("include.lst");
    std::fs::write(&inc_file, "# blocked domains\n*.example.com\n\nsub.domain.org.\n").unwrap();
    let exc_file = tmp_dir.join("exclude.lst");
    std::fs::write(&exc_file, "cdn.example.com\n").unwrap();

    let tun = TunSection {
        path: Some("/dev/net/tun".into()),
        name: None,
        mtu: None,
        max_flows: None,
        max_carrier_flows: None,
        idle_timeout_secs: None,
        max_concurrent_upstream_dials: None,
        tcp: None,
        defrag_max_fragment_sets: None,
        defrag_max_fragments_per_set: None,
        defrag_max_total_bytes: None,
        defrag_max_bytes_per_set: None,
        ipsec_bypass: None,
        pmtud_emit_below_quic_initial: None,
        sniff_quic: None,
        route_by_sni: None,
        sniff_override_include: Some(vec!["inline.net".into()]),
        sniff_override_include_file: Some("include.lst".into()),
        sniff_override_include_files: None,
        sniff_override_exclude: None,
        sniff_override_exclude_file: Some("exclude.lst".into()),
        sniff_override_exclude_files: None,
        gso: None,
        gro: None,
        uso: None,
    };

    let args = Args::parse_from(["test"]);
    let cfg = load_tun_config(Some(&tun), &args, &tmp_dir).unwrap().unwrap();
    assert_eq!(
        cfg.sniff_override_include.as_ref(),
        &["inline.net".into(), "example.com".into(), "sub.domain.org".into()][..]
    );
    assert_eq!(cfg.sniff_override_exclude.as_ref(), &["cdn.example.com".into()][..]);

    let _ = std::fs::remove_dir_all(tmp_dir);
}
