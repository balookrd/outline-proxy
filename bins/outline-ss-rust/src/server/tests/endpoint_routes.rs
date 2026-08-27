use super::super::endpoint_routes::{
    build_route_registry, build_ss_user_pool, build_vless_user_pool,
};
use crate::config::{CipherKind, EndpointConfig, EndpointKind, UserEntry};
use crate::crypto::UserKey;

fn ss_user(id: &str) -> UserKey {
    UserKey::new(id.to_owned(), "pw", None, crate::config::CipherKind::Aes128Gcm, None).unwrap()
}

fn ep(path: &str, kind: EndpointKind, padded: bool) -> EndpointConfig {
    EndpointConfig { path: path.to_owned(), kind, padded }
}

#[test]
fn combined_ws_ss_populates_both_tcp_and_udp() {
    let eps = [ep("/pss", EndpointKind::WsSs, true)];
    let reg = build_route_registry(&eps, &[ss_user("alice"), ss_user("bob")], &[]);
    assert!(reg.tcp.contains_key("/pss"), "combined lands in tcp");
    assert!(reg.udp.contains_key("/pss"), "combined lands in udp");
    assert_eq!(reg.tcp["/pss"].users.len(), 2, "pool = every ss user");
}

#[test]
fn split_kinds_land_in_one_map_each() {
    let eps = [ep("/tcp", EndpointKind::WsSsTcp, false), ep("/udp", EndpointKind::WsSsUdp, false)];
    let reg = build_route_registry(&eps, &[ss_user("a")], &[]);
    assert!(reg.tcp.contains_key("/tcp") && !reg.udp.contains_key("/tcp"));
    assert!(reg.udp.contains_key("/udp") && !reg.tcp.contains_key("/udp"));
}

#[test]
fn ss_endpoint_does_not_pull_vless_users_and_vice_versa() {
    let eps = [ep("/vl", EndpointKind::WsVless, false), ep("/tcp", EndpointKind::WsSsTcp, false)];
    let reg = build_route_registry(&eps, &[ss_user("a")], &[]);
    assert_eq!(reg.tcp["/tcp"].users.len(), 1);
    assert!(reg.vless.get("/vl").map(|r| r.users.is_empty()).unwrap_or(true));
}

fn ss_user_entry(id: &str, password: &str) -> UserEntry {
    UserEntry {
        id: id.to_owned(),
        password: Some(password.to_owned()),
        fwmark: None,
        method: None,
        ws_path_tcp: None,
        ws_path_udp: None,
        ws_path_ss: None,
        vless_id: None,
        ws_path_vless: None,
        xhttp_path_vless: None,
        xhttp_path_tcp: None,
        xhttp_path_udp: None,
        xhttp_path_ss: None,
        enabled: None,
        aliases: None,
    }
}

fn ss_user_entry_with_method(id: &str, password: &str, method: CipherKind) -> UserEntry {
    UserEntry {
        id: id.to_owned(),
        password: Some(password.to_owned()),
        fwmark: None,
        method: Some(method),
        ws_path_tcp: None,
        ws_path_udp: None,
        ws_path_ss: None,
        vless_id: None,
        ws_path_vless: None,
        xhttp_path_vless: None,
        xhttp_path_tcp: None,
        xhttp_path_udp: None,
        xhttp_path_ss: None,
        enabled: None,
        aliases: None,
    }
}

fn vless_user_entry(id: &str, vless_id: &str) -> UserEntry {
    UserEntry {
        id: id.to_owned(),
        password: None,
        fwmark: None,
        method: None,
        ws_path_tcp: None,
        ws_path_udp: None,
        ws_path_ss: None,
        vless_id: Some(vless_id.to_owned()),
        ws_path_vless: None,
        xhttp_path_vless: None,
        xhttp_path_tcp: None,
        xhttp_path_udp: None,
        xhttp_path_ss: None,
        enabled: None,
        aliases: None,
    }
}

#[test]
fn build_ss_user_pool_keeps_only_password_users() {
    let entries = [
        ss_user_entry("password_user", "secret"),
        vless_user_entry("vless_user", "00000000-0000-0000-0000-000000000001"),
    ];
    let pool = build_ss_user_pool(&entries, CipherKind::Chacha20IetfPoly1305).unwrap();
    assert_eq!(pool.len(), 1, "pool should contain only the password-bearing user");
    assert_eq!(pool[0].id(), "password_user", "password user should be in pool");
}

#[test]
fn build_ss_user_pool_respects_per_user_method_override() {
    let default_method = CipherKind::Chacha20IetfPoly1305;
    let per_user_method = CipherKind::Aes256Gcm;
    let entries = [
        ss_user_entry("default_method_user", "secret1"),
        ss_user_entry_with_method("override_method_user", "secret2", per_user_method),
    ];
    let pool = build_ss_user_pool(&entries, default_method).unwrap();
    assert_eq!(pool.len(), 2, "pool should contain both password users");

    // User with no per-user method should use default
    assert_eq!(pool[0].cipher(), default_method, "first user should use default method");

    // User with per-user method should use it
    assert_eq!(
        pool[1].cipher(),
        per_user_method,
        "second user should use per-user method override"
    );
}

#[test]
fn build_vless_user_pool_keeps_only_vless_users() {
    let entries = [
        ss_user_entry("password_user", "secret"),
        vless_user_entry("vless_user", "00000000-0000-0000-0000-000000000001"),
    ];
    let pool = build_vless_user_pool(&entries).unwrap();
    assert_eq!(pool.len(), 1, "pool should contain only the vless_id-bearing user");
    assert_eq!(pool[0].label(), "vless_user", "vless user should be in pool");
}
