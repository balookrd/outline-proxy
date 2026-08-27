use super::super::endpoint_routes::build_route_registry;
use crate::config::{EndpointConfig, EndpointKind};
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
