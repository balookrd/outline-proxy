//! Cluster-level orchestration for the SS dashboard (`/ss/dashboard/api/clusters/*`).
//!
//! Coordinates parallel fan-out across cluster members (explicit `[[ss.clusters]]`
//! or auto-discovered by matching `psk_fingerprint`), drift & mesh health analysis,
//! atomic-style user creation with pre-flight + rollback, and access-keys generation.

use std::collections::{BTreeMap, HashMap, HashSet};

use axum::extract::{Path, Query, State};
use axum::response::Response;
use bytes::Bytes;
use http::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio::task::JoinSet;

use crate::assets::{json_error, json_response};
use crate::backend::BackendResponse;
use crate::config::InstanceConfig;

use super::SsState;
use super::api::{encode_path_segment, is_valid_user_id, parse_or_raw};

#[derive(Debug, Clone)]
pub(super) struct ResolvedCluster {
    pub name: String,
    pub source: &'static str,
    pub members: Vec<InstanceConfig>,
    pub subscription_nodes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct ClusterSummaryView {
    pub name: String,
    pub source: &'static str,
    pub members: Vec<String>,
    pub subscription_nodes: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct ClusterAccessKeysQuery {
    #[serde(default)]
    pub nodes: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RegenerateClusterRequest {
    #[serde(default)]
    pub nodes: Option<Vec<String>>,
    #[serde(default)]
    pub prune: Option<bool>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct PatchClusterConfigRequest {
    #[serde(default)]
    pub shared: Option<Value>,
    #[serde(default)]
    pub per_node: HashMap<String, Value>,
}

#[derive(Debug, Serialize)]
pub(super) struct NodeActionResult {
    pub instance: String,
    pub ok: bool,
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires_restart: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub already_absent: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rolled_back: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

struct FanOutOutcome {
    instance: String,
    result: anyhow::Result<BackendResponse>,
}

async fn fan_out<F>(
    instances: &[InstanceConfig],
    backend: &crate::backend::Backend,
    build: F,
) -> Vec<FanOutOutcome>
where
    F: Fn(&InstanceConfig) -> (Method, String, Option<Bytes>),
{
    let mut join_set = JoinSet::new();
    for (idx, inst) in instances.iter().cloned().enumerate() {
        let (method, path, body) = build(&inst);
        let backend = backend.clone_handle();
        join_set.spawn(async move {
            let res = backend.request(&inst, method, &path, body).await;
            (idx, inst.name, res)
        });
    }

    let mut ordered = Vec::with_capacity(instances.len());
    while let Some(joined) = join_set.join_next().await {
        if let Ok((idx, instance, result)) = joined {
            ordered.push((idx, FanOutOutcome { instance, result }));
        }
    }
    ordered.sort_by_key(|(idx, _)| *idx);
    ordered.into_iter().map(|(_, item)| item).collect()
}

pub(super) fn build_access_keys_path(user_id: &str, nodes: Option<&[String]>) -> String {
    let base = format!("/control/users/{}/access-keys", encode_path_segment(user_id));
    match nodes {
        Some(list) if !list.is_empty() => {
            let qs = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("nodes", &list.join(","))
                .finish();
            format!("{base}?{qs}")
        },
        _ => base,
    }
}

pub(super) fn parse_nodes_query(raw: Option<&str>) -> Option<Vec<String>> {
    raw.map(|s| {
        s.split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>()
    })
    .filter(|list| !list.is_empty())
}

fn instance_by_name<'a>(state: &'a SsState, name: &str) -> Option<&'a InstanceConfig> {
    state.instances.iter().find(|i| i.name == name)
}

fn explicit_clusters(state: &SsState) -> Vec<ResolvedCluster> {
    state
        .clusters
        .iter()
        .filter_map(|cfg| {
            let members: Vec<InstanceConfig> = cfg
                .members
                .iter()
                .filter_map(|m| instance_by_name(state, m).cloned())
                .collect();
            if members.is_empty() {
                return None;
            }
            Some(ResolvedCluster {
                name: cfg.name.clone(),
                source: "config",
                members,
                subscription_nodes: cfg.subscription_nodes.clone(),
            })
        })
        .collect()
}

fn sanitize_member_token(raw: &str) -> String {
    raw.trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

pub(super) fn discovered_cluster_name(members: &[InstanceConfig], fp: &str) -> String {
    let names: Vec<String> = members
        .iter()
        .map(|m| sanitize_member_token(&m.name))
        .filter(|s| !s.is_empty())
        .collect();
    match names.len() {
        0 => {
            let prefix: String = fp.chars().take(6).collect();
            format!("auto-{prefix}")
        },
        1..=3 => names.join("+"),
        n => format!("{}+{}+{}more", names[0], names[1], n - 2),
    }
}

async fn discover_clusters(
    state: &SsState,
    reserved_names: &HashSet<String>,
) -> Vec<ResolvedCluster> {
    let claimed_instances: HashSet<&str> = state
        .clusters
        .iter()
        .flat_map(|c| c.members.iter().map(String::as_str))
        .collect();

    let standalone: Vec<InstanceConfig> = state
        .instances
        .iter()
        .filter(|i| !claimed_instances.contains(i.name.as_str()))
        .cloned()
        .collect();

    if standalone.len() < 2 {
        return Vec::new();
    }

    let outcomes = fan_out(&standalone, &state.backend, |_| {
        (Method::GET, "/control/config".to_string(), None)
    })
    .await;

    let mut by_fp: BTreeMap<String, Vec<InstanceConfig>> = BTreeMap::new();
    for (idx, item) in outcomes.into_iter().enumerate() {
        let Ok(resp) = item.result else {
            continue;
        };
        if !resp.status.is_success() {
            continue;
        }
        let Ok(cfg) = serde_json::from_slice::<Value>(&resp.body) else {
            continue;
        };
        let enabled = cfg.pointer("/cluster/enabled").and_then(Value::as_bool) == Some(true);
        let fp = cfg
            .pointer("/cluster/psk_fingerprint")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty());
        if enabled && let Some(fp) = fp {
            by_fp.entry(fp.to_owned()).or_default().push(standalone[idx].clone());
        }
    }

    let mut used_names = reserved_names.clone();
    let mut discovered = Vec::new();
    for (fp, members) in by_fp {
        if members.len() < 2 {
            continue;
        }
        let base = discovered_cluster_name(&members, &fp);
        let mut candidate = base.clone();
        let mut suffix = 2usize;
        while !used_names.insert(candidate.clone()) {
            candidate = format!("{base}-{suffix}");
            suffix += 1;
        }
        discovered.push(ResolvedCluster {
            name: candidate,
            source: "discovered",
            members,
            subscription_nodes: Vec::new(),
        });
    }
    discovered
}

async fn resolve_cluster(state: &SsState, name: &str) -> Option<ResolvedCluster> {
    let explicit = explicit_clusters(state);
    if let Some(found) = explicit.iter().find(|c| c.name == name) {
        return Some(found.clone());
    }
    let reserved: HashSet<String> = explicit.iter().map(|c| c.name.clone()).collect();
    discover_clusters(state, &reserved)
        .await
        .into_iter()
        .find(|c| c.name == name)
}

pub async fn list_clusters(State(state): State<SsState>) -> Response {
    let explicit = explicit_clusters(&state);
    let reserved: HashSet<String> = explicit.iter().map(|c| c.name.clone()).collect();
    let discovered = discover_clusters(&state, &reserved).await;

    let clusters: Vec<ClusterSummaryView> = explicit
        .into_iter()
        .chain(discovered)
        .map(|c| ClusterSummaryView {
            name: c.name,
            source: c.source,
            members: c.members.into_iter().map(|m| m.name).collect(),
            subscription_nodes: c.subscription_nodes,
        })
        .collect();

    json_response(StatusCode::OK, &serde_json::json!({ "clusters": clusters }))
}

fn canonicalize_value(val: Value) -> Value {
    match val {
        Value::Object(map) => {
            if map.is_empty() {
                Value::Null
            } else {
                Value::Object(map.into_iter().map(|(k, v)| (k, canonicalize_value(v))).collect())
            }
        },
        other => other,
    }
}

fn pointer_value(cfg: &Value, ptr: &str) -> Value {
    cfg.pointer(ptr)
        .cloned()
        .map(canonicalize_value)
        .unwrap_or(Value::Null)
}

fn compute_config_drift(alive_configs: &[(String, Value)]) -> Vec<String> {
    if alive_configs.len() < 2 {
        return Vec::new();
    }
    let shared_pointers: &[(&str, &str)] = &[
        ("endpoints", "/endpoints"),
        ("shadowsocks.method", "/shadowsocks/method"),
        ("http_root", "/http_root"),
        ("access_keys.public_host", "/access_keys/public_host"),
        ("access_keys.public_scheme", "/access_keys/public_scheme"),
        ("access_keys.url_base", "/access_keys/url_base"),
        ("access_keys.file_extension", "/access_keys/file_extension"),
        ("access_keys.nodes", "/access_keys/nodes"),
        ("session_resumption", "/session_resumption"),
        ("outbound.prefer_ipv4", "/outbound/prefer_ipv4"),
        ("outbound.block_private_ips", "/outbound/block_private_ips"),
        ("outbound.allowed_subnets", "/outbound/allowed_subnets"),
        ("outbound.ipv6_sticky", "/outbound/ipv6_sticky"),
        ("outbound.ipv6_sticky_ttl_secs", "/outbound/ipv6_sticky_ttl_secs"),
        ("outbound.ipv6_refresh_secs", "/outbound/ipv6_refresh_secs"),
        ("padding", "/padding"),
        ("http_fallback", "/http_fallback"),
        ("sni_fallback", "/sni_fallback"),
        ("tuning_profile", "/tuning_profile"),
        ("tuning", "/tuning"),
        ("server.max_connections_per_ip", "/server/max_connections_per_ip"),
        ("server.h3_alpn", "/server/h3_alpn"),
        ("server.h3_initial_mtu", "/server/h3_initial_mtu"),
        ("server.h3_mtu_first_probe", "/server/h3_mtu_first_probe"),
        ("server.h3_udp_datagrams", "/server/h3_udp_datagrams"),
    ];

    let mut drift = Vec::new();
    for (label, ptr) in shared_pointers {
        let first = pointer_value(&alive_configs[0].1, ptr);
        if alive_configs[1..]
            .iter()
            .any(|(_, cfg)| pointer_value(cfg, ptr) != first)
        {
            drift.push((*label).to_string());
        }
    }
    drift
}

fn compute_mesh_health(cluster: &ResolvedCluster, alive_configs: &[(String, Value)]) -> Value {
    let all_reachable = alive_configs.len() == cluster.members.len() && !alive_configs.is_empty();
    let restart_pending_nodes: Vec<String> = alive_configs
        .iter()
        .filter(|(_, cfg)| cfg.get("restart_pending").and_then(Value::as_bool) == Some(true))
        .map(|(name, _)| name.clone())
        .collect();

    if !all_reachable {
        return serde_json::json!({
            "all_reachable": false,
            "psk_match": false,
            "shards_unique": false,
            "peers_symmetric": false,
            "restart_pending_nodes": restart_pending_nodes,
        });
    }

    let mut psk_fps = HashSet::new();
    let mut all_cluster_enabled = true;
    let mut shard_ids = Vec::with_capacity(alive_configs.len());
    let mut shards_unique = true;
    let mut shard_set = HashSet::new();

    for (_, cfg) in alive_configs {
        let enabled = cfg.pointer("/cluster/enabled").and_then(Value::as_bool) == Some(true);
        if !enabled {
            all_cluster_enabled = false;
        }
        if let Some(fp) = cfg
            .pointer("/cluster/psk_fingerprint")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            psk_fps.insert(fp.to_string());
        } else {
            all_cluster_enabled = false;
        }
        if let Some(shard) = cfg.pointer("/cluster/shard_id").and_then(Value::as_u64) {
            if !shard_set.insert(shard) {
                shards_unique = false;
            }
            shard_ids.push(Some(shard));
        } else {
            shards_unique = false;
            shard_ids.push(None);
        }
    }
    let psk_match = all_cluster_enabled && psk_fps.len() == 1;

    let mut peers_symmetric = all_cluster_enabled && shards_unique;
    if peers_symmetric && alive_configs.len() >= 2 {
        let expected_mesh_addr: Vec<Option<&str>> =
            cluster.members.iter().map(|m| m.mesh_addr.as_deref()).collect();
        for (i, (_, cfg_i)) in alive_configs.iter().enumerate() {
            let Some(peers) = cfg_i.pointer("/cluster/peers").and_then(Value::as_array) else {
                peers_symmetric = false;
                break;
            };
            let peer_map: HashMap<u64, &str> = peers
                .iter()
                .filter_map(|p| {
                    let shard = p.get("shard").and_then(Value::as_u64)?;
                    let addr = p.get("addr").and_then(Value::as_str)?.trim();
                    Some((shard, addr))
                })
                .collect();

            for (j, target_shard) in shard_ids.iter().enumerate() {
                if i == j {
                    continue;
                }
                let Some(s_j) = target_shard else {
                    peers_symmetric = false;
                    break;
                };
                let Some(addr) = peer_map.get(s_j) else {
                    peers_symmetric = false;
                    break;
                };
                if addr.is_empty() {
                    peers_symmetric = false;
                    break;
                }
                if let Some(expected) = expected_mesh_addr.get(j).copied().flatten()
                    && *addr != expected
                {
                    peers_symmetric = false;
                    break;
                }
            }
            if !peers_symmetric {
                break;
            }
        }
    }

    serde_json::json!({
        "all_reachable": all_reachable,
        "psk_match": psk_match,
        "shards_unique": shards_unique,
        "peers_symmetric": peers_symmetric,
        "restart_pending_nodes": restart_pending_nodes,
    })
}

pub async fn defaults(State(state): State<SsState>, Path(cluster_name): Path<String>) -> Response {
    let Some(cluster) = resolve_cluster(&state, &cluster_name).await else {
        return json_error(StatusCode::NOT_FOUND, "unknown cluster");
    };

    let outcomes = fan_out(&cluster.members, &state.backend, |_| {
        (Method::GET, "/control/defaults".to_string(), None)
    })
    .await;

    let mut last_error: Option<(StatusCode, String)> = None;
    for item in outcomes {
        match item.result {
            Ok(resp) if resp.status.is_success() => {
                return json_response(StatusCode::OK, &parse_or_raw(&resp.body));
            },
            Ok(resp) => {
                let parsed = parse_or_raw(&resp.body);
                let msg = parsed
                    .get("error")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("HTTP {}", resp.status.as_u16()));
                last_error = Some((resp.status, msg));
            },
            Err(err) => {
                last_error = Some((StatusCode::BAD_GATEWAY, format!("{err:#}")));
            },
        }
    }

    let (status, msg) =
        last_error.unwrap_or((StatusCode::BAD_GATEWAY, "cluster has no reachable members".into()));
    json_error(status, &msg)
}

pub async fn get_config(
    State(state): State<SsState>,
    Path(cluster_name): Path<String>,
) -> Response {
    let Some(cluster) = resolve_cluster(&state, &cluster_name).await else {
        return json_error(StatusCode::NOT_FOUND, "unknown cluster");
    };

    let outcomes = fan_out(&cluster.members, &state.backend, |_| {
        (Method::GET, "/control/config".to_string(), None)
    })
    .await;

    let mut nodes = Vec::with_capacity(outcomes.len());
    let mut alive_configs = Vec::new();
    for item in outcomes {
        match item.result {
            Ok(resp) if resp.status.is_success() => {
                let parsed = parse_or_raw(&resp.body);
                alive_configs.push((item.instance.clone(), parsed.clone()));
                nodes.push(serde_json::json!({
                    "instance": item.instance,
                    "ok": true,
                    "status": resp.status.as_u16(),
                    "config": parsed,
                }));
            },
            Ok(resp) => {
                let parsed = parse_or_raw(&resp.body);
                let err = parsed
                    .get("error")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("HTTP {}", resp.status.as_u16()));
                nodes.push(serde_json::json!({
                    "instance": item.instance,
                    "ok": false,
                    "status": resp.status.as_u16(),
                    "error": err,
                }));
            },
            Err(err) => {
                nodes.push(serde_json::json!({
                    "instance": item.instance,
                    "ok": false,
                    "status": StatusCode::BAD_GATEWAY.as_u16(),
                    "error": format!("{err:#}"),
                }));
            },
        }
    }

    let drift = compute_config_drift(&alive_configs);
    let mesh_health = compute_mesh_health(&cluster, &alive_configs);

    json_response(
        StatusCode::OK,
        &serde_json::json!({
            "cluster": cluster.name,
            "source": cluster.source,
            "members": cluster.members.iter().map(|m| &m.name).collect::<Vec<_>>(),
            "subscription_nodes": cluster.subscription_nodes,
            "nodes": nodes,
            "drift": drift,
            "mesh_health": mesh_health,
        }),
    )
}

/// Deep-merges one level of JSON objects so per-node keys inside `[server]`,
/// `[outbound]`, `[access_keys]`, `[cluster]` override only conflicting keys
/// without clobbering sibling shared keys.
fn merge_patch(shared: Option<&Value>, per_node: Option<&Value>) -> Value {
    let mut dst = match shared {
        Some(Value::Object(map)) => map.clone(),
        _ => Map::new(),
    };
    if let Some(Value::Object(src)) = per_node {
        for (k, v) in src {
            match (dst.get_mut(k), v) {
                (Some(Value::Object(dst_nested)), Value::Object(src_nested)) => {
                    for (nk, nv) in src_nested {
                        dst_nested.insert(nk.clone(), nv.clone());
                    }
                },
                _ => {
                    dst.insert(k.clone(), v.clone());
                },
            }
        }
    }
    Value::Object(dst)
}

pub async fn patch_config(
    State(state): State<SsState>,
    Path(cluster_name): Path<String>,
    body: Bytes,
) -> Response {
    let Some(cluster) = resolve_cluster(&state, &cluster_name).await else {
        return json_error(StatusCode::NOT_FOUND, "unknown cluster");
    };
    let req: PatchClusterConfigRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(err) => return json_error(StatusCode::BAD_REQUEST, &format!("invalid JSON: {err}")),
    };

    let member_names: HashSet<&str> = cluster.members.iter().map(|m| m.name.as_str()).collect();
    for key in req.per_node.keys() {
        if !member_names.contains(key.as_str()) {
            return json_error(
                StatusCode::BAD_REQUEST,
                &format!("per_node references unknown cluster member {key:?}"),
            );
        }
    }

    let mut targets = Vec::new();
    let mut skipped_results = Vec::new();
    for member in &cluster.members {
        let merged = merge_patch(req.shared.as_ref(), req.per_node.get(&member.name));
        if merged.as_object().is_some_and(Map::is_empty) {
            skipped_results.push(NodeActionResult {
                instance: member.name.clone(),
                ok: true,
                status: StatusCode::OK.as_u16(),
                requires_restart: Some(false),
                already_absent: None,
                rolled_back: None,
                error: None,
                data: None,
            });
        } else {
            let payload = Bytes::from(serde_json::to_vec(&merged).unwrap_or_default());
            targets.push((member.clone(), payload));
        }
    }

    let instances: Vec<InstanceConfig> = targets.iter().map(|(inst, _)| inst.clone()).collect();
    let bodies: HashMap<String, Bytes> = targets
        .into_iter()
        .map(|(inst, payload)| (inst.name, payload))
        .collect();

    let outcomes = fan_out(&instances, &state.backend, |inst| {
        (Method::PATCH, "/control/config".to_string(), bodies.get(&inst.name).cloned())
    })
    .await;

    let mut results = Vec::with_capacity(cluster.members.len());
    results.extend(skipped_results);
    for item in outcomes {
        results.push(outcome_to_action_result(item));
    }

    let order: HashMap<&str, usize> = cluster
        .members
        .iter()
        .enumerate()
        .map(|(i, m)| (m.name.as_str(), i))
        .collect();
    results.sort_by_key(|r| order.get(r.instance.as_str()).copied().unwrap_or(usize::MAX));

    let all_ok = results.iter().all(|r| r.ok);
    let status = if all_ok {
        StatusCode::OK
    } else if results
        .iter()
        .all(|r| !r.ok && r.status == StatusCode::BAD_REQUEST.as_u16())
    {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::BAD_GATEWAY
    };

    json_response(
        status,
        &serde_json::json!({
            "ok": all_ok,
            "cluster": cluster.name,
            "results": results,
        }),
    )
}

fn outcome_to_action_result(item: FanOutOutcome) -> NodeActionResult {
    match item.result {
        Ok(resp) if resp.status.is_success() => {
            let data = if resp.body.is_empty() {
                None
            } else {
                Some(parse_or_raw(&resp.body))
            };
            let requires_restart = data
                .as_ref()
                .and_then(|v| v.get("requires_restart"))
                .and_then(Value::as_bool);
            NodeActionResult {
                instance: item.instance,
                ok: true,
                status: resp.status.as_u16(),
                requires_restart,
                already_absent: None,
                rolled_back: None,
                error: None,
                data,
            }
        },
        Ok(resp) => {
            let parsed = parse_or_raw(&resp.body);
            let error = parsed
                .get("error")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| format!("HTTP {}", resp.status.as_u16()));
            NodeActionResult {
                instance: item.instance,
                ok: false,
                status: resp.status.as_u16(),
                requires_restart: None,
                already_absent: None,
                rolled_back: None,
                error: Some(error),
                data: Some(parsed),
            }
        },
        Err(err) => NodeActionResult {
            instance: item.instance,
            ok: false,
            status: StatusCode::BAD_GATEWAY.as_u16(),
            requires_restart: None,
            already_absent: None,
            rolled_back: None,
            error: Some(format!("{err:#}")),
            data: None,
        },
    }
}

pub async fn list_users(
    State(state): State<SsState>,
    Path(cluster_name): Path<String>,
) -> Response {
    let Some(cluster) = resolve_cluster(&state, &cluster_name).await else {
        return json_error(StatusCode::NOT_FOUND, "unknown cluster");
    };

    let outcomes = fan_out(&cluster.members, &state.backend, |_| {
        (Method::GET, "/control/users".to_string(), None)
    })
    .await;

    let mut node_errors = Vec::new();
    let mut node_users: Vec<(String, BTreeMap<String, Value>)> = Vec::new();
    let mut ordered_ids = Vec::new();
    let mut seen_ids = HashSet::new();

    for item in outcomes {
        match item.result {
            Ok(resp) if resp.status.is_success() => {
                let parsed = parse_or_raw(&resp.body);
                let mut map = BTreeMap::new();
                if let Some(arr) = parsed.get("users").and_then(Value::as_array) {
                    for u in arr {
                        if let Some(id) = u.get("id").and_then(Value::as_str) {
                            if seen_ids.insert(id.to_string()) {
                                ordered_ids.push(id.to_string());
                            }
                            map.insert(id.to_string(), u.clone());
                        }
                    }
                }
                node_users.push((item.instance, map));
            },
            Ok(resp) => {
                let parsed = parse_or_raw(&resp.body);
                let err = parsed
                    .get("error")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("HTTP {}", resp.status.as_u16()));
                node_errors.push(serde_json::json!({
                    "instance": item.instance,
                    "status": resp.status.as_u16(),
                    "error": err,
                }));
            },
            Err(err) => {
                node_errors.push(serde_json::json!({
                    "instance": item.instance,
                    "status": StatusCode::BAD_GATEWAY.as_u16(),
                    "error": format!("{err:#}"),
                }));
            },
        }
    }

    let has_unreachable = !node_errors.is_empty();
    let mut aggregated = Vec::with_capacity(ordered_ids.len());

    for id in ordered_ids {
        let mut present_on = Vec::new();
        let mut missing_on = Vec::new();
        let mut per_node = BTreeMap::new();
        let mut sample: Option<Value> = None;

        for (node_name, map) in &node_users {
            if let Some(u) = map.get(&id) {
                present_on.push(node_name.clone());
                per_node.insert(node_name.clone(), u.clone());
                if sample.is_none() {
                    sample = Some(u.clone());
                }
            } else {
                missing_on.push(node_name.clone());
            }
        }

        let diff_fields = compute_user_diff_fields(&per_node);
        let sync_status = if has_unreachable {
            "unknown"
        } else if !missing_on.is_empty() {
            "partial"
        } else if !diff_fields.is_empty() {
            "drift"
        } else {
            "synced"
        };

        let rep = sample.unwrap_or(Value::Null);
        aggregated.push(serde_json::json!({
            "id": id,
            "enabled": rep.get("enabled").cloned().unwrap_or(Value::Bool(true)),
            "method": rep.get("method").cloned().unwrap_or(Value::Null),
            "fwmark": rep.get("fwmark").cloned().unwrap_or(Value::Null),
            "aliases": rep.get("aliases").cloned().unwrap_or(Value::Null),
            "has_password": rep.get("has_password").cloned().unwrap_or(Value::Bool(false)),
            "has_vless_id": rep.get("has_vless_id").cloned().unwrap_or(Value::Bool(false)),
            "password_fp": rep.get("password_fp").cloned().unwrap_or(Value::Null),
            "vless_id_fp": rep.get("vless_id_fp").cloned().unwrap_or(Value::Null),
            "sync_status": sync_status,
            "present_on": present_on,
            "missing_on": missing_on,
            "diff_fields": diff_fields,
            "per_node": per_node,
        }));
    }

    let status = if node_users.is_empty() && has_unreachable {
        StatusCode::BAD_GATEWAY
    } else {
        StatusCode::OK
    };

    json_response(
        status,
        &serde_json::json!({
            "cluster": cluster.name,
            "source": cluster.source,
            "members": cluster.members.iter().map(|m| &m.name).collect::<Vec<_>>(),
            "total_nodes": cluster.members.len(),
            "reachable_nodes": node_users.len(),
            "node_errors": node_errors,
            "users": aggregated,
        }),
    )
}

fn compute_user_diff_fields(per_node: &BTreeMap<String, Value>) -> Vec<String> {
    if per_node.len() < 2 {
        return Vec::new();
    }
    let fields: &[(&str, &str)] = &[
        ("enabled", "enabled"),
        ("method", "method"),
        ("fwmark", "fwmark"),
        ("aliases", "aliases"),
        ("has_password", "has_password"),
        ("has_vless_id", "has_vless_id"),
        ("password", "password_fp"),
        ("vless_id", "vless_id_fp"),
    ];
    let mut vals = per_node.values();
    let Some(first) = vals.next() else {
        return Vec::new();
    };
    let rest: Vec<&Value> = vals.collect();

    let mut diffs = Vec::new();
    for (label, key) in fields {
        let base = first.get(*key).cloned().unwrap_or(Value::Null);
        if rest
            .iter()
            .any(|v| v.get(*key).cloned().unwrap_or(Value::Null) != base)
        {
            diffs.push((*label).to_string());
        }
    }
    diffs
}

pub async fn create_user(
    State(state): State<SsState>,
    Path(cluster_name): Path<String>,
    body: Bytes,
) -> Response {
    let Some(cluster) = resolve_cluster(&state, &cluster_name).await else {
        return json_error(StatusCode::NOT_FOUND, "unknown cluster");
    };
    let mut payload: Map<String, Value> = match serde_json::from_slice(&body) {
        Ok(Value::Object(map)) => map,
        Ok(_) => return json_error(StatusCode::BAD_REQUEST, "expected JSON object"),
        Err(err) => return json_error(StatusCode::BAD_REQUEST, &format!("invalid JSON: {err}")),
    };
    let rollback_on_error = payload
        .remove("rollback_on_error")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let Some(user_id) = payload.get("id").and_then(Value::as_str).map(str::to_owned) else {
        return json_error(StatusCode::BAD_REQUEST, "missing user id");
    };
    if !is_valid_user_id(&user_id) {
        return json_error(StatusCode::BAD_REQUEST, "invalid user id");
    }

    // 1. Pre-flight: check all nodes are reachable and id is unused everywhere.
    let preflight = fan_out(&cluster.members, &state.backend, |_| {
        (Method::GET, "/control/users".to_string(), None)
    })
    .await;

    let mut unreachable = Vec::new();
    let mut present_on = Vec::new();
    for item in preflight {
        match item.result {
            Ok(resp) if resp.status.is_success() => {
                let parsed = parse_or_raw(&resp.body);
                if parsed.get("users").and_then(Value::as_array).is_some_and(|arr| {
                    arr.iter()
                        .any(|u| u.get("id").and_then(Value::as_str) == Some(&user_id))
                }) {
                    present_on.push(item.instance);
                }
            },
            Ok(resp) => {
                let parsed = parse_or_raw(&resp.body);
                let err = parsed
                    .get("error")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("HTTP {}", resp.status.as_u16()));
                unreachable.push(format!("{}: {err}", item.instance));
            },
            Err(err) => unreachable.push(format!("{err:#}")),
        }
    }

    if !unreachable.is_empty() {
        return json_response(
            StatusCode::BAD_GATEWAY,
            &serde_json::json!({
                "ok": false,
                "error": format!("cluster pre-flight failed: {}", unreachable.join("; ")),
            }),
        );
    }
    if !present_on.is_empty() {
        return json_response(
            StatusCode::CONFLICT,
            &serde_json::json!({
                "ok": false,
                "error": format!("user {:?} already exists on: {}", user_id, present_on.join(", ")),
                "present_on": present_on,
            }),
        );
    }

    // 2. Fan-out create
    let forward_body = Bytes::from(serde_json::to_vec(&payload).unwrap_or_default());
    let outcomes = fan_out(&cluster.members, &state.backend, |_| {
        (Method::POST, "/control/users".to_string(), Some(forward_body.clone()))
    })
    .await;

    let mut results: Vec<NodeActionResult> =
        outcomes.into_iter().map(outcome_to_action_result).collect();
    let all_ok = results.iter().all(|r| r.ok);
    if all_ok {
        return json_response(
            StatusCode::CREATED,
            &serde_json::json!({
                "ok": true,
                "id": user_id,
                "cluster": cluster.name,
                "results": results,
            }),
        );
    }

    // 3. Rollback on partial failure
    let created_instances: Vec<InstanceConfig> = results
        .iter()
        .filter(|r| r.ok)
        .filter_map(|r| instance_by_name(&state, &r.instance).cloned())
        .collect();

    let mut rollback_ok = true;
    if rollback_on_error && !created_instances.is_empty() {
        let del_path = format!("/control/users/{}", encode_path_segment(&user_id));
        let rollback_outcomes = fan_out(&created_instances, &state.backend, |_| {
            (Method::DELETE, del_path.clone(), None)
        })
        .await;

        let mut rb_status = HashMap::new();
        for item in rollback_outcomes {
            let ok = matches!(&item.result, Ok(resp) if resp.status.is_success() || resp.status == StatusCode::NOT_FOUND);
            if !ok {
                rollback_ok = false;
            }
            rb_status.insert(item.instance, ok);
        }
        for res in &mut results {
            if let Some(&ok) = rb_status.get(&res.instance) {
                res.rolled_back = Some(ok);
            }
        }
    }

    let status = if results
        .iter()
        .all(|r| !r.ok && r.status == StatusCode::BAD_REQUEST.as_u16())
    {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::BAD_GATEWAY
    };

    json_response(
        status,
        &serde_json::json!({
            "ok": false,
            "id": user_id,
            "cluster": cluster.name,
            "rolled_back": rollback_on_error && !created_instances.is_empty() && rollback_ok,
            "results": results,
        }),
    )
}

async fn fan_out_user_mutation(
    state: SsState,
    cluster_name: String,
    user_id: String,
    method: Method,
    suffix: &str,
    body: Option<Bytes>,
) -> Response {
    let Some(cluster) = resolve_cluster(&state, &cluster_name).await else {
        return json_error(StatusCode::NOT_FOUND, "unknown cluster");
    };
    if !is_valid_user_id(&user_id) {
        return json_error(StatusCode::BAD_REQUEST, "invalid user id");
    }
    let path = format!("/control/users/{}{suffix}", encode_path_segment(&user_id));
    let outcomes = fan_out(&cluster.members, &state.backend, |_| {
        (method.clone(), path.clone(), body.clone())
    })
    .await;

    let results: Vec<NodeActionResult> =
        outcomes.into_iter().map(outcome_to_action_result).collect();
    let all_ok = results.iter().all(|r| r.ok);
    let status = if all_ok {
        StatusCode::OK
    } else if results
        .iter()
        .all(|r| !r.ok && r.status == StatusCode::NOT_FOUND.as_u16())
    {
        StatusCode::NOT_FOUND
    } else if results
        .iter()
        .all(|r| !r.ok && r.status == StatusCode::BAD_REQUEST.as_u16())
    {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::BAD_GATEWAY
    };

    json_response(
        status,
        &serde_json::json!({
            "ok": all_ok,
            "id": user_id,
            "cluster": cluster.name,
            "results": results,
        }),
    )
}

pub async fn update_user(
    State(state): State<SsState>,
    Path((cluster_name, id)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    fan_out_user_mutation(state, cluster_name, id, Method::PATCH, "", Some(body)).await
}

pub async fn block_user(
    State(state): State<SsState>,
    Path((cluster_name, id)): Path<(String, String)>,
) -> Response {
    fan_out_user_mutation(state, cluster_name, id, Method::POST, "/block", None).await
}

pub async fn unblock_user(
    State(state): State<SsState>,
    Path((cluster_name, id)): Path<(String, String)>,
) -> Response {
    fan_out_user_mutation(state, cluster_name, id, Method::POST, "/unblock", None).await
}

pub async fn delete_user(
    State(state): State<SsState>,
    Path((cluster_name, id)): Path<(String, String)>,
) -> Response {
    let Some(cluster) = resolve_cluster(&state, &cluster_name).await else {
        return json_error(StatusCode::NOT_FOUND, "unknown cluster");
    };
    if !is_valid_user_id(&id) {
        return json_error(StatusCode::BAD_REQUEST, "invalid user id");
    }
    let path = format!("/control/users/{}", encode_path_segment(&id));
    let outcomes =
        fan_out(&cluster.members, &state.backend, |_| (Method::DELETE, path.clone(), None)).await;

    let mut results = Vec::with_capacity(outcomes.len());
    for item in outcomes {
        match item.result {
            Ok(resp) if resp.status == StatusCode::NOT_FOUND => {
                results.push(NodeActionResult {
                    instance: item.instance,
                    ok: true,
                    status: StatusCode::NOT_FOUND.as_u16(),
                    requires_restart: None,
                    already_absent: Some(true),
                    rolled_back: None,
                    error: None,
                    data: None,
                });
            },
            _ => results.push(outcome_to_action_result(item)),
        }
    }

    let all_ok = results.iter().all(|r| r.ok);
    let status = if all_ok {
        StatusCode::OK
    } else {
        StatusCode::BAD_GATEWAY
    };
    json_response(
        status,
        &serde_json::json!({
            "ok": all_ok,
            "id": id,
            "cluster": cluster.name,
            "results": results,
        }),
    )
}

pub async fn regenerate_access_keys(
    State(state): State<SsState>,
    Path(cluster_name): Path<String>,
    body: Bytes,
) -> Response {
    let Some(cluster) = resolve_cluster(&state, &cluster_name).await else {
        return json_error(StatusCode::NOT_FOUND, "unknown cluster");
    };
    let req: RegenerateClusterRequest = if body.is_empty() {
        RegenerateClusterRequest::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(err) => {
                return json_error(StatusCode::BAD_REQUEST, &format!("invalid JSON: {err}"));
            },
        }
    };

    let effective_nodes = match req.nodes {
        Some(list) if !list.is_empty() => Some(list),
        Some(_) => return json_error(StatusCode::BAD_REQUEST, "nodes must not be empty"),
        None if !cluster.subscription_nodes.is_empty() => Some(cluster.subscription_nodes.clone()),
        None => None,
    };

    let mut payload = Map::new();
    payload.insert("prune".to_string(), Value::Bool(req.prune.unwrap_or(true)));
    if let Some(nodes) = &effective_nodes {
        payload.insert(
            "nodes".to_string(),
            Value::Array(nodes.iter().cloned().map(Value::String).collect()),
        );
    }
    let body_bytes = Bytes::from(serde_json::to_vec(&payload).unwrap_or_default());

    let outcomes = fan_out(&cluster.members, &state.backend, |_| {
        (
            Method::POST,
            "/control/access-keys/regenerate".to_string(),
            Some(body_bytes.clone()),
        )
    })
    .await;

    let results: Vec<NodeActionResult> =
        outcomes.into_iter().map(outcome_to_action_result).collect();
    let all_ok = results.iter().all(|r| r.ok);
    let status = if all_ok {
        StatusCode::OK
    } else if results
        .iter()
        .all(|r| !r.ok && r.status == StatusCode::NOT_IMPLEMENTED.as_u16())
    {
        StatusCode::NOT_IMPLEMENTED
    } else {
        StatusCode::BAD_GATEWAY
    };

    json_response(
        status,
        &serde_json::json!({
            "ok": all_ok,
            "cluster": cluster.name,
            "nodes": effective_nodes,
            "results": results,
        }),
    )
}

pub async fn get_user_access_keys(
    State(state): State<SsState>,
    Path((cluster_name, id)): Path<(String, String)>,
    Query(query): Query<ClusterAccessKeysQuery>,
) -> Response {
    let Some(cluster) = resolve_cluster(&state, &cluster_name).await else {
        return json_error(StatusCode::NOT_FOUND, "unknown cluster");
    };
    if !is_valid_user_id(&id) {
        return json_error(StatusCode::BAD_REQUEST, "invalid user id");
    }

    let query_nodes = parse_nodes_query(query.nodes.as_deref());
    let shared_nodes = query_nodes.or_else(|| {
        (!cluster.subscription_nodes.is_empty()).then(|| cluster.subscription_nodes.clone())
    });

    let target_path = build_access_keys_path(&id, shared_nodes.as_deref());
    let outcomes =
        fan_out(&cluster.members, &state.backend, |_| (Method::GET, target_path.clone(), None))
            .await;

    if shared_nodes.is_some() {
        // Cluster-wide balanced subscription: any live healthy node renders the same bundle.
        let mut results = Vec::with_capacity(outcomes.len());
        let mut best_payload: Option<(String, Value)> = None;
        let mut best_error_status: Option<StatusCode> = None;

        for item in outcomes {
            let res = outcome_to_action_result(item);
            if res.ok
                && best_payload.is_none()
                && let Some(data) = res.data.clone()
            {
                best_payload = Some((res.instance.clone(), data));
            } else if !res.ok && best_error_status.is_none() {
                best_error_status = StatusCode::from_u16(res.status).ok();
            }
            results.push(res);
        }

        if let Some((source_node, mut payload)) = best_payload {
            if let Value::Object(map) = &mut payload {
                map.insert("mode".to_string(), Value::String("cluster".to_string()));
                map.insert("source_node".to_string(), Value::String(source_node));
            }
            return json_response(StatusCode::OK, &payload);
        }

        let status = best_error_status.unwrap_or(StatusCode::BAD_GATEWAY);
        let msg = results
            .iter()
            .find_map(|r| r.error.as_deref())
            .unwrap_or("failed to fetch access keys");
        return json_response(
            status,
            &serde_json::json!({
                "error": msg,
                "results": results,
            }),
        );
    }

    // Per-node mode (e.g. exit nodes without a shared subscription balancer).
    let results: Vec<NodeActionResult> =
        outcomes.into_iter().map(outcome_to_action_result).collect();
    let any_ok = results.iter().any(|r| r.ok);
    if !any_ok {
        let status = results
            .iter()
            .find_map(|r| StatusCode::from_u16(r.status).ok())
            .unwrap_or(StatusCode::BAD_GATEWAY);
        let msg = results
            .iter()
            .find_map(|r| r.error.as_deref())
            .unwrap_or("failed to fetch access keys");
        return json_response(status, &serde_json::json!({ "error": msg, "results": results }));
    }

    let mut share_links = Vec::new();
    let mut seen_links = HashSet::new();
    let mut warnings = Vec::new();
    let mut nodes_out = Vec::with_capacity(results.len());

    for r in &results {
        if let Some(data) = &r.data {
            if let Some(links) = data.get("share_links").and_then(Value::as_array) {
                for l in links {
                    if let Some(s) = l.as_str()
                        && seen_links.insert(s.to_string())
                    {
                        share_links.push(s.to_string());
                    }
                }
            }
            if let Some(ws) = data.get("warnings").and_then(Value::as_array) {
                for w in ws {
                    if let Some(s) = w.as_str() {
                        warnings.push(format!("{}: {s}", r.instance));
                    }
                }
            }
        }
        nodes_out.push(serde_json::json!({
            "instance": r.instance,
            "ok": r.ok,
            "status": r.status,
            "links": r.data,
            "error": r.error,
        }));
    }

    json_response(
        StatusCode::OK,
        &serde_json::json!({
            "mode": "per_node",
            "user": id,
            "enabled": true,
            "share_links": share_links,
            "warnings": warnings,
            "nodes": nodes_out,
        }),
    )
}
