use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use tokio::fs;
use tracing::warn;
use url::Url;

use crate::types::{CipherKind, UplinkTransport, WsTransportMode};

use super::args::Args;
use super::schema::{
    ConfigFile, H2Section, LoadBalancingSection, OutlineSection, ProbeSection, RouteSection,
    UplinkGroupSection, UplinkSection, resolve_outline_section,
};
#[cfg(feature = "tun")]
use super::schema::TunSection;
use super::types::{
    AppConfig, DnsProbeConfig, H2Config, HttpProbeConfig, LoadBalancingConfig, LoadBalancingMode,
    MetricsConfig, ProbeConfig, RouteRule, RouteTarget, RoutingScope, RoutingTableConfig,
    Socks5AuthConfig, Socks5AuthUserConfig, TcpProbeConfig, UplinkConfig, UplinkGroupConfig,
    WsProbeConfig,
};
#[cfg(feature = "tun")]
use super::types::{TunConfig, TunTcpConfig};

pub async fn load_config(path: &Path, args: &Args) -> Result<AppConfig> {
    let file = if path.exists() {
        let raw = fs::read_to_string(path)
            .await
            .with_context(|| format!("failed to read {}", path.display()))?;
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        Some(match ext {
            "yaml" | "yml" => serde_yml::from_str::<ConfigFile>(&raw)
                .with_context(|| format!("failed to parse {}", path.display()))?,
            _ => toml::from_str::<ConfigFile>(&raw)
                .with_context(|| format!("failed to parse {}", path.display()))?,
        })
    } else {
        None
    };

    let socks5 = file.as_ref().and_then(|f| f.socks5.as_ref());
    let outline = file.as_ref().and_then(resolve_outline_section);
    let metrics_section = file.as_ref().and_then(|f| f.metrics.as_ref());
    #[cfg(feature = "tun")]
    let tun_section = file.as_ref().and_then(|f| f.tun.as_ref());
    let h2_section = file.as_ref().and_then(|f| f.h2.as_ref());
    let udp_recv_buf_bytes = file.as_ref().and_then(|f| f.udp_recv_buf_bytes);
    let udp_send_buf_bytes = file.as_ref().and_then(|f| f.udp_send_buf_bytes);

    let listen = args.listen.or_else(|| socks5.and_then(|s| s.listen));
    let socks5_auth = load_socks5_auth_config(socks5, args)?;

    let config_dir = path.parent().unwrap_or_else(|| Path::new("."));

    let groups = load_groups(outline.as_ref(), file.as_ref(), args)?;
    let routing = load_routing_table(file.as_ref(), &groups, config_dir)?;

    let metrics = args
        .metrics_listen
        .or_else(|| metrics_section.and_then(|section| section.listen))
        .map(|listen| MetricsConfig { listen });
    #[cfg(feature = "tun")]
    let tun = load_tun_config(tun_section, args)?;
    let h2 = load_h2_config(h2_section);

    #[cfg(feature = "tun")]
    if listen.is_none() && tun.is_none() {
        bail!("no ingress configured: set --listen / [socks5].listen and/or configure [tun]");
    }
    #[cfg(not(feature = "tun"))]
    if listen.is_none() {
        bail!("no ingress configured: set --listen / [socks5].listen");
    }

    let direct_fwmark = file.as_ref().and_then(|f| f.direct_fwmark);

    // State file path priority: CLI flag > config key > default (config
    // path with extension replaced by ".state.toml"). Relative paths in
    // the config file are resolved against the config directory (not CWD);
    // `..` components are rejected to keep the path predictable.
    let state_path = if let Some(p) = args.state_path.clone() {
        Some(p)
    } else if let Some(p) = file.as_ref().and_then(|f| f.state_path.clone()) {
        Some(resolve_config_path(&p, config_dir).context("invalid [state_path]")?)
    } else {
        Some(path.with_extension("state.toml"))
    };

    Ok(AppConfig {
        listen,
        socks5_auth,
        groups,
        routing,
        routing_table: None,
        metrics,
        #[cfg(feature = "tun")]
        tun,
        h2,
        udp_recv_buf_bytes,
        udp_send_buf_bytes,
        direct_fwmark,
        state_path,
    })
}

fn load_socks5_auth_config(
    socks5: Option<&super::schema::Socks5Section>,
    args: &Args,
) -> Result<Option<Socks5AuthConfig>> {
    let cli_username = args.socks5_username.clone();
    let cli_password = args.socks5_password.clone();

    if cli_username.is_some() || cli_password.is_some() {
        return match (cli_username, cli_password) {
            (Some(username), Some(password)) => Ok(Some(Socks5AuthConfig {
                users: vec![validate_socks5_auth_user(
                    Socks5AuthUserConfig { username, password },
                    "CLI socks5 auth user",
                )?],
            })),
            (Some(_), None) => {
                bail!(
                    "missing socks5 password: pass --socks5-password together with --socks5-username"
                )
            },
            (None, Some(_)) => {
                bail!(
                    "missing socks5 username: pass --socks5-username together with --socks5-password"
                )
            },
            (None, None) => unreachable!("checked above"),
        };
    }

    let Some(socks5) = socks5 else {
        return Ok(None);
    };

    let users = match (&socks5.users, &socks5.username, &socks5.password) {
        (Some(users), None, None) => users
            .iter()
            .enumerate()
            .map(|(index, user)| {
                let username = user.username.clone().ok_or_else(|| {
                    anyhow!("missing socks5 user username in [socks5].users entry {}", index + 1)
                })?;
                let password = user.password.clone().ok_or_else(|| {
                    anyhow!("missing socks5 user password in [socks5].users entry {}", index + 1)
                })?;
                validate_socks5_auth_user(
                    Socks5AuthUserConfig { username, password },
                    &format!("socks5 user {}", index + 1),
                )
            })
            .collect::<Result<Vec<_>>>()?,
        (Some(_), Some(_), _) | (Some(_), _, Some(_)) => {
            bail!(
                "use either [socks5].username/password for a single user or [[socks5.users]] for multiple users, not both"
            )
        },
        (None, Some(username), Some(password)) => vec![validate_socks5_auth_user(
            Socks5AuthUserConfig {
                username: username.clone(),
                password: password.clone(),
            },
            "socks5 auth user",
        )?],
        (None, Some(_), None) => {
            bail!("missing socks5 password: set [socks5].password together with [socks5].username")
        },
        (None, None, Some(_)) => {
            bail!("missing socks5 username: set [socks5].username together with [socks5].password")
        },
        (None, None, None) => Vec::new(),
    };

    if users.is_empty() {
        return Ok(None);
    }

    Ok(Some(Socks5AuthConfig { users }))
}

fn validate_socks5_auth_user(
    user: Socks5AuthUserConfig,
    context_label: &str,
) -> Result<Socks5AuthUserConfig> {
    if user.username.len() > u8::MAX as usize {
        bail!("{context_label} username is too long; maximum is 255 bytes");
    }
    if user.password.len() > u8::MAX as usize {
        bail!("{context_label} password is too long; maximum is 255 bytes");
    }
    Ok(user)
}

#[derive(Debug, Clone)]
struct ResolvedUplinkInput {
    name: String,
    transport: UplinkTransport,
    tcp_ws_url: Option<Url>,
    tcp_ws_mode: Option<WsTransportMode>,
    udp_ws_url: Option<Url>,
    udp_ws_mode: Option<WsTransportMode>,
    tcp_addr: Option<crate::types::ServerAddr>,
    udp_addr: Option<crate::types::ServerAddr>,
    cipher: Option<CipherKind>,
    password: Option<String>,
    weight: Option<f64>,
    fwmark: Option<u32>,
    ipv6_first: Option<bool>,
}

impl ResolvedUplinkInput {
    fn from_cli(args: &Args, outline: Option<&OutlineSection>) -> Self {
        Self {
            name: "cli".to_string(),
            transport: args
                .transport
                .or_else(|| outline.and_then(|section| section.transport))
                .unwrap_or_default(),
            tcp_ws_url: args
                .tcp_ws_url
                .clone()
                .or_else(|| outline.and_then(|section| section.tcp_ws_url.clone())),
            tcp_ws_mode: args
                .tcp_ws_mode
                .or_else(|| outline.and_then(|section| section.tcp_ws_mode)),
            udp_ws_url: args
                .udp_ws_url
                .clone()
                .or_else(|| outline.and_then(|section| section.udp_ws_url.clone())),
            udp_ws_mode: args
                .udp_ws_mode
                .or_else(|| outline.and_then(|section| section.udp_ws_mode)),
            tcp_addr: args
                .tcp_addr
                .clone()
                .or_else(|| outline.and_then(|section| section.tcp_addr.clone())),
            udp_addr: args
                .udp_addr
                .clone()
                .or_else(|| outline.and_then(|section| section.udp_addr.clone())),
            cipher: args.method.or_else(|| outline.and_then(|section| section.method)),
            password: args
                .password
                .clone()
                .or_else(|| outline.and_then(|section| section.password.clone())),
            weight: Some(1.0),
            fwmark: args.fwmark.or_else(|| outline.and_then(|section| section.fwmark)),
            ipv6_first: args
                .ipv6_first
                .or_else(|| outline.and_then(|section| section.ipv6_first)),
        }
    }

    fn from_section(index: usize, uplink: &UplinkSection) -> Self {
        Self {
            name: uplink.name.clone().unwrap_or_else(|| format!("uplink-{}", index + 1)),
            transport: uplink.transport.unwrap_or_default(),
            tcp_ws_url: uplink.tcp_ws_url.clone(),
            tcp_ws_mode: uplink.tcp_ws_mode,
            udp_ws_url: uplink.udp_ws_url.clone(),
            udp_ws_mode: uplink.udp_ws_mode,
            tcp_addr: uplink.tcp_addr.clone(),
            udp_addr: uplink.udp_addr.clone(),
            cipher: uplink.method,
            password: uplink.password.clone(),
            weight: uplink.weight,
            fwmark: uplink.fwmark,
            ipv6_first: uplink.ipv6_first,
        }
    }

    fn from_outline_default(outline: Option<&OutlineSection>) -> Self {
        Self {
            name: "default".to_string(),
            transport: outline.and_then(|section| section.transport).unwrap_or_default(),
            tcp_ws_url: outline.and_then(|section| section.tcp_ws_url.clone()),
            tcp_ws_mode: outline.and_then(|section| section.tcp_ws_mode),
            udp_ws_url: outline.and_then(|section| section.udp_ws_url.clone()),
            udp_ws_mode: outline.and_then(|section| section.udp_ws_mode),
            tcp_addr: outline.and_then(|section| section.tcp_addr.clone()),
            udp_addr: outline.and_then(|section| section.udp_addr.clone()),
            cipher: outline.and_then(|section| section.method),
            password: outline.and_then(|section| section.password.clone()),
            weight: Some(1.0),
            fwmark: outline.and_then(|section| section.fwmark),
            ipv6_first: outline.and_then(|section| section.ipv6_first),
        }
    }
}

impl TryFrom<ResolvedUplinkInput> for UplinkConfig {
    type Error = anyhow::Error;

    fn try_from(input: ResolvedUplinkInput) -> Result<Self> {
        let ResolvedUplinkInput {
            name,
            transport,
            tcp_ws_url,
            tcp_ws_mode,
            udp_ws_url,
            udp_ws_mode,
            tcp_addr,
            udp_addr,
            cipher,
            password,
            weight,
            fwmark,
            ipv6_first,
        } = input;

        let weight = weight.unwrap_or(1.0);
        if !weight.is_finite() || weight <= 0.0 {
            bail!("uplink weight must be a finite positive number");
        }
        let cipher = cipher.unwrap_or(CipherKind::Chacha20IetfPoly1305);
        let password = password
            .ok_or_else(|| anyhow!("missing password: set it in config.toml or pass --password"))?;
        cipher
            .derive_master_key(&password)
            .with_context(|| format!("invalid password/PSK for cipher {cipher}"))?;

        Ok(UplinkConfig {
            name,
            transport,
            tcp_ws_url: match transport {
                UplinkTransport::Websocket => Some(tcp_ws_url.ok_or_else(|| {
                    anyhow!("missing tcp_ws_url: set it in config.toml or pass --tcp-ws-url")
                })?),
                UplinkTransport::Shadowsocks => {
                    if tcp_ws_url.is_some() || udp_ws_url.is_some() {
                        bail!(
                            "websocket uplink fields are not valid for transport=shadowsocks; use tcp_addr/udp_addr"
                        );
                    }
                    None
                },
            },
            tcp_ws_mode: tcp_ws_mode.unwrap_or_default(),
            udp_ws_url: match transport {
                UplinkTransport::Websocket => udp_ws_url,
                UplinkTransport::Shadowsocks => None,
            },
            udp_ws_mode: udp_ws_mode.unwrap_or_default(),
            tcp_addr: match transport {
                UplinkTransport::Websocket => {
                    if tcp_addr.is_some() || udp_addr.is_some() {
                        bail!(
                            "socket uplink fields are not valid for transport=websocket; use tcp_ws_url/udp_ws_url"
                        );
                    }
                    None
                },
                UplinkTransport::Shadowsocks => Some(tcp_addr.ok_or_else(|| {
                    anyhow!("missing tcp_addr: set it in config.toml or pass --tcp-addr")
                })?),
            },
            udp_addr: match transport {
                UplinkTransport::Websocket => None,
                UplinkTransport::Shadowsocks => udp_addr,
            },
            cipher,
            password,
            weight,
            fwmark,
            ipv6_first: ipv6_first.unwrap_or(false),
        })
    }
}

fn load_uplinks(outline: Option<&OutlineSection>, args: &Args) -> Result<Vec<UplinkConfig>> {
    let cli_override_requested = args.tcp_ws_url.is_some()
        || args.transport.is_some()
        || args.tcp_ws_mode.is_some()
        || args.udp_ws_url.is_some()
        || args.udp_ws_mode.is_some()
        || args.tcp_addr.is_some()
        || args.udp_addr.is_some()
        || args.method.is_some()
        || args.password.is_some()
        || args.fwmark.is_some()
        || args.ipv6_first.is_some();

    if cli_override_requested {
        return Ok(vec![ResolvedUplinkInput::from_cli(args, outline).try_into()?]);
    }

    if let Some(uplinks) = outline.and_then(|o| o.uplinks.as_ref()) {
        let resolved = uplinks
            .iter()
            .enumerate()
            .map(|(index, uplink)| ResolvedUplinkInput::from_section(index, uplink).try_into())
            .collect::<Result<Vec<_>>>()?;
        if resolved.is_empty() {
            bail!("uplinks is present but empty");
        }
        return Ok(resolved);
    }

    Ok(vec![ResolvedUplinkInput::from_outline_default(outline).try_into()?])
}

// ── New config: uplink groups + policy routes ─────────────────────────────────

const DIRECT_TARGET: &str = "direct";
const DROP_TARGET: &str = "drop";
const DEFAULT_GROUP: &str = "default";

/// Build the full set of uplink groups.
///
/// - New shape (`[[uplink_group]]` present): each group gets its own LB + probe
///   config (probe merged from top-level `[probe]` template). Every uplink must
///   carry a `group = "…"` field referencing a declared group.
/// - Legacy shape: a single synthetic `default` group is built from the
///   existing top-level `[load_balancing]` + `[probe]` + `[[uplinks]]` (or CLI
///   overrides / `[outline]`).
fn load_groups(
    outline: Option<&OutlineSection>,
    file: Option<&ConfigFile>,
    args: &Args,
) -> Result<Vec<UplinkGroupConfig>> {
    let group_sections = file.and_then(|f| f.uplink_group.as_ref());
    if group_sections.is_none_or(|v| v.is_empty()) {
        // Legacy single-group path — reuse existing flat-config logic.
        let uplinks = load_uplinks(outline, args)?;
        let probe = load_probe_config(outline.and_then(|o| o.probe.as_ref()))?;
        let load_balancing = load_balancing_config(outline.and_then(|o| o.load_balancing.as_ref()))?;
        return Ok(vec![UplinkGroupConfig {
            name: DEFAULT_GROUP.to_string(),
            uplinks,
            probe,
            load_balancing,
        }]);
    }

    let sections = group_sections.expect("checked above");
    let probe_template = outline.and_then(|o| o.probe.as_ref()).cloned();

    // Each group becomes a distinct `group` label on every uplink-scoped
    // Prometheus metric; unbounded groups would blow up series cardinality
    // (and with it, scrape memory / disk). Cap well above any realistic
    // deployment (10s of groups at most) but below where cardinality harms.
    const MAX_UPLINK_GROUPS: usize = 64;
    if sections.len() > MAX_UPLINK_GROUPS {
        bail!(
            "too many [[uplink_group]] entries ({}); maximum is {MAX_UPLINK_GROUPS} \
             to bound metric label cardinality",
            sections.len()
        );
    }

    // Validate group names. `name_to_index` gives O(1) duplicate detection
    // here and O(1) lookups further down (per-uplink `group` → index),
    // avoiding what would otherwise be a quadratic scan over uplinks×groups.
    let mut names: Vec<String> = Vec::with_capacity(sections.len());
    let mut name_to_index: std::collections::HashMap<String, usize> =
        std::collections::HashMap::with_capacity(sections.len());
    for (index, section) in sections.iter().enumerate() {
        let name = section
            .name
            .clone()
            .ok_or_else(|| anyhow!("[[uplink_group]] entry {} is missing `name`", index + 1))?;
        if name.is_empty() {
            bail!("[[uplink_group]] entry {} has empty name", index + 1);
        }
        if name.eq_ignore_ascii_case(DIRECT_TARGET) || name.eq_ignore_ascii_case(DROP_TARGET) {
            bail!("[[uplink_group]].name = \"{name}\" is reserved; pick another name");
        }
        if name_to_index.insert(name.clone(), index).is_some() {
            bail!("duplicate [[uplink_group]] name: {name}");
        }
        names.push(name);
    }

    // Uplinks in new-shape config must live under `outline.uplinks` and carry
    // a `group` field. CLI override still lands everything in the first group
    // (single-uplink CLI convenience).
    let cli_override_requested = args.tcp_ws_url.is_some()
        || args.transport.is_some()
        || args.tcp_ws_mode.is_some()
        || args.udp_ws_url.is_some()
        || args.udp_ws_mode.is_some()
        || args.tcp_addr.is_some()
        || args.udp_addr.is_some()
        || args.method.is_some()
        || args.password.is_some()
        || args.fwmark.is_some()
        || args.ipv6_first.is_some();
    if cli_override_requested {
        bail!(
            "CLI uplink overrides (--tcp-ws-url / --password / …) are not supported together \
             with [[uplink_group]]: declare the uplink in `[[uplinks]]` instead"
        );
    }

    let uplink_sections = outline.and_then(|o| o.uplinks.as_ref()).cloned().unwrap_or_default();
    if uplink_sections.is_empty() {
        bail!("[[uplink_group]] declared but no [[uplinks]] provided");
    }

    // Group uplinks by their `group` field.
    let mut buckets: Vec<Vec<UplinkConfig>> = vec![Vec::new(); names.len()];
    for (index, uplink) in uplink_sections.iter().enumerate() {
        let group_name = uplink.group.as_ref().ok_or_else(|| {
            anyhow!(
                "[[uplinks]] entry {} is missing `group` (required when [[uplink_group]] is used)",
                index + 1
            )
        })?;
        let group_index = *name_to_index.get(group_name.as_str()).ok_or_else(|| {
            anyhow!(
                "[[uplinks]] entry {} references unknown group \"{group_name}\"",
                index + 1
            )
        })?;
        let resolved: UplinkConfig = ResolvedUplinkInput::from_section(index, uplink).try_into()?;
        buckets[group_index].push(resolved);
    }
    for (name, bucket) in names.iter().zip(&buckets) {
        if bucket.is_empty() {
            bail!("uplink group \"{name}\" has no uplinks assigned");
        }
    }

    // Build each UplinkGroupConfig with merged probe + LB.
    let mut groups = Vec::with_capacity(sections.len());
    for ((section, name), bucket) in sections.iter().zip(names.iter()).zip(buckets.into_iter()) {
        let merged_probe = merge_probe_section(probe_template.as_ref(), section.probe.as_ref());
        let probe = load_probe_config(merged_probe.as_ref())?;
        let load_balancing = load_balancing_config_from_group(section)?;
        groups.push(UplinkGroupConfig {
            name: name.clone(),
            uplinks: bucket,
            probe,
            load_balancing,
        });
    }

    Ok(groups)
}

/// Field-by-field merge of a probe template with a per-group override.
/// Sub-tables (ws/http/dns/tcp) are replaced whole-sale — if the group
/// overrides `[uplink_group.probe.http]`, the template's `[probe.http]` is
/// dropped entirely, not merged field-by-field.
fn merge_probe_section(
    template: Option<&ProbeSection>,
    override_: Option<&ProbeSection>,
) -> Option<ProbeSection> {
    match (template, override_) {
        (None, None) => None,
        (Some(t), None) => Some(t.clone()),
        (None, Some(o)) => Some(o.clone()),
        (Some(t), Some(o)) => Some(ProbeSection {
            interval_secs: o.interval_secs.or(t.interval_secs),
            timeout_secs: o.timeout_secs.or(t.timeout_secs),
            max_concurrent: o.max_concurrent.or(t.max_concurrent),
            max_dials: o.max_dials.or(t.max_dials),
            min_failures: o.min_failures.or(t.min_failures),
            attempts: o.attempts.or(t.attempts),
            ws: o.ws.clone().or_else(|| t.ws.clone()),
            http: o.http.clone().or_else(|| t.http.clone()),
            dns: o.dns.clone().or_else(|| t.dns.clone()),
            tcp: o.tcp.clone().or_else(|| t.tcp.clone()),
        }),
    }
}

/// Adapter: build a `LoadBalancingConfig` from the LB fields embedded in
/// `[[uplink_group]]` (same field names / defaults as legacy
/// `[load_balancing]`).
fn load_balancing_config_from_group(
    section: &UplinkGroupSection,
) -> Result<LoadBalancingConfig> {
    let shim = LoadBalancingSection {
        mode: section.mode,
        routing_scope: section.routing_scope,
        sticky_ttl_secs: section.sticky_ttl_secs,
        hysteresis_ms: section.hysteresis_ms,
        failure_cooldown_secs: section.failure_cooldown_secs,
        tcp_chunk0_failover_timeout_secs: section.tcp_chunk0_failover_timeout_secs,
        warm_standby_tcp: section.warm_standby_tcp,
        warm_standby_udp: section.warm_standby_udp,
        rtt_ewma_alpha: section.rtt_ewma_alpha,
        failure_penalty_ms: section.failure_penalty_ms,
        failure_penalty_max_ms: section.failure_penalty_max_ms,
        failure_penalty_halflife_secs: section.failure_penalty_halflife_secs,
        h3_downgrade_secs: section.h3_downgrade_secs,
        udp_ws_keepalive_secs: section.udp_ws_keepalive_secs,
        tcp_ws_standby_keepalive_secs: section.tcp_ws_standby_keepalive_secs,
        tcp_active_keepalive_secs: section.tcp_active_keepalive_secs,
        auto_failback: section.auto_failback,
    };
    load_balancing_config(Some(&shim))
}

/// Parse the `[[route]]` list into a `RoutingTableConfig`.
///
/// Returns `Ok(None)` when no `[[route]]` is declared (no routing table declared).
/// Otherwise validates:
/// - exactly one rule has `default = true` (and it has no prefixes/file);
/// - non-default rules have `prefixes` and/or `file`;
/// - `via` references a declared group or the reserved `direct`/`drop`;
/// - at most one of `fallback_via`/`fallback_direct`/`fallback_drop` is set.
fn load_routing_table(
    file: Option<&ConfigFile>,
    groups: &[UplinkGroupConfig],
    config_dir: &Path,
) -> Result<Option<RoutingTableConfig>> {
    let Some(route_sections) = file.and_then(|f| f.route.as_ref()) else {
        return Ok(None);
    };
    // An explicit but empty `[[route]]` array is almost certainly a config
    // mistake (e.g. `route = []` in YAML, or all entries commented out) —
    // silently dropping it would leave the proxy routing everything through
    // the default group with no visible diagnostic. Fail loudly instead.
    if route_sections.is_empty() {
        bail!(
            "`[[route]]` section is present but empty; remove it entirely to \
             disable policy routing, or add at least one rule (including a \
             `default = true` entry)"
        );
    }

    let group_names: Vec<&str> = groups.iter().map(|g| g.name.as_str()).collect();

    let mut rules: Vec<RouteRule> = Vec::new();
    let mut default_target: Option<RouteTarget> = None;
    let mut default_fallback: Option<RouteTarget> = None;

    for (index, section) in route_sections.iter().enumerate() {
        let target = parse_route_target(
            section.via.as_deref(),
            &group_names,
            &format!("[[route]] entry {}", index + 1),
        )?;
        let fallback =
            parse_route_fallback(section, &group_names, &format!("[[route]] entry {}", index + 1))?;

        let is_default = section.default.unwrap_or(false);
        let has_prefixes = section.prefixes.as_ref().is_some_and(|v| !v.is_empty());
        let has_file = section.file.is_some();

        if is_default {
            if has_prefixes || has_file {
                bail!(
                    "[[route]] entry {} has `default = true` and must not set prefixes/file",
                    index + 1
                );
            }
            if default_target.is_some() {
                bail!("multiple [[route]] entries have `default = true`");
            }
            default_target = Some(target);
            default_fallback = fallback;
        } else {
            if !has_prefixes && !has_file {
                bail!(
                    "[[route]] entry {} must set `prefixes` and/or `file` (or `default = true`)",
                    index + 1
                );
            }
            let resolved_file = section
                .file
                .as_deref()
                .map(|p| {
                    resolve_config_path(p, config_dir).with_context(|| {
                        format!("invalid file in [[route]] entry {}", index + 1)
                    })
                })
                .transpose()?;
            rules.push(RouteRule {
                inline_prefixes: section.prefixes.clone().unwrap_or_default(),
                file: resolved_file,
                file_poll: Duration::from_secs(section.file_poll_secs.unwrap_or(60)),
                target,
                fallback,
                invert: section.invert.unwrap_or(false),
            });
        }
    }

    let default_target = default_target.ok_or_else(|| {
        anyhow!(
            "[[route]] is declared but no entry has `default = true`; add one to match unlisted traffic"
        )
    })?;

    Ok(Some(RoutingTableConfig {
        rules,
        default_target,
        default_fallback,
    }))
}

/// Resolve a path from the config file:
/// - reject any `..` component (defense-in-depth against pointing the
///   process at files outside the config tree);
/// - if absolute, return it verbatim;
/// - if relative, anchor it at the config file's directory (so it doesn't
///   silently depend on the process's working directory).
fn resolve_config_path(raw: &Path, config_dir: &Path) -> Result<PathBuf> {
    for comp in raw.components() {
        if matches!(comp, Component::ParentDir) {
            bail!(
                "path {} must not contain `..` components",
                raw.display()
            );
        }
    }
    if raw.is_absolute() {
        Ok(raw.to_path_buf())
    } else {
        Ok(config_dir.join(raw))
    }
}

fn parse_route_target(
    via: Option<&str>,
    group_names: &[&str],
    context: &str,
) -> Result<RouteTarget> {
    let via = via.ok_or_else(|| anyhow!("{context} is missing `via`"))?;
    route_target_from_name(via, group_names, context)
}

fn parse_route_fallback(
    section: &RouteSection,
    group_names: &[&str],
    context: &str,
) -> Result<Option<RouteTarget>> {
    let count = usize::from(section.fallback_via.is_some())
        + usize::from(section.fallback_direct.unwrap_or(false))
        + usize::from(section.fallback_drop.unwrap_or(false));
    if count > 1 {
        bail!(
            "{context} has multiple fallbacks set; pick at most one of \
             fallback_via / fallback_direct / fallback_drop"
        );
    }
    if let Some(name) = section.fallback_via.as_deref() {
        return Ok(Some(route_target_from_name(name, group_names, context)?));
    }
    if section.fallback_direct.unwrap_or(false) {
        return Ok(Some(RouteTarget::Direct));
    }
    if section.fallback_drop.unwrap_or(false) {
        return Ok(Some(RouteTarget::Drop));
    }
    Ok(None)
}

fn route_target_from_name(
    name: &str,
    group_names: &[&str],
    context: &str,
) -> Result<RouteTarget> {
    if name.eq_ignore_ascii_case(DIRECT_TARGET) {
        return Ok(RouteTarget::Direct);
    }
    if name.eq_ignore_ascii_case(DROP_TARGET) {
        return Ok(RouteTarget::Drop);
    }
    if group_names.iter().any(|g| *g == name) {
        return Ok(RouteTarget::Group(name.to_string()));
    }
    bail!(
        "{context}: via = \"{name}\" does not match any declared group; \
         known groups: {:?} (plus reserved `direct`, `drop`)",
        group_names
    )
}

fn load_probe_config(probe: Option<&ProbeSection>) -> Result<ProbeConfig> {
    let http = probe
        .and_then(|p| p.http.as_ref())
        .map(|http| HttpProbeConfig { url: http.url.clone() });
    let dns = probe.and_then(|p| p.dns.as_ref()).map(|dns| DnsProbeConfig {
        server: dns.server.clone(),
        port: dns.port.unwrap_or(53),
        name: dns.name.clone().unwrap_or_else(|| "example.com".to_string()),
    });
    let tcp = probe.and_then(|p| p.tcp.as_ref()).map(|tcp| TcpProbeConfig {
        host: tcp.host.clone(),
        port: tcp.port.unwrap_or(80),
    });

    // Defaults chosen to be safe for upstream Shadowsocks stacks that apply
    // per-IP rate limits / replay-filter back-pressure on a burst of fresh
    // handshakes.  Each probe cycle opens at least one fresh WS connection
    // per uplink per enabled sub-probe (ws/http/dns/tcp), and all uplinks
    // are probed in parallel — at interval=30 s with attempts=2 this easily
    // put ~8 simultaneous handshakes on the wire every 30 s on a 2-uplink
    // deployment, which was observed in the field to overlap bursty
    // real-user traffic and cause cascading chunk-0 "Connection reset
    // without closing handshake" failures.  The larger defaults spread that
    // load out by ~4× while still detecting uplink failures inside a
    // couple of minutes.
    let interval_secs = probe.and_then(|p| p.interval_secs).unwrap_or(120);
    let attempts = probe.and_then(|p| p.attempts).unwrap_or(1).max(1);
    if interval_secs < 60 {
        warn!(
            probe_interval_secs = interval_secs,
            "probe interval below 60 s: frequent probe handshakes can trip upstream rate limits \
             and cause spurious chunk-0 failures; consider 120 s unless you know the upstream \
             tolerates it"
        );
    }
    if attempts > 1 {
        warn!(
            probe_attempts = attempts,
            "probe.attempts > 1 multiplies handshakes per cycle; min_failures already gates noisy \
             failover — consider leaving attempts=1 unless the link is intrinsically flaky"
        );
    }
    Ok(ProbeConfig {
        interval: Duration::from_secs(interval_secs),
        timeout: Duration::from_secs(probe.and_then(|p| p.timeout_secs).unwrap_or(10)),
        max_concurrent: probe.and_then(|p| p.max_concurrent).unwrap_or(4).max(1),
        max_dials: probe.and_then(|p| p.max_dials).unwrap_or(2).max(1),
        min_failures: probe.and_then(|p| p.min_failures).unwrap_or(3).max(1),
        attempts,
        ws: WsProbeConfig {
            enabled: probe
                .and_then(|p| p.ws.as_ref())
                .and_then(|ws| ws.enabled)
                .unwrap_or(false),
        },
        http,
        dns,
        tcp,
    })
}

fn load_balancing_config(lb: Option<&LoadBalancingSection>) -> Result<LoadBalancingConfig> {
    let rtt_ewma_alpha = lb.and_then(|l| l.rtt_ewma_alpha).unwrap_or(0.3);
    if !(rtt_ewma_alpha.is_finite() && 0.0 < rtt_ewma_alpha && rtt_ewma_alpha <= 1.0) {
        bail!("load_balancing.rtt_ewma_alpha must be in the range (0, 1]");
    }
    Ok(LoadBalancingConfig {
        mode: lb.and_then(|l| l.mode).unwrap_or(LoadBalancingMode::ActiveActive),
        routing_scope: lb.and_then(|l| l.routing_scope).unwrap_or(RoutingScope::PerFlow),
        sticky_ttl: Duration::from_secs(lb.and_then(|l| l.sticky_ttl_secs).unwrap_or(300)),
        hysteresis: Duration::from_millis(lb.and_then(|l| l.hysteresis_ms).unwrap_or(50)),
        failure_cooldown: Duration::from_secs(
            lb.and_then(|l| l.failure_cooldown_secs).unwrap_or(10),
        ),
        tcp_chunk0_failover_timeout: Duration::from_secs(
            lb.and_then(|l| l.tcp_chunk0_failover_timeout_secs).unwrap_or(10),
        ),
        warm_standby_tcp: lb.and_then(|l| l.warm_standby_tcp).unwrap_or(0),
        warm_standby_udp: lb.and_then(|l| l.warm_standby_udp).unwrap_or(0),
        rtt_ewma_alpha,
        failure_penalty: Duration::from_millis(
            lb.and_then(|l| l.failure_penalty_ms).unwrap_or(500),
        ),
        failure_penalty_max: Duration::from_millis(
            lb.and_then(|l| l.failure_penalty_max_ms).unwrap_or(30_000),
        ),
        failure_penalty_halflife: Duration::from_secs(
            lb.and_then(|l| l.failure_penalty_halflife_secs).unwrap_or(60),
        ),
        h3_downgrade_duration: Duration::from_secs(
            lb.and_then(|l| l.h3_downgrade_secs).unwrap_or(60),
        ),
        udp_ws_keepalive_interval: lb
            .and_then(|l| l.udp_ws_keepalive_secs)
            .map(Duration::from_secs)
            .or(Some(Duration::from_secs(60))),
        // Default: 20 s — sends a WebSocket Ping on each idle warm-standby TCP
        // socket to keep connections alive through NAT/firewall idle-timeout
        // windows.  outline-ss-server handles WS Ping/Pong correctly.
        // Set to 0 to disable.
        tcp_ws_standby_keepalive_interval: {
            let secs = lb.and_then(|l| l.tcp_ws_standby_keepalive_secs).unwrap_or(20);
            if secs == 0 { None } else { Some(Duration::from_secs(secs)) }
        },
        // Default: 20 s — keeps active SOCKS TCP sessions alive through common
        // 25-30 s upstream idle-timeout windows (HAProxy, nginx, NAT tables).
        // Keepalives are SS2022 0-length encrypted chunks; SS1 uplinks ignore them.
        // Set to 0 to disable.
        tcp_active_keepalive_interval: {
            let secs = lb.and_then(|l| l.tcp_active_keepalive_secs).unwrap_or(20);
            if secs == 0 {
                None
            } else {
                Some(Duration::from_secs(secs))
            }
        },
        auto_failback: lb.and_then(|l| l.auto_failback).unwrap_or(false),
    })
}

#[cfg(feature = "tun")]
fn load_tun_config(tun: Option<&TunSection>, args: &Args) -> Result<Option<TunConfig>> {
    let path = args
        .tun_path
        .clone()
        .or_else(|| tun.and_then(|section| section.path.clone()));
    let name = args
        .tun_name
        .clone()
        .or_else(|| tun.and_then(|section| section.name.clone()));
    let mtu = args
        .tun_mtu
        .or_else(|| tun.and_then(|section| section.mtu))
        .unwrap_or(1500);
    let max_flows = tun.and_then(|section| section.max_flows).unwrap_or(4096);
    let idle_timeout =
        Duration::from_secs(tun.and_then(|section| section.idle_timeout_secs).unwrap_or(300));

    if path.is_none() && name.is_none() {
        return Ok(None);
    }

    let path =
        path.ok_or_else(|| anyhow!("missing tun.path: set it in config.toml or pass --tun-path"))?;

    if mtu < 1280 {
        bail!("tun mtu must be at least 1280");
    }
    if max_flows == 0 {
        bail!("tun max_flows must be greater than zero");
    }
    if idle_timeout < Duration::from_secs(5) {
        bail!("tun idle_timeout_secs must be at least 5");
    }

    let tcp_section = tun.and_then(|section| section.tcp.as_ref());
    let tcp = TunTcpConfig {
        connect_timeout: Duration::from_secs(
            tcp_section
                .and_then(|section| section.connect_timeout_secs)
                .unwrap_or(10),
        ),
        handshake_timeout: Duration::from_secs(
            tcp_section
                .and_then(|section| section.handshake_timeout_secs)
                .unwrap_or(15),
        ),
        half_close_timeout: Duration::from_secs(
            tcp_section
                .and_then(|section| section.half_close_timeout_secs)
                .unwrap_or(60),
        ),
        max_pending_server_bytes: tcp_section
            .and_then(|section| section.max_pending_server_bytes)
            .unwrap_or(4_194_304),
        backlog_abort_grace: Duration::from_secs(
            tcp_section
                .and_then(|section| section.backlog_abort_grace_secs)
                .unwrap_or(3),
        ),
        backlog_hard_limit_multiplier: tcp_section
            .and_then(|section| section.backlog_hard_limit_multiplier)
            .unwrap_or(2),
        backlog_no_progress_abort: Duration::from_secs(
            tcp_section
                .and_then(|section| section.backlog_no_progress_abort_secs)
                .unwrap_or(8),
        ),
        max_buffered_client_segments: tcp_section
            .and_then(|section| section.max_buffered_client_segments)
            .unwrap_or(4096),
        max_buffered_client_bytes: tcp_section
            .and_then(|section| section.max_buffered_client_bytes)
            .unwrap_or(262_144),
        max_retransmits: tcp_section.and_then(|section| section.max_retransmits).unwrap_or(12),
    };
    if tcp.connect_timeout < Duration::from_secs(1) {
        bail!("tun.tcp.connect_timeout_secs must be at least 1");
    }
    if tcp.handshake_timeout < Duration::from_secs(1) {
        bail!("tun.tcp.handshake_timeout_secs must be at least 1");
    }
    if tcp.half_close_timeout < Duration::from_secs(1) {
        bail!("tun.tcp.half_close_timeout_secs must be at least 1");
    }
    if tcp.max_pending_server_bytes < 16_384 {
        bail!("tun.tcp.max_pending_server_bytes must be at least 16384");
    }
    if tcp.backlog_abort_grace < Duration::from_secs(1) {
        bail!("tun.tcp.backlog_abort_grace_secs must be at least 1");
    }
    if tcp.backlog_hard_limit_multiplier < 2 {
        bail!("tun.tcp.backlog_hard_limit_multiplier must be at least 2");
    }
    if tcp.backlog_no_progress_abort < Duration::from_secs(1) {
        bail!("tun.tcp.backlog_no_progress_abort_secs must be at least 1");
    }
    if tcp.max_buffered_client_segments == 0 {
        bail!("tun.tcp.max_buffered_client_segments must be greater than zero");
    }
    if tcp.max_buffered_client_bytes < 16_384 {
        bail!("tun.tcp.max_buffered_client_bytes must be at least 16384");
    }
    if tcp.max_buffered_client_bytes > 262_144 {
        bail!("tun.tcp.max_buffered_client_bytes must be at most 262144");
    }
    if tcp.max_retransmits == 0 {
        bail!("tun.tcp.max_retransmits must be greater than zero");
    }

    #[cfg(target_os = "linux")]
    if name.is_none() {
        bail!("missing tun.name: Linux TUN attach requires --tun-name or [tun].name");
    }

    let defrag_max_fragment_sets = tun
        .and_then(|section| section.defrag_max_fragment_sets)
        .unwrap_or(1024);
    let defrag_max_fragments_per_set = tun
        .and_then(|section| section.defrag_max_fragments_per_set)
        .unwrap_or(64);
    let defrag_max_total_bytes = tun
        .and_then(|section| section.defrag_max_total_bytes)
        .unwrap_or(16 * 1024 * 1024);
    let defrag_max_bytes_per_set = tun
        .and_then(|section| section.defrag_max_bytes_per_set)
        .unwrap_or(128 * 1024);
    if defrag_max_fragment_sets == 0 {
        bail!("tun.defrag_max_fragment_sets must be greater than zero");
    }
    if defrag_max_fragments_per_set == 0 {
        bail!("tun.defrag_max_fragments_per_set must be greater than zero");
    }
    if defrag_max_total_bytes < 64 * 1024 {
        bail!("tun.defrag_max_total_bytes must be at least 65536");
    }
    if defrag_max_bytes_per_set < 1500 {
        bail!("tun.defrag_max_bytes_per_set must be at least 1500");
    }
    if defrag_max_bytes_per_set > defrag_max_total_bytes {
        bail!("tun.defrag_max_bytes_per_set must not exceed tun.defrag_max_total_bytes");
    }

    Ok(Some(TunConfig {
        path,
        name,
        mtu,
        max_flows,
        idle_timeout,
        tcp,
        defrag_max_fragment_sets,
        defrag_max_fragments_per_set,
        defrag_max_total_bytes,
        defrag_max_bytes_per_set,
    }))
}

fn load_h2_config(h2: Option<&H2Section>) -> H2Config {
    H2Config {
        initial_stream_window_size: h2
            .and_then(|s| s.initial_stream_window_size)
            .unwrap_or(1024 * 1024),
        initial_connection_window_size: h2
            .and_then(|s| s.initial_connection_window_size)
            .unwrap_or(2 * 1024 * 1024),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::schema::{DnsProbeSection, HttpProbeSection, TcpProbeSection, WsProbeSection};

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
            url: "http://template.example.com/probe".parse().unwrap(),
        });
        t.dns = Some(DnsProbeSection {
            server: "8.8.8.8".to_string(),
            port: Some(53),
            name: None,
        });

        let mut o = probe(None, None);
        o.http = Some(HttpProbeSection {
            url: "http://override.example.com/probe".parse().unwrap(),
        });
        // o.dns is not set — template's dns must survive

        let r = merge_probe_section(Some(&t), Some(&o)).unwrap();
        assert_eq!(
            r.http.unwrap().url.as_str(),
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
}

