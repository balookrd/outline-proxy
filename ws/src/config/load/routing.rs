use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};

use outline_routing::{RouteRule, RouteTarget, RoutingTableConfig};
use outline_uplink::UplinkGroupConfig;

use super::super::schema::{ConfigFile, RouteSection};

/// Parse the `[[route]]` list into a `RoutingTableConfig`.
///
/// Returns `Ok(None)` when no `[[route]]` is declared (no routing table declared).
/// Otherwise validates:
/// - exactly one rule has `default = true` (and it has no prefixes/file);
/// - non-default rules have `prefixes` and/or `file`;
/// - `via` references a declared group or the reserved `direct`/`drop`;
/// - at most one of `fallback_via`/`fallback_direct`/`fallback_drop` is set.
pub(super) fn load_routing_table(
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
pub(super) fn resolve_config_path(raw: &Path, config_dir: &Path) -> Result<PathBuf> {
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
    if name.eq_ignore_ascii_case(super::DIRECT_TARGET) {
        return Ok(RouteTarget::Direct);
    }
    if name.eq_ignore_ascii_case(super::DROP_TARGET) {
        return Ok(RouteTarget::Drop);
    }
    if group_names.contains(&name) {
        return Ok(RouteTarget::Group(name.to_string()));
    }
    bail!(
        "{context}: via = \"{name}\" does not match any declared group; \
         known groups: {:?} (plus reserved `direct`, `drop`)",
        group_names
    )
}
