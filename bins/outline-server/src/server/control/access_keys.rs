//! Control-plane runner for `access-keys/generate_keys.py`.
//!
//! Invokes Python directly via `tokio::process::Command` (never through `/bin/sh`)
//! with strict argument validation, timeout and bounded output capture.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use axum::{
    Json,
    extract::{Path as AxumPath, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::Value;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tracing::warn;

use crate::config::FileConfig;

use super::handlers::{ControlState, error_response};

/// Ceiling for stdout/stderr collected from the generator process.
const MAX_GENERATOR_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_NODE_HOST_LEN: usize = 253;
const MAX_NODES_PER_REQUEST: usize = 32;

#[derive(Clone, Debug)]
pub(super) struct AccessKeysRunnerConfig {
    pub generator: PathBuf,
    pub python: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RegenerateRequest {
    #[serde(default)]
    pub nodes: Option<Vec<String>>,
    #[serde(default)]
    pub prune: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct UserAccessKeysQuery {
    #[serde(default)]
    pub nodes: Option<String>,
}

pub(super) fn validate_user_id(id: &str) -> Result<(), &'static str> {
    let trimmed = id.trim();
    if trimmed.is_empty() || trimmed != id {
        return Err("invalid user id");
    }
    if trimmed == "." || trimmed == ".." {
        return Err("invalid user id");
    }
    if id.starts_with('-') {
        return Err("user id cannot start with '-'");
    }
    if id.contains('/') || id.contains('\\') || id.contains('\0') {
        return Err("user id contains forbidden characters");
    }
    if id.chars().any(char::is_control) {
        return Err("user id contains control characters");
    }
    Ok(())
}

pub(super) fn validate_node_host(raw: &str) -> Result<String, String> {
    let node = raw.trim();
    if node.is_empty() {
        return Err("node host must not be empty".to_owned());
    }
    if node.len() > MAX_NODE_HOST_LEN {
        return Err(format!("node host {node:?} exceeds {MAX_NODE_HOST_LEN} characters"));
    }
    if node.starts_with('-') {
        return Err(format!("node host {node:?} must not start with '-'"));
    }
    if node.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!("node host {node:?} contains whitespace or control characters"));
    }
    if !node
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'))
    {
        return Err(format!("node host {node:?} contains disallowed characters"));
    }
    Ok(node.to_owned())
}

fn validate_nodes_list(raw: &[String]) -> Result<Vec<String>, String> {
    if raw.len() > MAX_NODES_PER_REQUEST {
        return Err(format!("too many nodes (max {MAX_NODES_PER_REQUEST})"));
    }
    raw.iter().map(|s| validate_node_host(s)).collect()
}

/// Resolve nodes for generator invocation:
/// 1) explicit request nodes;
/// 2) `[access_keys].nodes` in config.toml;
/// 3) `[access_keys].public_host` in config.toml (self-hosted single node).
fn resolve_effective_nodes(
    requested: Option<&[String]>,
    disk_file: Option<&FileConfig>,
) -> Result<Vec<String>, String> {
    if let Some(req) = requested {
        let validated = validate_nodes_list(req)?;
        if validated.is_empty() {
            return Err("nodes list must not be empty when explicitly provided".to_owned());
        }
        return Ok(validated);
    }
    let Some(ak) = disk_file.and_then(|f| f.access_keys.as_ref()) else {
        return Ok(Vec::new());
    };
    if let Some(cfg_nodes) = ak.nodes.as_ref() {
        let validated = validate_nodes_list(cfg_nodes)?;
        if !validated.is_empty() {
            return Ok(validated);
        }
    }
    if let Some(host) = ak.public_host.as_deref() {
        let trimmed = host.trim();
        if !trimmed.is_empty() {
            return Ok(vec![validate_node_host(trimmed)?]);
        }
    }
    Ok(Vec::new())
}

fn needs_default_file_extension(disk_file: Option<&FileConfig>) -> bool {
    disk_file
        .and_then(|f| f.access_keys.as_ref())
        .and_then(|ak| ak.file_extension.as_deref())
        .is_none_or(|ext| ext.trim().is_empty())
}

async fn read_disk_file_config(path: &Path) -> Option<FileConfig> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| toml::from_str(&text).ok())
    })
    .await
    .ok()
    .flatten()
}

fn redact_write_dir(text: &str, disk_file: Option<&FileConfig>) -> String {
    let Some(write_dir) = disk_file
        .and_then(|f| f.access_keys.as_ref())
        .and_then(|ak| ak.write_dir.as_ref())
    else {
        return text.to_owned();
    };
    let needle = write_dir.to_string_lossy();
    let trimmed = needle.trim();
    if trimmed.is_empty() {
        return text.to_owned();
    }
    text.replace(trimmed, "<redacted>")
}

struct GeneratorOutput {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

async fn run_generator(
    runner: &AccessKeysRunnerConfig,
    args: Vec<String>,
) -> Result<GeneratorOutput, (StatusCode, String)> {
    let mut cmd = Command::new(&runner.python);
    cmd.arg("-B")
        .arg(&runner.generator)
        .args(&args)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = cmd.spawn().map_err(|err| {
        warn!(error = %err, "failed to spawn access-keys generator");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to spawn access-keys generator: {err}"),
        )
    })?;

    let mut stdout_pipe = child.stdout.take().expect("stdout piped");
    let mut stderr_pipe = child.stderr.take().expect("stderr piped");

    let run_fut = async {
        let read_stdout = read_bounded(&mut stdout_pipe, MAX_GENERATOR_OUTPUT_BYTES);
        let read_stderr = read_bounded(&mut stderr_pipe, MAX_GENERATOR_OUTPUT_BYTES);
        let (out_bytes, err_bytes) = tokio::try_join!(read_stdout, read_stderr)?;
        let status = child
            .wait()
            .await
            .map_err(|err| format!("failed to wait for generator: {err}"))?;
        Ok::<_, String>((status, out_bytes, err_bytes))
    };

    let (status, stdout_bytes, stderr_bytes) =
        match tokio::time::timeout(runner.timeout, run_fut).await {
            Ok(Ok(res)) => res,
            Ok(Err(msg)) => {
                let _ = child.kill().await;
                return Err((StatusCode::INTERNAL_SERVER_ERROR, msg));
            },
            Err(_) => {
                let _ = child.kill().await;
                warn!(timeout_secs = runner.timeout.as_secs(), "access-keys generator timed out");
                return Err((
                    StatusCode::GATEWAY_TIMEOUT,
                    "access-keys generator timed out".to_owned(),
                ));
            },
        };

    Ok(GeneratorOutput {
        code: status.code(),
        stdout: String::from_utf8_lossy(&stdout_bytes).into_owned(),
        stderr: String::from_utf8_lossy(&stderr_bytes).into_owned(),
    })
}

async fn read_bounded<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    limit: usize,
) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    let mut limited = reader.take((limit + 1) as u64);
    limited
        .read_to_end(&mut buf)
        .await
        .map_err(|err| format!("failed reading generator output: {err}"))?;
    if buf.len() > limit {
        return Err(format!("generator output exceeded {limit} bytes"));
    }
    Ok(buf)
}

pub(super) async fn regenerate(
    State(state): State<ControlState>,
    body: Option<Json<RegenerateRequest>>,
) -> axum::response::Response {
    let Some(runner) = state.access_keys.as_ref() else {
        return error_response(
            StatusCode::NOT_IMPLEMENTED,
            "access_keys_generator is not configured in [control]",
        );
    };
    let Some(config_path) = state.manager.config_path() else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "server is running without a config file; cannot generate access keys",
        );
    };
    let req = body.map(|Json(v)| v).unwrap_or_default();
    let prune = req.prune.unwrap_or(true);

    let _file_guard = state.manager.config_file_lock().lock().await;
    let disk_file = read_disk_file_config(config_path).await;
    let nodes = match resolve_effective_nodes(req.nodes.as_deref(), disk_file.as_ref()) {
        Ok(nodes) => nodes,
        Err(msg) => return error_response(StatusCode::BAD_REQUEST, msg),
    };

    let mut args =
        vec!["--config".to_owned(), config_path.display().to_string(), "--json-report".to_owned()];
    if prune {
        args.push("--prune".to_owned());
    }
    if needs_default_file_extension(disk_file.as_ref()) {
        args.push("--file-extension".to_owned());
        args.push(".conf".to_owned());
    }
    for node in &nodes {
        args.push("--node".to_owned());
        args.push(node.clone());
    }

    let output = match run_generator(runner, args).await {
        Ok(out) => out,
        Err((status, msg)) => return error_response(status, msg),
    };

    if output.code != Some(0) {
        let redacted = redact_write_dir(output.stderr.trim(), disk_file.as_ref());
        let msg = if redacted.is_empty() {
            format!("access-keys generator exited with {:?}", output.code)
        } else {
            redacted.clone()
        };
        warn!(code = ?output.code, stderr = %redacted, "access-keys regenerate failed");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, msg);
    }

    match serde_json::from_str::<Value>(&output.stdout) {
        Ok(payload) => (StatusCode::OK, Json(payload)).into_response(),
        Err(err) => {
            warn!(error = %err, "generator returned invalid JSON report");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("generator returned invalid JSON: {err}"),
            )
        },
    }
}

pub(super) async fn get_user_access_keys(
    State(state): State<ControlState>,
    AxumPath(id): AxumPath<String>,
    Query(query): Query<UserAccessKeysQuery>,
) -> axum::response::Response {
    if let Err(msg) = validate_user_id(&id) {
        return error_response(StatusCode::BAD_REQUEST, msg);
    }
    let Some(runner) = state.access_keys.as_ref() else {
        return error_response(
            StatusCode::NOT_IMPLEMENTED,
            "access_keys_generator is not configured in [control]",
        );
    };
    let Some(config_path) = state.manager.config_path() else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "server is running without a config file; cannot generate access keys",
        );
    };

    let requested_nodes: Option<Vec<String>> = query
        .nodes
        .as_deref()
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .filter(|v| !v.is_empty());

    let _file_guard = state.manager.config_file_lock().lock().await;
    let disk_file = read_disk_file_config(config_path).await;
    let nodes = match resolve_effective_nodes(requested_nodes.as_deref(), disk_file.as_ref()) {
        Ok(nodes) => nodes,
        Err(msg) => return error_response(StatusCode::BAD_REQUEST, msg),
    };

    let mut args = vec![
        "--config".to_owned(),
        config_path.display().to_string(),
        "--user".to_owned(),
        id,
        "--links-json".to_owned(),
    ];
    if needs_default_file_extension(disk_file.as_ref()) {
        args.push("--file-extension".to_owned());
        args.push(".conf".to_owned());
    }
    for node in &nodes {
        args.push("--node".to_owned());
        args.push(node.clone());
    }

    let output = match run_generator(runner, args).await {
        Ok(out) => out,
        Err((status, msg)) => return error_response(status, msg),
    };

    match output.code {
        Some(0) => match serde_json::from_str::<Value>(&output.stdout) {
            Ok(payload) => (StatusCode::OK, Json(payload)).into_response(),
            Err(err) => error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("generator returned invalid JSON: {err}"),
            ),
        },
        Some(2) => {
            let detail = redact_write_dir(output.stderr.trim(), disk_file.as_ref());
            error_response(StatusCode::CONFLICT, detail.if_empty_or("user is disabled"))
        },
        Some(3) => {
            let detail = redact_write_dir(output.stderr.trim(), disk_file.as_ref());
            error_response(StatusCode::NOT_FOUND, detail.if_empty_or("user not found"))
        },
        other => {
            let redacted = redact_write_dir(output.stderr.trim(), disk_file.as_ref());
            warn!(code = ?other, stderr = %redacted, "access-keys links lookup failed");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                redacted.if_empty_or("access-keys generator failed"),
            )
        },
    }
}

trait StrFallback {
    fn if_empty_or(&self, fallback: &str) -> String;
}

impl StrFallback for str {
    fn if_empty_or(&self, fallback: &str) -> String {
        if self.is_empty() {
            fallback.to_owned()
        } else {
            self.to_owned()
        }
    }
}

#[cfg(test)]
#[path = "tests/access_keys.rs"]
mod tests;
