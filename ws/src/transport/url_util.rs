use anyhow::{Result, bail};
use url::Url;

pub(crate) fn websocket_path(url: &Url) -> String {
    let mut path = if url.path().is_empty() {
        "/".to_string()
    } else {
        url.path().to_string()
    };
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    path
}

pub(super) fn websocket_target_uri(url: &Url) -> Result<String> {
    let scheme = match url.scheme() {
        "wss" => "https",
        "ws" => "http",
        other => bail!("unsupported websocket scheme for h2 target URI: {other}"),
    };

    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL is missing host: {url}"))?;
    let mut uri = format!("{scheme}://{}", format_authority(host, url.port()));
    uri.push_str(&websocket_path(url));
    Ok(uri)
}

pub(crate) fn format_authority(host: &str, port: Option<u16>) -> String {
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    match port {
        Some(port) => format!("{host}:{port}"),
        None => host,
    }
}
