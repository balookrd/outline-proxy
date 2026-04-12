use super::*;

pub(super) async fn resolve_target(
    target: &TargetAddr,
    prefer_ipv4_upstream: bool,
) -> Result<SocketAddr> {
    resolve_target_addrs(target, prefer_ipv4_upstream)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| {
            anyhow!(
                "dns lookup returned no records for {}",
                target.display_host_port()
            )
        })
}

pub(super) async fn resolve_udp_target(
    udp_dns_cache: &UdpDnsCache,
    target: &TargetAddr,
    prefer_ipv4_upstream: bool,
) -> Result<SocketAddr> {
    match target {
        TargetAddr::Domain(host, port) => {
            if let Some(resolved) = udp_dns_cache.lookup(host, *port, prefer_ipv4_upstream) {
                return Ok(resolved);
            }
            let resolved = resolve_target(target, prefer_ipv4_upstream).await?;
            udp_dns_cache.store(host, *port, prefer_ipv4_upstream, resolved);
            Ok(resolved)
        }
        TargetAddr::Socket(_) => resolve_target(target, prefer_ipv4_upstream).await,
    }
}

pub(super) async fn resolve_target_addrs(
    target: &TargetAddr,
    prefer_ipv4_upstream: bool,
) -> Result<Vec<SocketAddr>> {
    match target {
        TargetAddr::Socket(addr) => {
            if prefer_ipv4_upstream && addr.is_ipv6() {
                return Err(anyhow!(
                    "ipv6 upstream disabled by prefer_ipv4_upstream for {}",
                    addr
                ));
            }
            Ok(vec![*addr])
        }
        TargetAddr::Domain(host, port) => {
            let mut addrs = lookup_host((host.as_str(), *port))
                .await
                .with_context(|| format!("dns lookup failed for {host}:{port}"))?
                .collect::<Vec<_>>();
            if prefer_ipv4_upstream {
                addrs.retain(SocketAddr::is_ipv4);
            }
            if addrs.is_empty() {
                return Err(anyhow!("dns lookup returned no records for {host}:{port}"));
            }
            Ok(addrs)
        }
    }
}

pub(super) async fn connect_tcp_target(
    target: &TargetAddr,
    fwmark: Option<u32>,
    prefer_ipv4_upstream: bool,
) -> Result<TcpStream> {
    let resolved = order_tcp_connect_addrs(
        resolve_target_addrs(target, prefer_ipv4_upstream).await?,
        prefer_ipv4_upstream,
    );
    connect_tcp_addrs(&resolved, fwmark)
        .await
        .with_context(|| format!("tcp connect failed for {}", target.display_host_port()))
}

pub(super) fn order_tcp_connect_addrs(
    addrs: Vec<SocketAddr>,
    prefer_ipv4_upstream: bool,
) -> Vec<SocketAddr> {
    let prefer_ipv6 = if prefer_ipv4_upstream {
        false
    } else {
        addrs.first().is_some_and(SocketAddr::is_ipv6)
    };
    let mut seen = HashSet::with_capacity(addrs.len());
    let mut ipv4 = VecDeque::new();
    let mut ipv6 = VecDeque::new();

    for addr in addrs {
        if !seen.insert(addr) {
            continue;
        }
        if addr.is_ipv6() {
            ipv6.push_back(addr);
        } else {
            ipv4.push_back(addr);
        }
    }

    let (primary, secondary) = if prefer_ipv6 {
        (&mut ipv6, &mut ipv4)
    } else {
        (&mut ipv4, &mut ipv6)
    };
    let mut ordered = Vec::with_capacity(primary.len() + secondary.len());
    while let Some(addr) = primary.pop_front() {
        ordered.push(addr);
        if let Some(fallback_addr) = secondary.pop_front() {
            ordered.push(fallback_addr);
        }
    }
    ordered.extend(secondary.drain(..));
    ordered
}

pub(super) async fn connect_tcp_addrs(
    addrs: &[SocketAddr],
    fwmark: Option<u32>,
) -> Result<TcpStream> {
    let mut attempts = FuturesUnordered::new();
    for (index, addr) in addrs.iter().copied().enumerate() {
        attempts.push(async move {
            if index > 0 {
                tokio::time::sleep(Duration::from_millis(
                    TCP_HAPPY_EYEBALLS_DELAY_MS * index as u64,
                ))
                .await;
            }
            let result = connect_tcp_addr(addr, fwmark).await;
            (addr, result)
        });
    }

    let mut last_error = None;
    while let Some((addr, result)) = attempts.next().await {
        match result {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some((addr, error)),
        }
    }

    match last_error {
        Some((addr, error)) => Err(error)
            .with_context(|| format!("all tcp connect attempts failed; last address {addr}")),
        None => Err(anyhow!("no socket addresses available for tcp connect")),
    }
}

async fn connect_tcp_addr(resolved: SocketAddr, fwmark: Option<u32>) -> Result<TcpStream> {
    let socket = if resolved.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }
    .with_context(|| format!("failed to create tcp socket for {resolved}"))?;

    apply_fwmark_if_needed(&socket, fwmark)
        .with_context(|| format!("failed to apply fwmark {fwmark:?} to tcp socket"))?;

    match timeout(
        Duration::from_secs(TCP_CONNECT_TIMEOUT_SECS),
        socket.connect(resolved),
    )
    .await
    {
        Ok(Ok(stream)) => {
            configure_tcp_stream(&stream)
                .with_context(|| format!("failed to configure tcp stream for {resolved}"))?;
            Ok(stream)
        }
        Ok(Err(error)) => Err(error).with_context(|| format!("tcp connect failed for {resolved}")),
        Err(_) => Err(anyhow!(
            "tcp connect timed out after {}s for {resolved}",
            TCP_CONNECT_TIMEOUT_SECS
        )),
    }
}

pub(super) fn configure_tcp_stream(stream: &TcpStream) -> Result<()> {
    stream
        .set_nodelay(true)
        .context("failed to enable TCP_NODELAY")
}
