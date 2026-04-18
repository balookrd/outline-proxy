use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use bytes::Bytes;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinSet;
use tracing::debug;

use crate::types::TargetAddr;
use outline_uplink::{UplinkManager, UplinkRegistry};

use super::transport::{
    ActiveUdpTransport, close_active_udp_transport, failover_udp_transport,
    reconcile_global_udp_transport, select_udp_transport,
};

/// Per-association state for one uplink group actively carrying UDP traffic.
///
/// Each `Tunnel(group)` resolution lazily opens a [`GroupUdpContext`] the
/// first time a packet targets that group. The context owns the
/// [`ActiveUdpTransport`] (so each group reconciles / fails over within its
/// own manager) and hands out `Arc<UdpWsTransport>` clones to the send path.
#[derive(Clone)]
pub(super) struct GroupUdpContext {
    pub(super) manager: UplinkManager,
    pub(super) active: Arc<Mutex<ActiveUdpTransport>>,
    pub(super) group_name: Arc<str>,
}

/// A response datagram emitted by some group's downlink task, waiting to be
/// written to the SOCKS5 client. Allows multiple per-group read tasks to
/// share a single writer half without fighting for a mutex.
pub(super) struct UdpResponse {
    pub(super) target: TargetAddr,
    pub(super) payload: Bytes,
    pub(super) group_name: Arc<str>,
    pub(super) uplink_name: Arc<str>,
}

/// Per-association map of group-name → per-group UDP context, plus the
/// downlink tasks spawned for each active group. Owned exclusively by one
/// UDP associate session; not shared with other associations or the global
/// [`UplinkRegistry`].
pub(super) struct AssocGroupMap {
    map: Mutex<HashMap<String, GroupUdpContext>>,
    tasks: Mutex<JoinSet<()>>,
}

impl AssocGroupMap {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            map: Mutex::new(HashMap::new()),
            tasks: Mutex::new(JoinSet::new()),
        })
    }

    /// Close every group's active transport; abort spawned downlink tasks.
    /// Called once on association shutdown.
    pub(super) async fn shutdown(&self, reason: &'static str) {
        self.tasks.lock().await.abort_all();
        let map = std::mem::take(&mut *self.map.lock().await);
        for (_, ctx) in map {
            close_active_udp_transport(&ctx.active, reason).await;
        }
    }
}

/// Get-or-create the group context for `group_name`.
///
/// First caller spawns a dedicated downlink task that reads from the group's
/// transport and pushes responses into `responses`. All subsequent callers
/// reuse the cached context.
pub(super) async fn resolve_group_context(
    registry_groups: &Arc<AssocGroupMap>,
    registry: &UplinkRegistry,
    group_name: &str,
    responses: &mpsc::Sender<UdpResponse>,
) -> Result<GroupUdpContext> {
    {
        let map = registry_groups.map.lock().await;
        if let Some(ctx) = map.get(group_name) {
            return Ok(ctx.clone());
        }
    }
    let manager = registry
        .group_by_name(group_name)
        .ok_or_else(|| anyhow!("uplink group \"{group_name}\" is not configured"))?
        .clone();
    let initial = select_udp_transport(&manager, None).await?;
    let active = Arc::new(Mutex::new(initial));
    let ctx = GroupUdpContext {
        manager: manager.clone(),
        active: Arc::clone(&active),
        group_name: Arc::from(group_name),
    };

    let mut map = registry_groups.map.lock().await;
    if let Some(existing) = map.get(group_name) {
        // Lost the race to another concurrent caller for the same group.
        // Clone what we need, release the lock first, then close the
        // duplicate transport — closing is async and must not hold the lock.
        let existing = existing.clone();
        drop(map);
        close_active_udp_transport(&active, "duplicate_group_context").await;
        return Ok(existing);
    }
    map.insert(group_name.to_string(), ctx.clone());
    drop(map);

    let task_ctx = ctx.clone();
    let task_responses = responses.clone();
    let group_label = group_name.to_string();
    registry_groups.tasks.lock().await.spawn(async move {
        if let Err(error) = run_group_downlink(task_ctx, task_responses).await {
            debug!(
                group = %group_label,
                error = %format!("{error:#}"),
                "UDP group downlink task exited"
            );
        }
    });
    Ok(ctx)
}

/// Per-group downlink: reads upstream datagrams from one group's active
/// transport and pushes parsed responses into the shared channel.
pub(super) async fn run_group_downlink(
    ctx: GroupUdpContext,
    responses: mpsc::Sender<UdpResponse>,
) -> Result<()> {
    loop {
        reconcile_global_udp_transport(&ctx.manager, &ctx.active, None).await?;
        let (index, name, transport) = {
            let a = ctx.active.lock().await;
            (a.index, a.uplink_name.clone(), Arc::clone(&a.transport))
        };
        let payload = match transport.read_packet().await {
            Ok(payload) => payload,
            Err(error) => {
                let replacement =
                    failover_udp_transport(&ctx.manager, &ctx.active, None, index, error).await?;
                let payload = replacement.transport.read_packet().await?;
                let (target, consumed) = TargetAddr::from_wire_bytes(&payload)?;
                if responses
                    .send(UdpResponse {
                        target,
                        payload: payload.slice(consumed..),
                        group_name: Arc::clone(&ctx.group_name),
                        uplink_name: replacement.uplink_name,
                    })
                    .await
                    .is_err()
                {
                    return Ok(());
                }
                continue;
            },
        };
        let (target, consumed) = TargetAddr::from_wire_bytes(&payload)?;
        if responses
            .send(UdpResponse {
                target,
                payload: payload.slice(consumed..),
                group_name: Arc::clone(&ctx.group_name),
                uplink_name: name,
            })
            .await
            .is_err()
        {
            return Ok(());
        }
    }
}
