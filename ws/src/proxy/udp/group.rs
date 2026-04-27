use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use anyhow::{Result, anyhow};
use arc_swap::ArcSwap;
use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::debug;

use socks5_proto::TargetAddr;
use outline_metrics as metrics;
use outline_transport::is_dropped_oversized_udp_error;
use outline_uplink::{TransportKind, UplinkManager, UplinkRegistry};

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
    pub(super) active: Arc<ArcSwap<ActiveUdpTransport>>,
    pub(super) group_name: Arc<str>,
}

impl GroupUdpContext {
    /// Send a pre-wrapped payload through this group's active transport.
    ///
    /// Reconciles global transport state before sending, and falls over to a
    /// replacement uplink on error. All transport-state side effects are
    /// contained here so callers in the dispatch layer stay stateless.
    pub(super) async fn send_packet(
        &self,
        target: Option<&TargetAddr>,
        payload: &[u8],
    ) -> Result<()> {
        reconcile_global_udp_transport(&self.manager, &self.active, target).await?;
        let snapshot = self.active.load_full();
        let transport = Arc::clone(&snapshot.transport);
        let uplink_name = snapshot.uplink_name.clone();
        let active_index = snapshot.index;
        let group = self.manager.group_name();
        if let Err(error) = transport.send_packet(payload).await {
            if is_dropped_oversized_udp_error(&error) {
                return Ok(());
            }
            let replacement =
                failover_udp_transport(&self.manager, &self.active, target, active_index, error)
                    .await?;
            if let Err(error) = replacement.transport.send_packet(payload).await {
                if is_dropped_oversized_udp_error(&error) {
                    return Ok(());
                }
                return Err(error);
            }
            metrics::add_udp_datagram("client_to_upstream", group, &replacement.uplink_name);
            metrics::add_bytes(
                "udp",
                "client_to_upstream",
                group,
                &replacement.uplink_name,
                payload.len(),
            );
            self.manager.report_active_traffic(replacement.index, TransportKind::Udp).await;
        } else {
            metrics::add_udp_datagram("client_to_upstream", group, &uplink_name);
            metrics::add_bytes("udp", "client_to_upstream", group, &uplink_name, payload.len());
            self.manager.report_active_traffic(active_index, TransportKind::Udp).await;
        }
        Ok(())
    }
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
///
/// Split locks: `map` is an `RwLock` so the hot fast path (group already
/// resolved) takes a read-lock without contending with other senders, and
/// `tasks` is a separate `Mutex` touched only on first-use spawn and on
/// shutdown. The invariant "every entry in `map` has exactly one task in
/// `tasks`" is preserved by always taking the locks in the order
/// `map` (write) → `tasks` when inserting.
pub(super) struct AssocGroupMap {
    map: RwLock<HashMap<String, GroupUdpContext>>,
    tasks: Mutex<JoinSet<()>>,
}

impl AssocGroupMap {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            map: RwLock::new(HashMap::new()),
            tasks: Mutex::new(JoinSet::new()),
        })
    }

    /// Close every group's active transport; abort spawned downlink tasks.
    /// Called once on association shutdown.
    pub(super) async fn shutdown(&self, reason: &'static str) {
        self.tasks.lock().expect("AssocGroupMap tasks poisoned").abort_all();
        let map = std::mem::take(&mut *self.map.write().expect("AssocGroupMap map poisoned"));
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
///
/// The map insert and task spawn happen under a single lock acquisition so the
/// invariant "every map entry has exactly one downlink task" is never violated,
/// even under concurrent callers for the same group.
pub(super) async fn resolve_group_context(
    registry_groups: &Arc<AssocGroupMap>,
    registry: &UplinkRegistry,
    group_name: &str,
    responses: &mpsc::Sender<UdpResponse>,
) -> Result<GroupUdpContext> {
    // Fast path: context already exists. Read-lock keeps concurrent senders
    // for the same (or different) groups from serializing on a single mutex.
    {
        let map = registry_groups.map.read().expect("AssocGroupMap map poisoned");
        if let Some(ctx) = map.get(group_name) {
            return Ok(ctx.clone());
        }
    }

    // Slow path: build a new transport outside any lock (async I/O).
    let manager = registry
        .group_by_name(group_name)
        .ok_or_else(|| anyhow!("uplink group \"{group_name}\" is not configured"))?
        .clone();
    let initial = select_udp_transport(&manager, None).await?;
    let active = Arc::new(ArcSwap::from_pointee(initial));
    let ctx = GroupUdpContext {
        manager: manager.clone(),
        active: Arc::clone(&active),
        group_name: Arc::from(group_name),
    };

    // Insert the context and spawn the downlink task atomically: take the map
    // write-lock first, then the tasks lock under it, so no caller ever sees a
    // map entry without a running task. Locking order is always map → tasks.
    let (result, duplicate_transport) = {
        let mut map = registry_groups.map.write().expect("AssocGroupMap map poisoned");
        if let Some(existing) = map.get(group_name) {
            // Lost the race — another caller inserted while we were building.
            // Return their context; close our duplicate transport after unlock.
            (existing.clone(), Some(active))
        } else {
            map.insert(group_name.to_string(), ctx.clone());
            let task_ctx = ctx.clone();
            let task_responses = responses.clone();
            let group_label = group_name.to_string();
            registry_groups
                .tasks
                .lock()
                .expect("AssocGroupMap tasks poisoned")
                .spawn(async move {
                    if let Err(error) = run_group_downlink(task_ctx, task_responses).await {
                        debug!(
                            group = %group_label,
                            error = %format!("{error:#}"),
                            "UDP group downlink task exited"
                        );
                    }
                });
            (ctx, None)
        }
    };

    if let Some(transport) = duplicate_transport {
        close_active_udp_transport(&transport, "duplicate_group_context").await;
    }
    Ok(result)
}

/// Per-group downlink: reads upstream datagrams from one group's active
/// transport and pushes parsed responses into the shared channel.
pub(super) async fn run_group_downlink(
    ctx: GroupUdpContext,
    responses: mpsc::Sender<UdpResponse>,
) -> Result<()> {
    loop {
        reconcile_global_udp_transport(&ctx.manager, &ctx.active, None).await?;
        let snapshot = ctx.active.load_full();
        let index = snapshot.index;
        let name = snapshot.uplink_name.clone();
        let transport = Arc::clone(&snapshot.transport);
        drop(snapshot);
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
