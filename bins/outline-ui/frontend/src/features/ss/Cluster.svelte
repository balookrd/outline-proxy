<script lang="ts">
  import { onDestroy } from 'svelte';
  import {
    ApiError,
    getClusterConfig,
    getServerConfig,
    patchClusterConfig,
    patchServerConfig,
  } from '../../lib/api';
  import { createPoll } from '../../lib/poll.svelte';
  import { toast } from '../../lib/toast.svelte';
  import {
    ssTargetState,
    getClusterSummary,
    getInstanceInfo,
  } from '../../lib/ssTarget.svelte';
  import { buildSymmetricPeers } from '../../lib/serverConfigForm';
  import type {
    ClusterConfig,
    ClusterConfigResponse,
    ClusterPeer,
    NodeActionResult,
    ServerConfigPatch,
    ServerConfigResponse,
    SsTarget,
  } from '../../lib/types';
  import SsTargetSelector from '../../components/layout/SsTargetSelector.svelte';
  import ErrorBanner from '../../components/layout/ErrorBanner.svelte';
  import ConfirmDialog from '../../components/layout/ConfirmDialog.svelte';
  import ClusterStatusStrip from './ClusterStatusStrip.svelte';
  import PerNodeResultPanel from './PerNodeResultPanel.svelte';

  const target = $derived(ssTargetState.target);
  const isCluster = $derived(target?.kind === 'cluster');
  const clusterSummary = $derived(
    target?.kind === 'cluster' ? getClusterSummary(target.name) : null,
  );
  const refreshMs = $derived(Math.max(1000, ssTargetState.refreshSecs * 1000));

  let mutating = $state(false);
  let formDirty = $state(false);
  let actionResults = $state<NodeActionResult[]>([]);
  let actionTitle = $state('');

  // Pending target switch confirmation
  let pendingTarget = $state<SsTarget | null>(null);
  let confirmSwitchOpen = $derived(pendingTarget !== null);
  let rotatePskConfirmOpen = $state(false);

  // Cluster mode form state
  interface EditableMember {
    name: string;
    enabled: boolean;
    shard_id: number;
    mesh_listen: string;
    mesh_addr: string;
    psk_fingerprint: string | null;
    restart_pending: boolean;
    reachable: boolean;
  }
  let clusterMembersForm = $state<EditableMember[]>([]);
  let clusterRelayBudgetMs = $state(4000);

  // Standalone mode form state
  let enabled = $state(false);
  let shardId = $state(0);
  let meshListen = $state('');
  let relayBudgetMs = $state(4000);
  let clusterPsk = $state('');
  let peers = $state<ClusterPeer[]>([]);

  type PollData =
    | { kind: 'cluster'; payload: ClusterConfigResponse }
    | { kind: 'single'; payload: ServerConfigResponse }
    | null;

  const configPoll = createPoll<PollData>(
    async () => {
      if (!target) return null;
      if (target.kind === 'cluster') {
        const payload = await getClusterConfig(target.name);
        return { kind: 'cluster', payload };
      }
      const payload = await getServerConfig(target.name);
      return { kind: 'single', payload };
    },
    () => refreshMs,
  );

  $effect(() => {
    void target;
    formDirty = false;
    actionResults = [];
    configPoll.start();
  });
  onDestroy(() => configPoll.stop());

  const clusterRes = $derived(
    configPoll.data?.kind === 'cluster' ? configPoll.data.payload : null,
  );
  const singleRes = $derived(
    configPoll.data?.kind === 'single' ? configPoll.data.payload : null,
  );

  $effect(() => {
    if (formDirty) return;
    if (clusterRes) {
      let budget = 4000;
      clusterMembersForm = clusterRes.nodes.map((node, idx) => {
        const cl = node.config?.cluster;
        const info = getInstanceInfo(node.instance);
        if (cl?.mesh_relay_budget_ms) budget = cl.mesh_relay_budget_ms;
        return {
          name: node.instance,
          enabled: cl?.enabled ?? false,
          shard_id: cl?.shard_id ?? idx,
          mesh_listen: cl?.mesh_listen ?? '',
          mesh_addr: info?.mesh_addr ?? cl?.mesh_listen ?? '',
          psk_fingerprint: cl?.psk_fingerprint ?? null,
          restart_pending: Boolean(node.config?.restart_pending),
          reachable: node.ok,
        };
      });
      clusterRelayBudgetMs = budget;
    } else if (singleRes?.cluster) {
      const c = singleRes.cluster;
      enabled = c.enabled;
      shardId = c.shard_id ?? 0;
      meshListen = c.mesh_listen ?? '';
      relayBudgetMs = c.mesh_relay_budget_ms ?? 4000;
      clusterPsk = c.cluster_psk ?? '';
      peers = c.peers ? c.peers.map((p) => ({ ...p })) : [];
    }
  });

  function generateBase64Psk(): string {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }

  function onBeforeTargetChange(next: SsTarget): boolean {
    if (!formDirty) return true;
    pendingTarget = next;
    return false;
  }

  function extractResults(e: unknown): NodeActionResult[] {
    if (e instanceof ApiError && e.body && typeof e.body === 'object' && 'results' in e.body) {
      const r = (e.body as { results?: unknown }).results;
      if (Array.isArray(r)) return r as NodeActionResult[];
    }
    return [];
  }

  async function saveClusterTopology(newPsk?: string) {
    if (!target || target.kind !== 'cluster') return;
    const { peersByNode, error } = buildSymmetricPeers(
      clusterMembersForm.map((m) => ({
        name: m.name,
        shard_id: m.shard_id,
        mesh_addr: m.mesh_addr.trim() || m.mesh_listen.trim(),
      })),
    );
    if (error) {
      toast(error, 'error');
      return;
    }
    for (const m of clusterMembersForm) {
      if (m.enabled && !m.mesh_listen.trim()) {
        toast(`${m.name}: mesh_listen address is required when mesh is enabled.`, 'error');
        return;
      }
    }

    mutating = true;
    actionResults = [];
    try {
      const perNode: Record<string, ServerConfigPatch> = {};
      for (const m of clusterMembersForm) {
        perNode[m.name] = {
          cluster: {
            enabled: m.enabled,
            shard_id: m.shard_id,
            mesh_listen: m.mesh_listen.trim() || null,
            mesh_relay_budget_ms: clusterRelayBudgetMs,
            peers: peersByNode[m.name],
            ...(newPsk ? { cluster_psk: newPsk } : {}),
          },
        };
      }
      const res = await patchClusterConfig(target.name, { per_node: perNode });
      formDirty = false;
      actionTitle = newPsk
        ? `Rotated cluster PSK on ${target.name}`
        : `Saved symmetric cluster topology on ${target.name}`;
      actionResults = res.results;
      toast(
        newPsk
          ? 'Cluster PSK rotated and saved. Restart nodes one at a time.'
          : 'Cluster topology saved across nodes.',
      );
      await configPoll.refresh();
    } catch (e) {
      const results = extractResults(e);
      if (results.length) {
        actionTitle = `Cluster topology update failed on ${target.name}`;
        actionResults = results;
      }
      toast(e instanceof Error ? e.message : String(e), 'error');
    } finally {
      mutating = false;
    }
  }

  // Single-node helpers
  function addPeer() {
    const used = new Set([shardId, ...peers.map((p) => p.shard)]);
    let next = 0;
    while (next < 16 && used.has(next)) next++;
    if (next >= 16) {
      toast('Maximum 16 shards in cluster (0..15).', 'error');
      return;
    }
    peers = [...peers, { shard: next, addr: '' }];
    formDirty = true;
  }

  function removePeer(idx: number) {
    peers = peers.filter((_, i) => i !== idx);
    formDirty = true;
  }

  async function saveSingleNode() {
    if (!target || target.kind !== 'instance') return;
    if (enabled) {
      if (shardId < 0 || shardId > 15) {
        toast('Local Shard ID must be between 0 and 15.', 'error');
        return;
      }
      if (!meshListen.trim()) {
        toast('Mesh listen address is required when cluster is enabled.', 'error');
        return;
      }
    }
    mutating = true;
    try {
      const clusterPatch: Partial<ClusterConfig> = {
        enabled,
        shard_id: shardId,
        mesh_listen: meshListen.trim() ? meshListen.trim() : null,
        mesh_relay_budget_ms: relayBudgetMs,
        peers: peers.filter((p) => p.addr.trim().length > 0),
      };
      if (clusterPsk && !clusterPsk.includes('*')) {
        clusterPatch.cluster_psk = clusterPsk.trim();
      }
      const res = await patchServerConfig(target.name, { cluster: clusterPatch });
      formDirty = false;
      toast(
        res.requires_restart
          ? 'Cluster settings saved. Restart node to apply changes.'
          : 'Cluster settings saved.',
      );
      await configPoll.refresh();
    } catch (e) {
      toast(e instanceof Error ? e.message : String(e), 'error');
    } finally {
      mutating = false;
    }
  }

  const singleStatus = $derived.by(() => {
    if (!singleRes?.cluster || !singleRes.cluster.enabled) return 'unconfigured';
    if (singleRes.cluster.peers?.length) return 'active';
    return 'standalone';
  });
</script>

<section class="view active">
  <div class="page-head">
    <div>
      <h1>Mesh Cluster</h1>
      <p>
        {isCluster
          ? `Multi-node anycast mesh health, shard assignment, and PSK management for ${target?.name}.`
          : 'Anycast cluster shard and peer configuration.'}
      </p>
    </div>
    <div class="toolbar">
      <SsTargetSelector onBeforeChange={onBeforeTargetChange} />
      {#if isCluster}
        <button
          type="button"
          class="btn sm"
          disabled={!clusterRes || mutating}
          onclick={() => (rotatePskConfirmOpen = true)}
        >
          Rotate PSK across cluster
        </button>
        <button
          type="button"
          class="btn primary sm"
          disabled={!clusterRes || mutating}
          onclick={() => saveClusterTopology()}
        >
          {formDirty ? 'Save symmetric topology' : 'Sync peers'}
        </button>
      {:else}
        <button
          type="button"
          class="btn primary sm"
          disabled={!target || mutating || !formDirty}
          onclick={saveSingleNode}
        >
          Save changes
        </button>
      {/if}
    </div>
  </div>

  {#if !target}
    <div class="empty">Select a cluster or server to manage mesh topology.</div>
  {:else if isCluster}
    {#if clusterSummary && clusterRes}
      <ClusterStatusStrip
        cluster={clusterSummary}
        reachableNodes={clusterRes.nodes.filter((n) => n.ok).length}
        totalNodes={clusterRes.members.length}
        restartPendingNodes={clusterRes.mesh_health.restart_pending_nodes}
      />
    {/if}

    <ErrorBanner message={configPoll.error} />

    {#if clusterRes}
      <div class="card" style="margin-bottom: var(--sp-4);">
        <h2>Cluster Health</h2>
        <div class="health-chips">
          <span class="chip" class:ok={clusterRes.mesh_health.psk_match} class:bad={!clusterRes.mesh_health.psk_match}>
            <span class="d"></span>
            PSK: {clusterRes.mesh_health.psk_match ? 'Match' : 'Mismatch / Missing'}
          </span>
          <span class="chip" class:ok={clusterRes.mesh_health.shards_unique} class:bad={!clusterRes.mesh_health.shards_unique}>
            <span class="d"></span>
            Shards: {clusterRes.mesh_health.shards_unique ? 'Unique' : 'Conflict / Missing'}
          </span>
          <span class="chip" class:ok={clusterRes.mesh_health.peers_symmetric} class:warn={!clusterRes.mesh_health.peers_symmetric}>
            <span class="d"></span>
            Peers: {clusterRes.mesh_health.peers_symmetric ? 'Symmetric' : 'Incomplete / Asymmetric'}
          </span>
          {#if clusterRes.mesh_health.restart_pending_nodes.length}
            <span class="chip warn">
              Restart pending: {clusterRes.mesh_health.restart_pending_nodes.join(', ')}
            </span>
          {:else}
            <span class="chip ok">All nodes synced with running config</span>
          {/if}
        </div>
      </div>

      <PerNodeResultPanel
        title={actionTitle}
        results={actionResults}
        onDismiss={() => (actionResults = [])}
      />

      <div class="panel panel-pad">
        <div class="section-head-row" style="margin-bottom: var(--sp-3);">
          <div style="flex: 1 1 280px; min-width: 0;">
            <h2>Cluster Members</h2>
            <p class="desc">
              Each node automatically receives peer entries for all other shards using their configured mesh addresses.
            </p>
          </div>
          <span class="spacer"></span>
          <div class="fieldrow" style="flex: 0 1 180px;">
            <label for="cluster-relay-budget">Relay budget (ms)</label>
            <input
              id="cluster-relay-budget"
              type="number"
              min="100"
              max="30000"
              class="field-mono"
              bind:value={clusterRelayBudgetMs}
              oninput={() => (formDirty = true)}
            />
          </div>
        </div>

        <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
        <div tabindex="0" role="region" aria-label="Cluster members table" class="table-wrapper">
          <table class="cluster-members-table">
            <thead>
              <tr>
                <th>Node</th>
                <th>Mesh</th>
                <th>Shard ID</th>
                <th>Mesh Listen</th>
                <th>Peer Reach Addr</th>
                <th>PSK fp / Status</th>
              </tr>
            </thead>
            <tbody>
              {#each clusterMembersForm as member (member.name)}
                <tr>
                  <td>
                    <span class="mono" style="font-weight: 600;">{member.name}</span>
                  </td>
                  <td>
                    <label class="switch">
                      <input
                        type="checkbox"
                        aria-label={`Enable mesh on ${member.name}`}
                        bind:checked={member.enabled}
                        onchange={() => (formDirty = true)}
                      />
                    </label>
                  </td>
                  <td>
                    <input
                      type="number"
                      min="0"
                      max="15"
                      class="field-mono"
                      aria-label={`Shard ID on ${member.name}`}
                      bind:value={member.shard_id}
                      oninput={() => (formDirty = true)}
                    />
                  </td>
                  <td>
                    <input
                      type="text"
                      class="field-mono"
                      aria-label={`Mesh listen on ${member.name}`}
                      placeholder="[::]:9443"
                      bind:value={member.mesh_listen}
                      oninput={() => (formDirty = true)}
                    />
                  </td>
                  <td>
                    <input
                      type="text"
                      class="field-mono"
                      aria-label={`Mesh peer address for ${member.name}`}
                      placeholder="198.51.100.10:9443"
                      bind:value={member.mesh_addr}
                      oninput={() => (formDirty = true)}
                    />
                  </td>
                  <td>
                    <div class="key-chips">
                      {#if !member.reachable}
                        <span class="chip bad">unreachable</span>
                      {:else if member.psk_fingerprint}
                        <span class="chip info mono">{member.psk_fingerprint}</span>
                      {:else}
                        <span class="chip off">no PSK</span>
                      {/if}
                      {#if member.restart_pending}
                        <span class="chip warn">restart</span>
                      {/if}
                    </div>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      </div>
    {/if}
  {:else}
    <ErrorBanner message={configPoll.error} />
    {#if singleRes?.cluster}
      <div class="card" style="margin-bottom: var(--sp-4);">
        <div class="section-head-row">
          <div>
            <h2>
              Node Status
              {#if singleStatus === 'active'}
                <span class="chip ok"><span class="d"></span>Active Mesh</span>
              {:else if singleStatus === 'standalone'}
                <span class="chip warn"><span class="d"></span>Standalone</span>
              {:else}
                <span class="chip off"><span class="d"></span>Disabled</span>
              {/if}
            </h2>
            {#if singleRes.restart_pending}
              <span class="chip warn">Restart pending to apply saved config</span>
            {/if}
          </div>
          <span class="spacer"></span>
          {#if singleRes.cluster.psk_fingerprint}
            <span class="chip info mono">PSK fp: {singleRes.cluster.psk_fingerprint}</span>
          {/if}
        </div>
        <div class="kpis" style="margin-top: var(--sp-3);">
          <div class="kpi"><div class="n">{singleRes.cluster.shard_id ?? 0}</div><div class="l">Shard ID</div></div>
          <div class="kpi"><div class="n">{singleRes.cluster.peers.length}</div><div class="l">Peers</div></div>
          <div class="kpi"><div class="n">{singleRes.cluster.mesh_relay_budget_ms ?? 4000} ms</div><div class="l">Relay budget</div></div>
        </div>
      </div>

      <div class="settings-two-col">
        <div class="panel panel-form panel-pad">
          <h3 style="margin-bottom: var(--sp-3);">Local Mesh Configuration</h3>
          <div class="stack-form">
            <div class="fieldrow">
              <label class="switch">
                <input type="checkbox" bind:checked={enabled} onchange={() => (formDirty = true)} />
                <span>Enable Mesh Cluster</span>
              </label>
            </div>
            <div class="fieldrow">
              <label for="single-shard">Local Shard ID (0..15)</label>
              <input id="single-shard" type="number" min="0" max="15" class="field-mono" bind:value={shardId} oninput={() => (formDirty = true)} disabled={!enabled} />
            </div>
            <div class="fieldrow">
              <label for="single-mesh-listen">Mesh Listen Address</label>
              <input id="single-mesh-listen" type="text" class="field-mono" bind:value={meshListen} oninput={() => (formDirty = true)} disabled={!enabled} placeholder="[::]:9443" />
            </div>
            <div class="fieldrow">
              <label for="single-budget">Relay Budget (ms)</label>
              <input id="single-budget" type="number" min="100" max="30000" class="field-mono" bind:value={relayBudgetMs} oninput={() => (formDirty = true)} disabled={!enabled} />
            </div>
            <div class="fieldrow">
              <label for="single-psk">Cluster PSK</label>
              <div class="secret-row">
                <input id="single-psk" type="text" class="field-mono" bind:value={clusterPsk} oninput={() => (formDirty = true)} disabled={!enabled} />
                <button type="button" class="btn sm" disabled={!enabled} onclick={() => { clusterPsk = generateBase64Psk(); formDirty = true; }}>Generate</button>
              </div>
              <span class="hint">Leave as ******** to preserve the current on-disk PSK.</span>
            </div>
          </div>
        </div>

        <div class="panel panel-form panel-pad">
          <div class="section-head-row" style="margin-bottom: var(--sp-3);">
            <h3>Remote Shards (Peers)</h3>
            <span class="spacer"></span>
            <button type="button" class="btn sm" disabled={!enabled} onclick={addPeer}>Add peer</button>
          </div>
          {#if peers.length === 0}
            <div class="empty">No remote peers configured.</div>
          {:else}
            <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
            <div tabindex="0" role="region" aria-label="Remote shard peers table" class="table-wrapper">
              <table class="peers-table">
                <thead>
                  <tr><th>Shard</th><th>Address</th><th>Action</th></tr>
                </thead>
                <tbody>
                  {#each peers as peer, idx (idx)}
                    <tr>
                      <td><input type="number" min="0" max="15" class="field-mono" aria-label={`Peer ${idx + 1} shard`} bind:value={peer.shard} oninput={() => (formDirty = true)} disabled={!enabled} /></td>
                      <td><input type="text" class="field-mono" aria-label={`Peer ${idx + 1} address`} bind:value={peer.addr} oninput={() => (formDirty = true)} disabled={!enabled} /></td>
                      <td style="text-align: right;">
                        <button type="button" class="iconbtn act-danger" aria-label={`Remove peer ${peer.shard}`} disabled={!enabled} onclick={() => removePeer(idx)}>
                          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14"/></svg>
                        </button>
                      </td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          {/if}
        </div>
      </div>
    {/if}
  {/if}
</section>

<ConfirmDialog
  open={rotatePskConfirmOpen}
  title={`Rotate PSK across ${target?.name ?? 'cluster'}?`}
  message="This generates a new 32-byte random Base64 PSK and writes it to every member node. Nodes must then be restarted carefully one at a time via systemd."
  confirmLabel="Rotate PSK"
  danger={true}
  onconfirm={() => {
    rotatePskConfirmOpen = false;
    void saveClusterTopology(generateBase64Psk());
  }}
  oncancel={() => (rotatePskConfirmOpen = false)}
/>

<ConfirmDialog
  open={confirmSwitchOpen}
  title="Discard unsaved cluster changes?"
  message="Switching targets will discard unsaved modifications to cluster members and peers."
  confirmLabel="Discard"
  danger={true}
  onconfirm={() => {
    const next = pendingTarget;
    pendingTarget = null;
    formDirty = false;
    if (next) ssTargetState.target = next;
  }}
  oncancel={() => (pendingTarget = null)}
/>
