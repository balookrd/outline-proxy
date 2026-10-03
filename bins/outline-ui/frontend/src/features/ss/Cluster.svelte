<script lang="ts">
  import { onDestroy } from 'svelte';
  import { getServerConfig, patchServerConfig } from '../../lib/api';
  import { createPoll } from '../../lib/poll.svelte';
  import { toast } from '../../lib/toast.svelte';
  import type { ClusterConfig, ClusterPeer, ServerConfigResponse } from '../../lib/types';
  import InstanceSelector from '../../components/layout/InstanceSelector.svelte';
  import ErrorBanner from '../../components/layout/ErrorBanner.svelte';

  let instance = $state('');
  let refreshSecs = $state(10);
  const refreshMs = $derived(Math.max(1000, refreshSecs * 1000));

  let mutating = $state(false);
  let formDirty = $state(false);

  // Editable local form state
  let enabled = $state(false);
  let shardId = $state<number>(0);
  let meshListen = $state('');
  let relayBudgetMs = $state(1500);
  let clusterPsk = $state('');
  let peers = $state<ClusterPeer[]>([]);

  const configPoll = createPoll<ServerConfigResponse | null>(
    () => (instance ? getServerConfig(instance) : Promise.resolve(null)),
    () => refreshMs,
  );

  $effect(() => {
    void instance;
    formDirty = false;
    configPoll.start();
  });
  onDestroy(() => configPoll.stop());

  const config = $derived(configPoll.data);
  const clusterData = $derived(config?.cluster);

  const clusterStatus = $derived.by(() => {
    if (!clusterData || !clusterData.enabled) return 'unconfigured';
    if (clusterData.peers && clusterData.peers.length > 0) return 'active';
    return 'standalone';
  });

  // Sync form from server if user hasn't made unsaved edits
  $effect(() => {
    if (clusterData && !formDirty) {
      enabled = clusterData.enabled;
      shardId = clusterData.shard_id ?? 0;
      meshListen = clusterData.mesh_listen ?? '';
      relayBudgetMs = clusterData.mesh_relay_budget_ms ?? 1500;
      clusterPsk = clusterData.cluster_psk ?? '';
      peers = clusterData.peers ? clusterData.peers.map((p) => ({ ...p })) : [];
    }
  });

  function markDirty() {
    formDirty = true;
  }

  function generateRandomPsk() {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    clusterPsk = btoa(binary);
    markDirty();
    toast('New 32-byte Base64 PSK generated.');
  }

  async function copyPsk() {
    if (!clusterPsk) return;
    try {
      await navigator.clipboard.writeText(clusterPsk);
      toast('Cluster PSK copied to clipboard.');
    } catch {
      toast('Failed to copy to clipboard', 'error');
    }
  }

  function addPeer() {
    // Find next available shard ID between 0 and 15
    const usedShards = new Set([shardId, ...peers.map((p) => p.shard)]);
    let nextShard = 0;
    while (nextShard < 16 && usedShards.has(nextShard)) {
      nextShard++;
    }
    if (nextShard >= 16) {
      toast('Maximum 16 shards in cluster (0..15).', 'error');
      return;
    }
    peers = [...peers, { shard: nextShard, addr: '' }];
    markDirty();
  }

  function removePeer(idx: number) {
    peers = peers.filter((_, i) => i !== idx);
    markDirty();
  }

  function updatePeerShard(idx: number, newShardStr: string) {
    const val = parseInt(newShardStr, 10);
    if (!isNaN(val)) {
      peers[idx].shard = Math.max(0, Math.min(15, val));
      markDirty();
    }
  }

  function updatePeerAddr(idx: number, addr: string) {
    peers[idx].addr = addr;
    markDirty();
  }

  async function save() {
    if (!instance) return;

    // Validation
    if (enabled) {
      if (shardId < 0 || shardId > 15) {
        toast('Local Shard ID must be between 0 and 15.', 'error');
        return;
      }
      if (!meshListen.trim()) {
        toast('Mesh listen address is required when cluster is enabled.', 'error');
        return;
      }
      const peerShards = new Set<number>();
      for (const p of peers) {
        if (p.shard === shardId) {
          toast(`Peer cannot share the same Shard ID (${p.shard}) as local node.`, 'error');
          return;
        }
        if (peerShards.has(p.shard)) {
          toast(`Duplicate peer Shard ID (${p.shard}). Each peer must have a unique shard.`, 'error');
          return;
        }
        peerShards.add(p.shard);
        if (!p.addr.trim()) {
          toast(`Peer with Shard ID ${p.shard} is missing an address.`, 'error');
          return;
        }
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

      // Only send cluster_psk if not masked
      if (clusterPsk && !clusterPsk.includes('*')) {
        clusterPatch.cluster_psk = clusterPsk.trim();
      }

      const res = await patchServerConfig(instance, { cluster: clusterPatch });
      formDirty = false;
      if (res.requires_restart) {
        toast('Cluster configuration saved. Restart server to apply port / listener changes.');
      } else {
        toast('Cluster configuration saved.');
      }
      await configPoll.refresh();
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      toast(msg, 'error');
    } finally {
      mutating = false;
    }
  }
</script>

<section class="view active">
  <div class="page-head">
    <div>
      <h1>Mesh Cluster</h1>
      <p>Multi-node anycast cluster and shard relay configuration.</p>
    </div>
    <div class="toolbar">
      <InstanceSelector base="/ss" bind:selected={instance} bind:refreshSecs={refreshSecs} />
      <button class="btn primary sm" disabled={!instance || mutating || !formDirty} onclick={save}>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
        Save changes
      </button>
    </div>
  </div>

  {#if !instance}
    <div class="empty">Select a server to view and configure cluster settings.</div>
  {:else}
    <ErrorBanner message={configPoll.error} />

    {#if clusterData}
      <!-- Status & Topology Overview Card -->
      <div class="card" style="margin-bottom: var(--sp-4);">
        <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: var(--sp-2);">
          <div>
            <h3 style="margin: 0; font-size: 15px;">
              Cluster Status
              {#if clusterStatus === 'active'}
                <span class="chip ok"><span class="d"></span>Active Mesh</span>
              {:else if clusterStatus === 'standalone'}
                <span class="chip warn"><span class="d"></span>Standalone Node</span>
              {:else}
                <span class="chip off"><span class="d"></span>Unconfigured</span>
              {/if}
            </h3>
            <p class="desc" style="margin-top: 4px;">
              Outline mesh allows anycast ingress: clients connect to any server, and requests are routed to the user's home shard over a secure authenticated QUIC mesh.
            </p>
          </div>
          {#if formDirty}
            <div class="chip warn">Unsaved changes</div>
          {/if}
        </div>

        <div class="kpis" style="margin-top: var(--sp-3);">
          <div class="kpi">
            <div class="n">{clusterData.shard_id ?? 0}</div>
            <div class="l">Current Shard ID</div>
          </div>
          <div class="kpi">
            <div class="n">{clusterData.peers?.length ?? 0}</div>
            <div class="l">Configured Peers</div>
          </div>
          <div class="kpi">
            <div class="n">{clusterData.mesh_relay_budget_ms ?? 1500} ms</div>
            <div class="l">Relay Budget</div>
          </div>
        </div>
      </div>

      <!-- Settings Grid -->
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: var(--sp-4);">
        <!-- Local Node Settings -->
        <div class="panel" style="padding: var(--sp-4);">
          <h3 style="font-size: 14px; font-weight: 600; margin-top: 0; margin-bottom: var(--sp-3);">
            Local Node Configuration
          </h3>

          <div style="display: flex; flex-direction: column; gap: var(--sp-3);">
            <div class="fieldrow">
              <label class="switch">
                <input type="checkbox" bind:checked={enabled} onchange={markDirty} />
                <span>Enable Mesh Cluster on this node</span>
              </label>
              <span class="hint">When enabled, this node accepts cross-shard relay connections.</span>
            </div>

            <div class="fieldrow">
              <label for="shard-id-input">Local Shard ID (0 .. 15)</label>
              <input
                id="shard-id-input"
                type="number"
                min="0"
                max="15"
                bind:value={shardId}
                oninput={markDirty}
                disabled={!enabled}
                class="field-mono"
              />
              <span class="hint">Identifies this server's shard in the cluster. Users are assigned to shards.</span>
            </div>

            <div class="fieldrow">
              <label for="mesh-listen-input">Mesh Listen Address</label>
              <input
                id="mesh-listen-input"
                type="text"
                placeholder="0.0.0.0:9443 or [::]:9443"
                bind:value={meshListen}
                oninput={markDirty}
                disabled={!enabled}
                class="field-mono"
              />
              <span class="hint">Address and UDP port for incoming inter-shard QUIC connections.</span>
            </div>

            <div class="fieldrow">
              <label for="relay-budget-input">Relay Budget (ms)</label>
              <input
                id="relay-budget-input"
                type="number"
                min="100"
                max="30000"
                bind:value={relayBudgetMs}
                oninput={markDirty}
                disabled={!enabled}
                class="field-mono"
              />
              <span class="hint">Maximum time allowed for a cross-shard relay connection attempt before fallback.</span>
            </div>

            <div class="fieldrow">
              <label for="cluster-psk-input">Cluster Pre-Shared Key (PSK)</label>
              <div class="secret-row">
                <input
                  id="cluster-psk-input"
                  type="text"
                  placeholder="32-byte Base64 string"
                  bind:value={clusterPsk}
                  oninput={markDirty}
                  disabled={!enabled}
                  class="field-mono"
                />
                <button
                  type="button"
                  class="btn sm"
                  title="Generate random 32-byte PSK"
                  onclick={generateRandomPsk}
                  disabled={!enabled}
                >
                  Generate
                </button>
                <button
                  type="button"
                  class="btn sm ghost"
                  title="Copy PSK"
                  onclick={copyPsk}
                  disabled={!enabled || !clusterPsk}
                >
                  Copy
                </button>
              </div>
              <span class="hint">Shared secret for all nodes in the mesh. Leave masked to keep current key.</span>
            </div>
          </div>
        </div>

        <!-- Peers List -->
        <div class="panel" style="padding: var(--sp-4);">
          <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: var(--sp-3);">
            <h3 style="font-size: 14px; font-weight: 600; margin: 0;">
              Remote Shards (Peers)
            </h3>
            <button
              class="btn sm"
              onclick={addPeer}
              disabled={!enabled}
              title="Add peer node"
            >
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg>
              Add Peer
            </button>
          </div>

          {#if peers.length === 0}
            <div class="empty" style="padding: var(--sp-4);">
              No remote peers configured. This node operates in standalone mode or awaits incoming connections only.
            </div>
          {:else}
            <table>
              <thead>
                <tr>
                  <th style="width: 90px;">Shard</th>
                  <th>Peer Address</th>
                  <th style="width: 50px; text-align: right;">Action</th>
                </tr>
              </thead>
              <tbody>
                {#each peers as peer, idx}
                  <tr>
                    <td>
                      <input
                        type="number"
                        min="0"
                        max="15"
                        value={peer.shard}
                        oninput={(e) => updatePeerShard(idx, (e.target as HTMLInputElement).value)}
                        disabled={!enabled}
                        class="field-mono"
                        style="width: 70px; padding: 4px 6px;"
                      />
                    </td>
                    <td>
                      <input
                        type="text"
                        placeholder="198.51.100.1:9443 or [2001:db8::1]:9443"
                        value={peer.addr}
                        oninput={(e) => updatePeerAddr(idx, (e.target as HTMLInputElement).value)}
                        disabled={!enabled}
                        class="field-mono"
                        style="width: 100%; padding: 4px 6px;"
                      />
                    </td>
                    <td style="text-align: right;">
                      <button
                        class="iconbtn act-danger"
                        title="Delete peer"
                        disabled={!enabled}
                        onclick={() => removePeer(idx)}
                        aria-label={`Remove peer ${peer.shard}`}
                      >
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14"/></svg>
                      </button>
                    </td>
                  </tr>
                {/each}
              </tbody>
            </table>
          {/if}
        </div>
      </div>
    {/if}
  {/if}
</section>
