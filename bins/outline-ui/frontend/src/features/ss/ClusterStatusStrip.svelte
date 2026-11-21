<script lang="ts">
  import type { ClusterSummary } from '../../lib/types';

  let {
    cluster,
    reachableNodes,
    totalNodes,
    restartPendingNodes = [],
    regenerating = false,
    onRegenerate,
  }: {
    cluster: ClusterSummary | null;
    reachableNodes: number;
    totalNodes: number;
    restartPendingNodes?: string[];
    regenerating?: boolean;
    onRegenerate?: () => void;
  } = $props();

  const healthy = $derived(totalNodes > 0 && reachableNodes === totalNodes);
</script>

{#if cluster}
  <div class="cluster-strip" role="status" aria-live="polite">
    <span class="chip info">
      Cluster: <strong class="mono">{cluster.name}</strong>
      {#if cluster.source === 'discovered'}· auto{/if}
    </span>
    <span class="chip" class:ok={healthy} class:warn={!healthy}>
      <span class="d"></span>
      {reachableNodes}/{totalNodes} nodes online
    </span>
    {#if cluster.subscription_nodes.length}
      <span class="chip mono" title={`Subscription balancer nodes: ${cluster.subscription_nodes.join(', ')}`}>
        balancer: {cluster.subscription_nodes.length} nodes
      </span>
    {:else}
      <span class="chip" title="Each node generates its own independent subscription artifacts">
        per-node subscriptions
      </span>
    {/if}
    {#if restartPendingNodes.length}
      <span class="chip warn" title={`Restart pending on: ${restartPendingNodes.join(', ')}`}>
        restart pending: {restartPendingNodes.join(', ')}
      </span>
    {/if}
    <span class="spacer"></span>
    {#if onRegenerate}
      <button
        type="button"
        class="btn sm"
        disabled={regenerating || totalNodes === 0}
        onclick={onRegenerate}
        title="Regenerate subscription files across the cluster and prune deleted/disabled users"
      >
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-2.64-6.36M21 3v6h-6"/></svg>
        {regenerating ? 'Regenerating…' : 'Regenerate subscriptions'}
      </button>
    {/if}
  </div>
{/if}
