<script lang="ts">
  import type { NodeActionResult, RegenerateReport } from '../../lib/types';

  let {
    title = 'Operation results',
    results,
    onDismiss,
  }: {
    title?: string;
    results: NodeActionResult[];
    onDismiss?: () => void;
  } = $props();

  function reportSummary(data: unknown): RegenerateReport | null {
    if (!data || typeof data !== 'object') return null;
    const obj = data as RegenerateReport;
    if ('written' in obj || 'pruned' in obj || 'warnings' in obj) return obj;
    return null;
  }
</script>

{#if results.length}
  <div class="per-node-panel" role="region" aria-label={title}>
    <div class="per-node-head">
      <strong>{title}</strong>
      <span class="spacer"></span>
      {#if onDismiss}
        <button type="button" class="btn ghost sm" onclick={onDismiss}>Dismiss</button>
      {/if}
    </div>
    <div class="per-node-list">
      {#each results as item (item.instance)}
        {@const report = reportSummary(item.data)}
        <div class="per-node-row">
          <span class="mono per-node-name">{item.instance}</span>
          {#if item.already_absent}
            <span class="chip off">already absent (404)</span>
          {:else if item.ok}
            <span class="chip ok"><span class="d"></span>ok ({item.status})</span>
          {:else}
            <span class="chip bad"><span class="d"></span>failed ({item.status})</span>
          {/if}
          {#if item.rolled_back === true}
            <span class="chip warn">rolled back</span>
          {:else if item.rolled_back === false}
            <span class="chip bad">rollback failed</span>
          {/if}
          {#if item.requires_restart}
            <span class="chip warn">restart required</span>
          {/if}
          {#if report}
            <span class="mono muted per-node-detail">
              written: {report.written?.length ?? 0}, pruned: {report.pruned?.length ?? 0}
              {#if report.warnings?.length} · {report.warnings.join('; ')}{/if}
            </span>
          {:else if item.error}
            <span class="per-node-err">{item.error}</span>
          {/if}
        </div>
      {/each}
    </div>
  </div>
{/if}
