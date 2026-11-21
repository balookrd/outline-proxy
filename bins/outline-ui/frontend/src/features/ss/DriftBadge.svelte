<script lang="ts">
  import type { ClusterConfigNode } from '../../lib/types';

  let {
    fieldKey,
    drift,
    nodes,
    label = 'Drift',
    extractValue,
    onAlign,
  }: {
    fieldKey: string;
    drift: string[];
    nodes: ClusterConfigNode[];
    label?: string;
    extractValue?: (cfg: NonNullable<ClusterConfigNode['config']>) => unknown;
    onAlign?: (value: unknown) => void;
  } = $props();

  let expanded = $state(false);

  const hasDrift = $derived(
    drift.some((d) => d === fieldKey || d.startsWith(`${fieldKey}.`)),
  );

  const perNodeValues = $derived.by(() => {
    if (!hasDrift || !extractValue) return [];
    return nodes
      .filter((n) => n.ok && n.config)
      .map((n) => {
        const val = extractValue(n.config!);
        return {
          instance: n.instance,
          raw: val,
          formatted:
            val === undefined || val === null || val === ''
              ? '—'
              : typeof val === 'string'
                ? val
                : JSON.stringify(val),
        };
      });
  });
</script>

{#if hasDrift}
  <div class="drift-wrap">
    <button
      type="button"
      class="drift-badge chip warn"
      aria-expanded={expanded}
      onclick={() => (expanded = !expanded)}
      title={`Cluster drift detected for ${fieldKey}`}
    >
      <span class="d"></span>
      {label}
    </button>
    {#if expanded && perNodeValues.length}
      <div class="drift-popover">
        <div class="drift-pop-head">Values across nodes ({fieldKey})</div>
        {#each perNodeValues as item (item.instance)}
          <div class="drift-pop-row">
            <span class="mono">{item.instance}</span>
            <code class="mono drift-val" title={item.formatted}>{item.formatted}</code>
            {#if onAlign}
              <button
                type="button"
                class="btn ghost sm"
                onclick={() => {
                  onAlign(item.raw);
                  expanded = false;
                }}
              >
                Use for all
              </button>
            {/if}
          </div>
        {/each}
      </div>
    {/if}
  </div>
{/if}
