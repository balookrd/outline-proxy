<script lang="ts">
  import { onDestroy } from 'svelte';
  import {
    ssTargetState,
    subscribeSsTargets,
    findClusterForInstance,
  } from '../../lib/ssTarget.svelte';
  import type { SsTarget } from '../../lib/types';

  let {
    onBeforeChange,
  }: {
    onBeforeChange?: (next: SsTarget) => Promise<boolean> | boolean;
  } = $props();

  const unsubscribe = subscribeSsTargets();
  onDestroy(() => unsubscribe());

  const currentValue = $derived(
    ssTargetState.target ? `${ssTargetState.target.kind}:${ssTargetState.target.name}` : '',
  );
  const hasOptions = $derived(
    ssTargetState.clusters.length > 0 || ssTargetState.instances.length > 0,
  );
  const memberCluster = $derived(
    ssTargetState.target?.kind === 'instance'
      ? findClusterForInstance(ssTargetState.target.name)
      : null,
  );

  async function applyTarget(next: SsTarget, selectEl?: HTMLSelectElement) {
    if (
      ssTargetState.target?.kind === next.kind &&
      ssTargetState.target?.name === next.name
    ) {
      return;
    }
    if (onBeforeChange) {
      const allowed = await onBeforeChange(next);
      if (!allowed) {
        if (selectEl) selectEl.value = currentValue;
        return;
      }
    }
    ssTargetState.target = next;
  }

  async function onChange(e: Event) {
    const el = e.currentTarget as HTMLSelectElement;
    const raw = el.value;
    const sep = raw.indexOf(':');
    if (sep <= 0) return;
    const kind = raw.slice(0, sep);
    const name = raw.slice(sep + 1);
    if (kind !== 'cluster' && kind !== 'instance') return;
    await applyTarget({ kind, name }, el);
  }
</script>

<div class="target-selector">
  <select
    aria-label="Target cluster or server"
    class="field-mono"
    value={currentValue}
    onchange={onChange}
    disabled={!hasOptions}
  >
    {#if !hasOptions}
      <option value="">No targets</option>
    {:else}
      {#if ssTargetState.clusters.length}
        <optgroup label="Clusters">
          {#each ssTargetState.clusters as cl (cl.name)}
            <option value={`cluster:${cl.name}`}>
              cluster · {cl.name} ({cl.members.length}){cl.source === 'discovered' ? ' · auto' : ''}
            </option>
          {/each}
        </optgroup>
      {/if}
      {#if ssTargetState.instances.length}
        <optgroup label="Single nodes">
          {#each ssTargetState.instances as inst (inst.name)}
            <option value={`instance:${inst.name}`}>{inst.name}</option>
          {/each}
        </optgroup>
      {/if}
    {/if}
  </select>
  {#if memberCluster}
    <button
      type="button"
      class="btn ghost sm"
      onclick={() => applyTarget({ kind: 'cluster', name: memberCluster.name })}
      title={`Switch target to cluster ${memberCluster.name}`}
    >
      Switch to cluster {memberCluster.name}
    </button>
  {/if}
</div>
