<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { listInstances } from '../../lib/api';
  import { createPoll } from '../../lib/poll.svelte';

  // Shared between the SS and WS panels (WS reuses this in later tasks) —
  // parameterized by `base` so the same component drives both `/ss` and `/ws`
  // instance pickers. Polls on its own (capabilities can appear/disappear
  // later, same reasoning as Landing.svelte) and re-exposes the two things a
  // parent panel needs: the selected instance name (bindable) and the
  // server-provided poll cadence (bindable), so the parent's own data poll
  // (e.g. listUsers) can use the same interval without fetching instances
  // itself.
  let {
    base,
    selected = $bindable(''),
    refreshSecs = $bindable(5),
  }: {
    base: '/ss' | '/ws';
    selected?: string;
    refreshSecs?: number;
  } = $props();

  const label = $derived(base === '/ws' ? 'Client instance' : 'Server instance');

  const instancesPoll = createPoll(() => listInstances(base), () => 5000);
  onMount(() => instancesPoll.start());
  onDestroy(() => instancesPoll.stop());

  const instances = $derived(instancesPoll.data?.instances ?? []);

  // Keep the parent's refresh cadence in sync with whatever the backend
  // reports (config.toml's dashboard.refresh_interval_secs), instead of the
  // parent hardcoding a guess.
  $effect(() => {
    const secs = instancesPoll.data?.refresh_interval_secs;
    if (secs && secs > 0) refreshSecs = secs;
  });

  // Auto-pick the first instance once the list loads (matches the old
  // dashboard.html behavior), and re-pick if the current selection falls out
  // of the list (instance removed from config).
  $effect(() => {
    if (instances.length && !instances.some((i) => i.name === selected)) {
      selected = instances[0].name;
    }
  });
</script>

<select aria-label={label} class="field-mono" bind:value={selected} disabled={!instances.length}>
  {#if !instances.length}
    <option value="">No instances</option>
  {/if}
  {#each instances as inst (inst.name)}
    <option value={inst.name}>{inst.name}</option>
  {/each}
</select>
