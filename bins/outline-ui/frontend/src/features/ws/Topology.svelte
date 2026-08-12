<script lang="ts">
  // WS topology read-view: every configured client instance at once (mirrors
  // dashboard.html's renderInstancePanel() loop over instancesArray(),
  // :1219-1258/:1389-1403 — NOT a single-instance selector like
  // features/ss/Users.svelte or features/ws/Uplinks.svelte). Visual shape from
  // the prototype's #view-topology + renderTopology()
  // (spec 2026-08-12-outline-ui-svelte-rewrite-prototype.html:351-360,
  // 492-532).
  //
  // One poll per instance, created/stopped as the instance list changes —
  // mirrors dashboard.html's loadInstanceList() diffing against
  // instanceTimers (:1447-1469). `started` is a plain (non-reactive) bookkeeping
  // Set so the sync effect only ever *reads* listPoll.data and only ever
  // *writes* the reactive `polls`/`updatedAt` maps — never both on the same
  // collection, which would make the effect its own dependency.
  import { onMount, onDestroy } from 'svelte';
  import { SvelteMap } from 'svelte/reactivity';
  import { listInstances, topology } from '../../lib/api';
  import { createPoll } from '../../lib/poll.svelte';
  import type { TopologyResponse } from '../../lib/types';
  import { instanceStatusTone, instanceStatusLabel } from '../../lib/wsTopology';
  import StatusDot from '../../components/layout/StatusDot.svelte';
  import ErrorBanner from '../../components/layout/ErrorBanner.svelte';
  import GroupTable from './GroupTable.svelte';

  let refreshSecs = $state(5);
  const refreshMs = $derived(Math.max(1000, refreshSecs * 1000));

  const listPoll = createPoll(() => listInstances('/ws'), () => refreshMs);
  onMount(() => listPoll.start());

  $effect(() => {
    const secs = listPoll.data?.refresh_interval_secs;
    if (secs && secs > 0) refreshSecs = secs;
  });

  type TopoPoll = ReturnType<typeof createPoll<TopologyResponse>>;
  const polls = new SvelteMap<string, TopoPoll>();
  const updatedAt = new SvelteMap<string, number>();
  const started = new Set<string>();

  // Stamps `updatedAt` on both success and failure (finally runs either way)
  // — mirrors dashboard.html applyInstanceView(), which sets `updatedAt` in
  // its ok:false branch too (:1199-1203): the timestamp means "last time we
  // checked", not "last time the check succeeded".
  function fetchTopology(name: string): () => Promise<TopologyResponse> {
    return async () => {
      try {
        return await topology(name);
      } finally {
        updatedAt.set(name, Date.now());
      }
    };
  }

  $effect(() => {
    const names = (listPoll.data?.instances ?? []).map((i) => i.name);
    const nameSet = new Set(names);
    for (const name of Array.from(started)) {
      if (!nameSet.has(name)) {
        polls.get(name)?.stop();
        polls.delete(name);
        updatedAt.delete(name);
        started.delete(name);
      }
    }
    for (const name of names) {
      if (!started.has(name)) {
        started.add(name);
        const poll = createPoll<TopologyResponse>(fetchTopology(name), () => refreshMs);
        polls.set(name, poll);
        poll.start();
      }
    }
  });

  onDestroy(() => {
    listPoll.stop();
    for (const poll of polls.values()) poll.stop();
  });

  function stampFor(name: string): string {
    const ts = updatedAt.get(name);
    return ts ? new Date(ts).toLocaleTimeString() : '—';
  }
</script>

<section class="view active">
  <div class="page-head">
    <div>
      <h1>Topology</h1>
      <p>Uplink groups and wire chains. Green = active &amp; healthy, amber = ready/degraded, red = down.</p>
    </div>
    <div class="toolbar">
      <span class="chip"><span class="d"></span> TCP wire</span>
      <span class="chip"><span class="seg h3" style="padding:0 5px">h3</span><span class="seg h2" style="padding:0 5px">h2</span><span class="seg ws" style="padding:0 5px">ws</span></span>
    </div>
  </div>

  <ErrorBanner message={listPoll.error} />

  {#if listPoll.data?.instances.length}
    {#each listPoll.data.instances as inst (inst.name)}
      {@const poll = polls.get(inst.name)}
      {@const data = poll?.data}
      {@const groups = data?.ok ? (data.topology?.instance?.groups ?? []) : []}
      {@const tone = data ? instanceStatusTone(data.ok, groups) : 'warn'}
      <div class="inst">
        <div class="inst-head">
          <StatusDot {tone} />
          <span class="title">
            {inst.name}
            <span class="chip {tone === 'good' ? 'ok' : tone}">{data ? instanceStatusLabel(tone) : 'Loading'}</span>
            {#if poll?.loading}<span class="chip">updating…</span>{/if}
          </span>
          <span class="sub">↻ {stampFor(inst.name)}</span>
        </div>
        {#if poll?.error}
          <ErrorBanner message={poll.error} />
        {:else if data && !data.ok}
          <ErrorBanner message={data.error ?? 'instance unavailable'} />
        {:else if data}
          {#if groups.length}
            {#each groups as group (group.name)}
              <GroupTable {group} />
            {/each}
          {:else}
            <div class="empty">No uplink groups configured.</div>
          {/if}
        {:else}
          <div class="empty">Loading topology…</div>
        {/if}
      </div>
    {/each}
  {:else if !listPoll.error}
    <div class="empty">No WS instances configured.</div>
  {/if}
</section>
