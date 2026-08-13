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
  import { SvelteMap, SvelteSet } from 'svelte/reactivity';
  import { listInstances, topology, activate, reselect, setEnabled } from '../../lib/api';
  import { createPoll } from '../../lib/poll.svelte';
  import { toast } from '../../lib/toast.svelte';
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

  // ── Operations (Task 10) ──────────────────────────────────────────────────
  // Topology owns the per-instance polls, so it's also the natural owner of
  // the mutation handlers GroupTable's callback props invoke: it's the only
  // place that can call the right instance's poll.refresh() after an op
  // completes. GroupTable stays presentational — see its own header comment.

  // Double-submit guard, scoped per-instance rather than globally: this view
  // (unlike features/ss/Users.svelte or features/ws/Uplinks.svelte) renders
  // every instance at once, so a single page-wide lock would grey out
  // instance B's buttons while instance A's request is still in flight. A
  // second op on the SAME instance (even a different group/uplink) is still
  // blocked until the first resolves — coarser than per-row, but matches the
  // granularity polls already use (one poll, one refresh, per instance).
  const mutatingInstances = new SvelteSet<string>();

  function errorMessage(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
  }

  async function runOp(instanceName: string, fn: () => Promise<void>) {
    if (mutatingInstances.has(instanceName)) return;
    mutatingInstances.add(instanceName);
    try {
      await fn();
    } finally {
      mutatingInstances.delete(instanceName);
    }
  }

  // Hard activate (soft=false) or soft-switch (soft=true) one uplink — both
  // ride POST /activate, `soft` is the only difference (dashboard.html
  // activateEntries(), :1492-1501). Always a single-target request (this
  // button always targets exactly one uplink), so `results` always has
  // exactly one entry; a structural failure (bad request, unreachable
  // outline-ui itself) throws instead of resolving — see lib/api.ts's json().
  async function handleActivate(instanceName: string, groupName: string, uplinkName: string, soft: boolean) {
    await runOp(instanceName, async () => {
      const label = `${instanceName}: ${uplinkName}`;
      try {
        const res = await activate({
          targets: [{ instance: instanceName, group: groupName, uplink: uplinkName }],
          soft,
        });
        const result = res.results[0];
        if (result?.ok) {
          toast(`${label} ${soft ? 'soft-switched' : 'activated'}.`);
        } else {
          toast(`${label} ${soft ? 'soft switch' : 'activate'} failed: ${result?.error ?? 'unknown error'}`, 'error');
        }
        await polls.get(instanceName)?.refresh();
      } catch (e) {
        toast(errorMessage(e), 'error');
      }
    });
  }

  // Reselect now (group header ⟳) — always requests soft:true; the instance
  // clamps it to a hard switch off-cluster (dashboard.html reselectGroup(),
  // :1507-1514).
  async function handleReselect(instanceName: string, groupName: string) {
    await runOp(instanceName, async () => {
      try {
        const res = await reselect({ instance: instanceName, group: groupName, soft: true });
        if (res.ok) toast(`${instanceName}: ${groupName} reselected.`);
        else toast(`${instanceName}: ${groupName} reselect failed.`, 'error');
        await polls.get(instanceName)?.refresh();
      } catch (e) {
        toast(errorMessage(e), 'error');
      }
    });
  }

  // Operator on/off toggle (dashboard.html setUplinkEnabled(), :1519-1526).
  async function handleSetEnabled(instanceName: string, groupName: string, uplinkName: string, enabled: boolean) {
    await runOp(instanceName, async () => {
      const label = `${instanceName}: ${uplinkName}`;
      try {
        const res = await setEnabled({ instance: instanceName, group: groupName, uplink: uplinkName, enabled });
        if (res.ok) toast(`${label} ${enabled ? 'enabled' : 'disabled'}.`);
        else toast(`${label} ${enabled ? 'enable' : 'disable'} failed.`, 'error');
        await polls.get(instanceName)?.refresh();
      } catch (e) {
        toast(errorMessage(e), 'error');
      }
    });
  }
</script>

<section class="view active">
  <div class="page-head">
    <div>
      <h1>Topology</h1>
      <p>Uplink groups and wire chains. Green = active &amp; healthy, amber = ready/degraded, red = down.</p>
    </div>
  </div>

  <!-- Wire-chain layer key: every link is coloured by its (transport, tunnel)
       combo and edge-accented by carrier — see WireChain.svelte /
       lib/wsTopology.ts's legWireChain()/wireComboKey(). Sits above the
       per-instance topology so every TCP/UDP wire-chain cell below reads
       without a per-cell legend. -->
  <div class="wire-legend">
    <span class="wl-group"><span class="wl-swatch vlws"></span><b>vless/ws</b></span>
    <span class="wl-group"><span class="wl-swatch vlxh"></span><b>vless/xhttp</b></span>
    <span class="wl-group"><span class="wl-swatch ssws"></span><b>ss/ws</b></span>
    <span class="wl-group"><span class="wl-swatch ssxh"></span><b>ss/xhttp</b></span>
    <span class="muted">— combo colour</span>
    <span class="wl-group"><span class="wl-edge h3"></span><b>h3</b><span class="wl-edge h2"></span><b>h2</b><span class="wl-edge h1"></span><b>h1</b></span>
    <span class="muted">— carrier (left edge)</span>
    <span class="muted">active = full text · fallback = square</span>
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
              <GroupTable
                {group}
                mutating={mutatingInstances.has(inst.name)}
                onActivate={(uplinkName, soft) => handleActivate(inst.name, group.name, uplinkName, soft)}
                onEnable={(uplinkName, enabled) => handleSetEnabled(inst.name, group.name, uplinkName, enabled)}
                onReselect={() => handleReselect(inst.name, group.name)}
              />
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
