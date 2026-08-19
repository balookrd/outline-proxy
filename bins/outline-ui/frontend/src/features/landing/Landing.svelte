<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { listInstances } from '../../lib/api';
  import { createPoll } from '../../lib/poll.svelte';
  import { go } from '../../lib/router.svelte';
  import bannerLight from '../../assets/banner-light.png';
  import bannerDark from '../../assets/banner-dark.png';

  // Capability check: a panel is only worth showing if the backend actually has
  // instances configured for it. `createPoll` re-checks periodically (and pauses
  // while the tab is hidden) so a panel that gets configured later appears
  // without a manual reload; a failed/unreachable backend just leaves `data`
  // `null` (see lib/poll.svelte.ts), which this view treats the same as "not
  // configured" — no crash, no fabricated numbers.
  const ssPoll = createPoll(() => listInstances('/ss'), () => 5000);
  const wsPoll = createPoll(() => listInstances('/ws'), () => 5000);

  onMount(() => { ssPoll.start(); wsPoll.start(); });
  onDestroy(() => { ssPoll.stop(); wsPoll.stop(); });

  const ssCount = $derived(ssPoll.data?.instances.length ?? 0);
  const wsCount = $derived(wsPoll.data?.instances.length ?? 0);

  function onKey(e: KeyboardEvent, path: string) {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(path); }
  }
</script>

<section class="view active" id="view-landing">
  <div class="page-head"><div><h1>Overview</h1><p>Two dashboards, one aggregating service. Pick a panel.</p></div></div>
  <div class="landing-hero">
    <img class="light" src={bannerLight} alt="outline-proxy" />
    <img class="dark" src={bannerDark} alt="outline-proxy" />
  </div>
  <div class="cards">
    {#if ssCount > 0}
      <div
        class="card link"
        role="button"
        tabindex="0"
        onclick={() => go('/ss')}
        onkeydown={(e) => onKey(e, '/ss')}
      >
        <h3><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/></svg> Server dashboard</h3>
        <div class="desc">Shadowsocks user management — create, edit, block access keys across server instances.</div>
        <div class="kpis">
          <div class="kpi"><div class="n">{ssCount}</div><div class="l">Instances</div></div>
        </div>
      </div>
    {/if}
    {#if wsCount > 0}
      <div
        class="card link"
        role="button"
        tabindex="0"
        onclick={() => go('/ws')}
        onkeydown={(e) => onKey(e, '/ws')}
      >
        <h3><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><path d="M12 7v4M12 11l-6 6M12 11l6 6"/></svg> Client dashboard</h3>
        <div class="desc">Uplink groups, wire chains, carrier loss and live switch operations across client instances.</div>
        <div class="kpis">
          <div class="kpi"><div class="n">{wsCount}</div><div class="l">Instances</div></div>
        </div>
      </div>
    {/if}
    {#if ssCount === 0 && wsCount === 0}
      <div class="empty">No capabilities detected yet — check the backend instance configuration.</div>
    {/if}
  </div>
</section>
