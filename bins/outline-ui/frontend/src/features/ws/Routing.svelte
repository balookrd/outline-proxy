<script lang="ts">
  import { onDestroy } from 'svelte';
  import { SvelteSet } from 'svelte/reactivity';
  import { routesList, routesMutate, routesReorder, apply } from '../../lib/api';
  import { createPoll } from '../../lib/poll.svelte';
  import { toast } from '../../lib/toast.svelte';
  import type { RouteEntry, RoutesListResponse, RouteConfig, ApplyResult } from '../../lib/types';
  import InstanceSelector from '../../components/layout/InstanceSelector.svelte';
  import ErrorBanner from '../../components/layout/ErrorBanner.svelte';
  import RouteDrawer from './RouteDrawer.svelte';

  let instance = $state('');
  let refreshSecs = $state(5);
  const refreshMs = $derived(Math.max(1000, refreshSecs * 1000));

  const routesPoll = createPoll<RoutesListResponse>(
    () => (instance ? routesList(instance) : Promise.resolve<RoutesListResponse>({ routes: [], groups: [], revision: '' })),
    () => refreshMs,
  );
  $effect(() => { void instance; routesPoll.start(); });
  onDestroy(() => routesPoll.stop());

  const entries = $derived<RouteEntry[]>(routesPoll.data?.routes ?? []);
  const groups = $derived<string[]>(routesPoll.data?.groups ?? []);
  const revision = $derived(routesPoll.data?.revision ?? '');

  const dirtyInstances = new SvelteSet<string>();
  const dirty = $derived(instance !== '' && dirtyInstances.has(instance));
  let mutating = $state(false);
  let applying = $state(false);

  const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e));

  let drawerOpen = $state(false);
  let editingEntry = $state<RouteEntry | null>(null);
  function openCreate() { editingEntry = null; drawerOpen = true; }
  function openEdit(entry: RouteEntry) { editingEntry = entry; drawerOpen = true; }
  function closeDrawer() { drawerOpen = false; editingEntry = null; }

  // Drawer hands back a validated payload; parent owns the API call.
  async function saveRoute(payload: Record<string, unknown>, editingIndex: number | null) {
    mutating = true;
    try {
      if (editingIndex !== null) {
        await routesMutate('PATCH', instance, { index: editingIndex, rule: payload, revision });
      } else {
        await routesMutate('POST', instance, { rule: payload, revision });
      }
      dirtyInstances.add(instance);
      toast('Saved to config (not yet applied).');
      closeDrawer();
      await routesPoll.refresh();
    } catch (e) { toast(errMsg(e), 'error'); }
    finally { mutating = false; }
  }

  async function removeRoute(entry: RouteEntry) {
    if (!confirm(`Delete route #${entry.index}?`)) return;
    mutating = true;
    try {
      await routesMutate('DELETE', instance, { index: entry.index, revision });
      dirtyInstances.add(instance);
      toast('Deleted from config (not yet applied).');
      await routesPoll.refresh();
    } catch (e) { toast(errMsg(e), 'error'); }
    finally { mutating = false; }
  }

  async function move(entry: RouteEntry, dir: -1 | 1) {
    const to = entry.index + dir;
    if (to < 0 || to >= entries.length) return;
    mutating = true;
    try {
      await routesReorder(instance, { from: entry.index, to, revision });
      dirtyInstances.add(instance);
      await routesPoll.refresh();
    } catch (e) { toast(errMsg(e), 'error'); }
    finally { mutating = false; }
  }

  async function applyNow() {
    applying = true;
    try {
      await apply(instance) as ApplyResult;
      dirtyInstances.delete(instance);
      toast('Applied to the running instance.');
      await routesPoll.refresh();
    } catch (e) { toast(`Apply failed: ${errMsg(e)}`, 'error'); }
    finally { applying = false; }
  }

  interface Chip { text: string; tone?: 'info' | 'off'; }
  function chipsFor(c: RouteConfig | null | undefined): Chip[] {
    const chips: Chip[] = [];
    if (c?.default) chips.push({ text: 'default', tone: 'info' });
    for (const p of c?.prefixes ?? []) chips.push({ text: p });
    if (c?.file) chips.push({ text: `file ${c.file}` });
    for (const f of c?.files ?? []) chips.push({ text: `file ${f}` });
    for (const d of c?.domains ?? []) chips.push({ text: d });
    if (c?.domain_file) chips.push({ text: `domains ${c.domain_file}` });
    for (const f of c?.domain_files ?? []) chips.push({ text: `domains ${f}` });
    if (c?.invert) chips.push({ text: 'invert' });
    return chips.length ? chips : [{ text: '—', tone: 'off' }];
  }
  function targetText(c: RouteConfig | null | undefined): string {
    let t = c?.via ?? '?';
    if (c?.fallback_via) t += ` → ${c.fallback_via}`;
    else if (c?.fallback_direct) t += ' → direct';
    else if (c?.fallback_drop) t += ' → drop';
    return t;
  }
</script>

<section class="view active">
  <div class="page-head">
    <div>
      <h1>Routing</h1>
      <p>Edit policy routes (first-match-wins), then hot-apply to the running instance.</p>
    </div>
    <div class="toolbar">
      <InstanceSelector base="/ws" bind:selected={instance} bind:refreshSecs={refreshSecs} />
    </div>
  </div>

  {#if !instance}
    <div class="empty">Select a client instance to load routes.</div>
  {:else}
    <ErrorBanner message={routesPoll.error} />

    {#if dirty}
      <div class="applybar">
        <span class="dot warn"></span>
        <strong>Pending changes</strong>
        <span class="pill">{instance}: staged, not yet applied</span>
        <div style="margin-left:auto; display:flex; gap:8px">
          <button class="btn primary sm" disabled={applying} onclick={applyNow}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6 9 17l-5-5"/></svg>
            Apply now
          </button>
        </div>
      </div>
    {/if}

    <div class="panel">
      <div class="group-head">
        <span class="gname">Rules</span>
        <span class="gcount">{entries.length}</span>
        <div class="right">
          <button class="btn sm" disabled={mutating} onclick={openCreate}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg>
            Add rule
          </button>
        </div>
      </div>
      {#if entries.length}
        <table>
          <thead><tr><th>#</th><th>Matchers</th><th>Target</th><th>Actions</th></tr></thead>
          <tbody>
            {#each entries as e (e.index)}
              <tr>
                <td>{e.index}</td>
                <td>
                  <div style="display:flex; flex-wrap:wrap; gap:4px">
                    {#each chipsFor(e.config) as c}<span class="chip {c.tone ?? ''}">{c.text}</span>{/each}
                  </div>
                </td>
                <td>{targetText(e.config)}</td>
                <td>
                  <div class="rowactions">
                    <button class="iconbtn" title="Move up" disabled={mutating || e.index === 0} aria-label="Move up" onclick={() => move(e, -1)}>↑</button>
                    <button class="iconbtn" title="Move down" disabled={mutating || e.index === entries.length - 1} aria-label="Move down" onclick={() => move(e, 1)}>↓</button>
                    <button class="iconbtn act-soft" title="Edit" disabled={mutating} aria-label="Edit" onclick={() => openEdit(e)}>
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>
                    </button>
                    <button class="iconbtn act-danger" title="Delete" disabled={mutating || e.is_default} aria-label="Delete" onclick={() => removeRoute(e)}>
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14"/></svg>
                    </button>
                  </div>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {:else if !routesPoll.error}
        <div class="empty">No routes configured for this instance.</div>
      {/if}
    </div>
  {/if}
</section>

<RouteDrawer open={drawerOpen} {groups} {editingEntry} onclose={closeDrawer} onsave={saveRoute} />
