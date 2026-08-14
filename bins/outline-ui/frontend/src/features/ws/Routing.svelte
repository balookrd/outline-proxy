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
  // Routing is first-match-wins and the server requires `default` to be the
  // last rule — any rule after it would be dead. Reordering can't be allowed
  // to violate that: the default row must never move up, and the row directly
  // above it must never move down past it. `-1` (no default rule yet) makes
  // both comparisons below false, so it's a no-op when the list has none.
  const defaultIndex = $derived(entries.findIndex((r) => r.is_default));

  const dirtyInstances = new SvelteSet<string>();
  const dirty = $derived(instance !== '' && dirtyInstances.has(instance));
  let mutating = $state(false);
  let applying = $state(false);

  const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e));

  let drawerOpen = $state(false);
  let editingEntry = $state<RouteEntry | null>(null);
  // Snapshot of `revision` taken when the drawer opens. `revision` itself is
  // poll-derived and keeps advancing (~every 5s) while the drawer sits open,
  // so a mutation fired on close must not pick up whatever the poll last saw
  // — it has to carry the revision that was current when the user started
  // editing, or a stale-snapshot edit could silently pass the 409 guard and
  // land on the wrong rule. `move`/`removeRoute` are inline actions with no
  // dwell time, so they keep reading the live `revision` directly.
  let drawerRevision = $state('');
  function openCreate() { editingEntry = null; drawerRevision = revision; drawerOpen = true; }
  function openEdit(entry: RouteEntry) { editingEntry = entry; drawerRevision = revision; drawerOpen = true; }
  function closeDrawer() { drawerOpen = false; editingEntry = null; }

  // Drawer hands back a validated payload; parent owns the API call.
  async function saveRoute(payload: Record<string, unknown>, editingIndex: number | null) {
    mutating = true;
    try {
      if (editingIndex !== null) {
        await routesMutate('PATCH', instance, { index: editingIndex, rule: payload, revision: drawerRevision });
      } else {
        await routesMutate('POST', instance, { rule: payload, revision: drawerRevision });
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

  async function reorderTo(from: number, to: number) {
    mutating = true;
    try {
      await routesReorder(instance, { from, to, revision });
      dirtyInstances.add(instance);
      await routesPoll.refresh();
    } catch (e) { toast(errMsg(e), 'error'); }
    finally { mutating = false; }
  }

  async function move(entry: RouteEntry, dir: -1 | 1) {
    const to = entry.index + dir;
    if (to < 0 || to >= entries.length) return;
    await reorderTo(entry.index, to);
  }

  // Drag-and-drop reorder, mirroring UplinkDrawer.svelte's fallback drag.
  // Move up/down (above) stay as the keyboard/screen-reader path; drag is a
  // pointer-only convenience firing the same routesReorder call. The default
  // rule never participates: its row is not a drag source (draggable=false)
  // and never a valid drop target, so "default stays last" (first-match-wins,
  // nothing may follow the catch-all) holds by construction — the same
  // invariant the ↑/↓ disabled rules enforce.
  let draggingIndex: number | null = $state(null);
  let dragOverIndex: number | null = $state(null);

  function handleDragStart(e: DragEvent, index: number) {
    draggingIndex = index;
    // Firefox won't start a native drag unless some data is set.
    e.dataTransfer?.setData('text/plain', String(index));
    if (e.dataTransfer) e.dataTransfer.effectAllowed = 'move';
  }
  function handleDragOver(e: DragEvent, index: number) {
    if (draggingIndex === null) return;
    // Refuse a drop onto/after the default rule — leaving preventDefault
    // uncalled makes the cursor show "no-drop" over those rows.
    if (defaultIndex !== -1 && index >= defaultIndex) return;
    e.preventDefault(); // a dragover target must preventDefault to accept a drop
    if (e.dataTransfer) e.dataTransfer.dropEffect = 'move';
    dragOverIndex = index;
  }
  function handleDragLeave(index: number) {
    // Guarded so a stale leave (fired after the next row's dragover already
    // moved the highlight) can't clobber that newer state.
    if (dragOverIndex === index) dragOverIndex = null;
  }
  async function handleDrop(e: DragEvent, targetIndex: number) {
    e.preventDefault();
    dragOverIndex = null;
    const from = draggingIndex;
    draggingIndex = null;
    if (from === null || from === targetIndex) return;
    // Defensive: dragover already blocks this, but guard the drop too.
    if (defaultIndex !== -1 && targetIndex >= defaultIndex) return;
    await reorderTo(from, targetIndex);
  }
  function handleDragEnd() {
    // Fires on the source regardless of where the drop landed (or if it was
    // cancelled), so always clear both flags — nothing stays highlighted.
    draggingIndex = null;
    dragOverIndex = null;
  }

  async function applyNow() {
    applying = true;
    try {
      const result = (await apply(instance)) as ApplyResult;
      dirtyInstances.delete(instance);
      // `routes_applied` is absent (not 0) when routing hot-apply was
      // skipped — e.g. this instance never had `[[route]]` at startup, so
      // there is no live table to swap into (see ApplyHandle::shared_routing
      // server-side). Reporting a blanket "Applied" in that case would be a
      // false positive: the uplinks did apply, but a staged routing change
      // is still sitting unapplied on disk until a restart.
      if (result.routes_applied != null) {
        toast(`Applied — ${result.routes_applied} route(s) live.`);
      } else {
        toast(
          'Applied uplinks; routing changes need a node restart (routing not hot-applyable on this instance).',
        );
      }
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
              <tr
                class:dragging={draggingIndex === e.index}
                class:drag-over={dragOverIndex === e.index && draggingIndex !== e.index}
                draggable={!e.is_default && !mutating}
                ondragstart={(ev) => handleDragStart(ev, e.index)}
                ondragover={(ev) => handleDragOver(ev, e.index)}
                ondragleave={() => handleDragLeave(e.index)}
                ondrop={(ev) => handleDrop(ev, e.index)}
                ondragend={handleDragEnd}
              >
                <td>
                  <span class="route-idx">
                    {#if !e.is_default}<span class="drag-handle" aria-hidden="true" title="Drag to reorder">⠿</span>{/if}
                    {e.index}
                  </span>
                </td>
                <td>
                  <div style="display:flex; flex-wrap:wrap; gap:4px">
                    {#each chipsFor(e.config) as c}<span class="chip {c.tone ?? ''}">{c.text}</span>{/each}
                  </div>
                </td>
                <td>{targetText(e.config)}</td>
                <td>
                  <div class="rowactions">
                    <button class="iconbtn" title="Move up" disabled={mutating || e.index === 0 || e.is_default} aria-label={`Move rule #${e.index} up`} onclick={() => move(e, -1)}>↑</button>
                    <button class="iconbtn" title="Move down" disabled={mutating || e.index === entries.length - 1 || e.index === defaultIndex - 1} aria-label={`Move rule #${e.index} down`} onclick={() => move(e, 1)}>↓</button>
                    <button class="iconbtn act-soft" title="Edit" disabled={mutating} aria-label={`Edit rule #${e.index}`} onclick={() => openEdit(e)}>
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>
                    </button>
                    <button class="iconbtn act-danger" title="Delete" disabled={mutating || e.is_default} aria-label={`Delete rule #${e.index}`} onclick={() => removeRoute(e)}>
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14"/></svg>
                    </button>
                  </div>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {:else if !routesPoll.error}
        <div class="empty">
          No routes configured for this instance.
          <p class="hint">Start with the default rule — it's the catch-all every other rule falls through to.</p>
        </div>
      {/if}
    </div>
  {/if}
</section>

<RouteDrawer open={drawerOpen} {groups} {editingEntry} onclose={closeDrawer} onsave={saveRoute} />
