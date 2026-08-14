<script lang="ts">
  import { onDestroy } from 'svelte';
  import { SvelteSet } from 'svelte/reactivity';
  import { groupsList, groupsMutate, groupsReorder, apply } from '../../lib/api';
  import { createPoll } from '../../lib/poll.svelte';
  import { toast } from '../../lib/toast.svelte';
  import type { GroupEntry, GroupsListResponse, GroupConfig, ApplyResult } from '../../lib/types';
  import InstanceSelector from '../../components/layout/InstanceSelector.svelte';
  import ErrorBanner from '../../components/layout/ErrorBanner.svelte';
  import GroupDrawer from './GroupDrawer.svelte';

  let instance = $state('');
  let refreshSecs = $state(5);
  const refreshMs = $derived(Math.max(1000, refreshSecs * 1000));

  const groupsPoll = createPoll<GroupsListResponse>(
    () => (instance ? groupsList(instance) : Promise.resolve<GroupsListResponse>({ groups: [] })),
    () => refreshMs,
  );
  $effect(() => { void instance; groupsPoll.start(); });
  onDestroy(() => groupsPoll.stop());

  const entries = $derived<GroupEntry[]>(groupsPoll.data?.groups ?? []);
  // Preventive hint: a group staged with zero uplinks makes /control/apply fail
  // the "≥1 uplink per group" invariant. Surface the names before Apply.
  const emptyGroups = $derived(entries.filter((g) => g.uplink_count === 0).map((g) => g.name));

  const dirtyInstances = new SvelteSet<string>();
  const dirty = $derived(instance !== '' && dirtyInstances.has(instance));
  let mutating = $state(false);
  let applying = $state(false);
  const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e));

  let drawerOpen = $state(false);
  let editingEntry = $state<GroupEntry | null>(null);
  function openCreate() { editingEntry = null; drawerOpen = true; }
  function openEdit(entry: GroupEntry) { editingEntry = entry; drawerOpen = true; }
  function closeDrawer() { drawerOpen = false; editingEntry = null; }

  async function saveGroup(payload: Record<string, unknown>, editingName: string | null) {
    mutating = true;
    try {
      if (editingName) {
        await groupsMutate('PATCH', instance, { name: editingName, patch: payload });
      } else {
        await groupsMutate('POST', instance, { group: payload });
      }
      dirtyInstances.add(instance);
      toast('Saved to config (not yet applied).');
      closeDrawer();
      await groupsPoll.refresh();
    } catch (e) { toast(errMsg(e), 'error'); }
    finally { mutating = false; }
  }

  async function removeGroup(entry: GroupEntry) {
    if (entry.uplink_count > 0) return; // UI guard; server also refuses (409)
    if (!confirm(`Delete uplink group "${entry.name}"?`)) return;
    mutating = true;
    try {
      await groupsMutate('DELETE', instance, { name: entry.name });
      dirtyInstances.add(instance);
      toast('Deleted from config (not yet applied).');
      await groupsPoll.refresh();
    } catch (e) { toast(errMsg(e), 'error'); }
    finally { mutating = false; }
  }

  // Reorder groups — cosmetic (rewrites config-file order only; selection is by
  // the routing `via` rule, not position). Drag a row or use ↑/↓; both drive
  // groupsReorder(name, to). Mirrors Uplinks.svelte's per-group row drag.
  let draggingName: string | null = $state(null);
  let dragOverName: string | null = $state(null);

  async function reorderTo(name: string, to: number) {
    mutating = true;
    try {
      await groupsReorder(instance, { name, to });
      dirtyInstances.add(instance);
      await groupsPoll.refresh();
    } catch (e) { toast(errMsg(e), 'error'); }
    finally { mutating = false; }
  }
  async function move(i: number, dir: -1 | 1) {
    const to = i + dir;
    if (to < 0 || to >= entries.length) return;
    await reorderTo(entries[i].name, to);
  }
  function handleDragStart(e: DragEvent, name: string) {
    draggingName = name;
    e.dataTransfer?.setData('text/plain', name);
    if (e.dataTransfer) e.dataTransfer.effectAllowed = 'move';
  }
  function handleDragOver(e: DragEvent, name: string) {
    if (draggingName === null) return;
    e.preventDefault();
    if (e.dataTransfer) e.dataTransfer.dropEffect = 'move';
    dragOverName = name;
  }
  function handleDragLeave(name: string) {
    if (dragOverName === name) dragOverName = null;
  }
  async function handleDrop(e: DragEvent, targetIndex: number) {
    e.preventDefault();
    dragOverName = null;
    const from = draggingName;
    draggingName = null;
    if (from === null) return;
    const srcIdx = entries.findIndex((g) => g.name === from);
    if (srcIdx === -1 || srcIdx === targetIndex) return;
    await reorderTo(from, targetIndex);
  }
  function handleDragEnd() {
    draggingName = null;
    dragOverName = null;
  }

  async function applyNow() {
    applying = true;
    try {
      const result = (await apply(instance)) as ApplyResult;
      dirtyInstances.delete(instance);
      toast(`Applied: ${result.groups ?? '?'} groups, ${result.total_uplinks ?? '?'} uplinks.`);
      await groupsPoll.refresh();
    } catch (e) { toast(`Apply failed: ${errMsg(e)}`, 'error'); }
    finally { applying = false; }
  }

  interface Chip { text: string; tone?: 'info' | 'off'; }
  function chipsFor(c: GroupConfig | null | undefined): Chip[] {
    const chips: Chip[] = [];
    if (c?.mode) chips.push({ text: String(c.mode), tone: 'info' });
    if (c?.routing_scope) chips.push({ text: String(c.routing_scope) });
    if (c?.shared_resume) chips.push({ text: 'cluster' });
    if (Array.isArray(c?.reselect_at)) chips.push({ text: `reselect @${(c!.reselect_at as string[]).join(',')}` });
    else if (c?.reselect_interval) chips.push({ text: `reselect ${c.reselect_interval}` });
    if (c?.probe) chips.push({ text: 'probe' });
    return chips.length ? chips : [{ text: '—', tone: 'off' }];
  }
</script>

<section class="view active">
  <div class="page-head">
    <div>
      <h1>Uplink groups</h1>
      <p>Edit group policy (mode, scope, reselect, scoring), then hot-apply to the running instance.</p>
    </div>
    <div class="toolbar">
      <InstanceSelector base="/ws" bind:selected={instance} bind:refreshSecs={refreshSecs} />
    </div>
  </div>

  {#if !instance}
    <div class="empty">Select a client instance to load uplink groups.</div>
  {:else}
    <ErrorBanner message={groupsPoll.error} />

    {#if dirty}
      <div class="applybar">
        <span class="dot warn"></span>
        <strong>Pending changes</strong>
        <span class="pill">{instance}: staged, not yet applied</span>
        {#if emptyGroups.length}
          <span class="pill warn">Empty: {emptyGroups.join(', ')} — add uplinks (Uplinks tab) before applying</span>
        {/if}
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
        <span class="gname">Groups</span>
        <span class="gcount">{entries.length}</span>
        <div class="right">
          <button class="btn sm" disabled={mutating} onclick={openCreate}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg>
            Add group
          </button>
        </div>
      </div>
      {#if entries.length}
        <table>
          <thead><tr><th>Group</th><th>Uplinks</th><th>Policy</th><th>Actions</th></tr></thead>
          <tbody>
            {#each entries as g, i (g.name)}
              <tr
                class:dragging={draggingName === g.name}
                class:drag-over={dragOverName === g.name && draggingName !== g.name}
                draggable={!mutating}
                ondragstart={(ev) => handleDragStart(ev, g.name)}
                ondragover={(ev) => handleDragOver(ev, g.name)}
                ondragleave={() => handleDragLeave(g.name)}
                ondrop={(ev) => handleDrop(ev, i)}
                ondragend={handleDragEnd}
              >
                <td>
                  <span class="route-idx">
                    <span class="drag-handle" aria-hidden="true" title="Drag to reorder">⠿</span>
                    {g.name}
                  </span>
                </td>
                <td>{g.uplink_count}</td>
                <td>
                  <div style="display:flex; flex-wrap:wrap; gap:4px">
                    {#each chipsFor(g.config) as c}<span class="chip {c.tone ?? ''}">{c.text}</span>{/each}
                  </div>
                </td>
                <td>
                  <div class="rowactions">
                    <button class="iconbtn" title="Move up" disabled={mutating || i === 0} aria-label={`Move ${g.name} up`} onclick={() => move(i, -1)}>↑</button>
                    <button class="iconbtn" title="Move down" disabled={mutating || i === entries.length - 1} aria-label={`Move ${g.name} down`} onclick={() => move(i, 1)}>↓</button>
                    <button class="iconbtn act-soft" title="Edit" disabled={mutating} aria-label={`Edit group ${g.name}`} onclick={() => openEdit(g)}>
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>
                    </button>
                    <button
                      class="iconbtn act-danger"
                      title={g.uplink_count > 0 ? 'Remove its uplinks first' : 'Delete'}
                      disabled={mutating || g.uplink_count > 0}
                      aria-label={`Delete group ${g.name}`}
                      onclick={() => removeGroup(g)}
                    >
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14"/></svg>
                    </button>
                  </div>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {:else if !groupsPoll.error}
        <div class="empty">No uplink groups configured for this instance.</div>
      {/if}
    </div>
  {/if}
</section>

<GroupDrawer open={drawerOpen} {editingEntry} onclose={closeDrawer} onsave={saveGroup} />
