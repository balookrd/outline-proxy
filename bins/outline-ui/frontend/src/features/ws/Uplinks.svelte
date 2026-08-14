<script lang="ts">
  import { onDestroy } from 'svelte';
  import { SvelteSet } from 'svelte/reactivity';
  import { uplinksList, uplinksMutate, uplinksReorder, apply } from '../../lib/api';
  import { createPoll } from '../../lib/poll.svelte';
  import { toast } from '../../lib/toast.svelte';
  import type { UplinkEntry, UplinksListResponse, UplinkConfig, ApplyResult } from '../../lib/types';
  import InstanceSelector from '../../components/layout/InstanceSelector.svelte';
  import ErrorBanner from '../../components/layout/ErrorBanner.svelte';
  import UplinkDrawer from './UplinkDrawer.svelte';

  let instance = $state('');
  let refreshSecs = $state(5);
  const refreshMs = $derived(Math.max(1000, refreshSecs * 1000));

  // No instance selected yet → resolve to an empty list without hitting the
  // network (mirrors features/ss/Users.svelte's loadUsers() guard, which
  // itself mirrors dashboard.html).
  const uplinksPoll = createPoll<UplinksListResponse>(
    () => (instance ? uplinksList(instance) : Promise.resolve<UplinksListResponse>({ uplinks: [] })),
    () => refreshMs,
  );

  $effect(() => {
    void instance;
    uplinksPoll.start();
  });
  onDestroy(() => uplinksPoll.stop());

  const entries = $derived(uplinksPoll.data?.uplinks ?? []);

  // Group the flat entry list by `group`, preserving first-seen order —
  // mirrors uplinks.html's per-group `.panel` sections. Unlike uplinks.html
  // (which sources its group/uplink *names* from /control/topology and only
  // uses /control/uplinks to enrich rows with `config`), this view's sole
  // data source is uplinksList() per task-8-brief.md, so a group with zero
  // uplinks simply can't appear here — topology-derived group listings are
  // Task 9/10's job. See task-8-report.md "Concerns".
  interface GroupBucket {
    name: string;
    uplinks: UplinkEntry[];
  }
  const groups = $derived.by((): GroupBucket[] => {
    const byName = new Map<string, GroupBucket>();
    for (const e of entries) {
      let bucket = byName.get(e.group);
      if (!bucket) {
        bucket = { name: e.group, uplinks: [] };
        byName.set(e.group, bucket);
      }
      bucket.uplinks.push(e);
    }
    return [...byName.values()];
  });

  // Pending/apply state — mirrors uplinks.html's `state.dirtyInstances`
  // exactly: a Set of instance names, set locally on every *successful*
  // create/edit/delete and cleared only by a successful /control/apply. It
  // is not derived from any server response — the mutation responses'
  // `apply_required`/`restart_required` fields (see
  // uplinks_crud/payload.rs `MutationResponse`) are ignored, same as
  // uplinks.html's submitForm()/deleteUplink() ignore them.
  const dirtyInstances = new SvelteSet<string>();
  const dirty = $derived(instance !== '' && dirtyInstances.has(instance));

  let mutating = $state(false);
  let applying = $state(false);

  function errorMessage(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
  }

  // Drawer (create/edit), split into its own component (Task 8 review Minor
  // #4) — mirrors features/ss/Users.svelte + UserDrawer.svelte exactly.
  // `editingEntry` is a snapshot taken at the moment "Edit" is clicked, not a
  // live binding into `entries` — a background poll refresh while the
  // drawer is open must not overwrite an in-progress edit.
  let drawerOpen = $state(false);
  let drawerGroup = $state('');
  let editingEntry = $state<UplinkEntry | null>(null);

  function openCreate(group: string) {
    drawerGroup = group;
    editingEntry = null;
    drawerOpen = true;
  }
  function openEdit(group: string, entry: UplinkEntry) {
    drawerGroup = group;
    editingEntry = entry;
    drawerOpen = true;
  }
  function closeDrawer() {
    drawerOpen = false;
    editingEntry = null;
  }

  // Passed to UplinkDrawer as `onsave`. The drawer already validated and
  // built the payload (lib/uplinkForm.ts); this does the actual API call,
  // the success/error toast, the dirty-instance flag, and — on success —
  // closes the drawer and refetches the list immediately instead of waiting
  // for the next poll tick. Mirrors features/ss/Users.svelte's saveUser().
  async function saveUplink(payload: Record<string, unknown>, editingName: string | null) {
    mutating = true;
    try {
      if (editingName) {
        await uplinksMutate('PATCH', instance, { group: drawerGroup, name: editingName, patch: payload });
      } else {
        await uplinksMutate('POST', instance, { group: drawerGroup, uplink: payload });
      }
      dirtyInstances.add(instance);
      toast('Saved to config (not yet applied).');
      closeDrawer();
      await uplinksPoll.refresh();
    } catch (err) {
      toast(errorMessage(err), 'error');
    } finally {
      mutating = false;
    }
  }

  async function removeUplink(group: string, name: string) {
    if (!confirm(`Delete uplink "${name}" from "${group}"?`)) return;
    mutating = true;
    try {
      await uplinksMutate('DELETE', instance, { group, name });
      dirtyInstances.add(instance);
      toast('Deleted from config (not yet applied).');
      await uplinksPoll.refresh();
    } catch (err) {
      toast(errorMessage(err), 'error');
    } finally {
      mutating = false;
    }
  }

  // Reorder within a group. Uplink order is cosmetic — active-uplink selection
  // is by weight/RTT, not list position — so this only rewrites config/display
  // order, no balancing change. Mirrors Routing.svelte's row drag, scoped per
  // group: a drop reorders only when source and target are the same group
  // (the on-disk array is flat but group-addressed server-side).
  let draggingName: string | null = $state(null);
  let dragOverName: string | null = $state(null);

  async function reorderTo(group: string, name: string, to: number) {
    mutating = true;
    try {
      await uplinksReorder(instance, { group, name, to });
      dirtyInstances.add(instance);
      await uplinksPoll.refresh();
    } catch (err) {
      toast(errorMessage(err), 'error');
    } finally {
      mutating = false;
    }
  }
  async function move(group: string, uplinks: UplinkEntry[], i: number, dir: -1 | 1) {
    const to = i + dir;
    if (to < 0 || to >= uplinks.length) return;
    await reorderTo(group, uplinks[i].name, to);
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
  async function handleDrop(
    e: DragEvent,
    group: string,
    uplinks: UplinkEntry[],
    targetIndex: number,
  ) {
    e.preventDefault();
    dragOverName = null;
    const from = draggingName;
    draggingName = null;
    if (from === null) return;
    // Reorder only within a group: a drag whose source isn't among this
    // group's rows (i.e. dragged across groups) is ignored.
    const srcIdx = uplinks.findIndex((u) => u.name === from);
    if (srcIdx === -1 || srcIdx === targetIndex) return;
    await reorderTo(group, from, targetIndex);
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
      await uplinksPoll.refresh();
    } catch (err) {
      toast(`Apply failed: ${errorMessage(err)}`, 'error');
    } finally {
      applying = false;
    }
  }

  // Row meta chips — mirrors uplinks.html's renderGroups() chip list (same
  // fields, same order, same `!= null` checks for weight/fwmark), extended
  // for the fields Task 8b adds to the drawer (tcp_xhttp_url/udp_xhttp_url/
  // ss_*/link) so a row never claims "no on-disk config" for an uplink that
  // actually has one — e.g. a share-link uplink's on-disk table has only
  // `link` set (see lib/uplinkForm.ts's fieldsFromConfig doc comment), which
  // the pre-8b chip list didn't recognize at all. `link`'s raw value is
  // never rendered (it embeds credentials — a vless UUID or an ss method:
  // password — same reason `password` itself isn't rendered as a chip).
  // The per-transport RTT EWMA chip uplinks.html also renders is
  // deliberately dropped: that data comes from /control/topology
  // (u.tcp_rtt_ewma_ms/u.udp_rtt_ewma_ms), out of scope here — see
  // task-8-report.md.
  interface Chip {
    text: string;
    tone?: 'info' | 'off';
  }

  // Every URL an uplink may carry. A share-link uplink has only `link` on disk
  // (transport/carrier expansion happens server-side at load — see types.ts),
  // so `link` is its sole source; explicit-field uplinks carry one or more of
  // the *_ws_url/*_xhttp_url instead.
  function wireUrls(cfg: UplinkConfig): string[] {
    return [
      cfg.link,
      cfg.tcp_ws_url, cfg.tcp_xhttp_url,
      cfg.udp_ws_url, cfg.udp_xhttp_url,
      cfg.vless_ws_url, cfg.vless_xhttp_url,
      cfg.ss_ws_url, cfg.ss_xhttp_url,
    ].filter((s): s is string => typeof s === 'string' && s.length > 0);
  }

  function chipsFor(cfg: UplinkConfig | null | undefined): Chip[] {
    if (!cfg) return [{ text: 'no on-disk config', tone: 'off' }];
    const chips: Chip[] = [];
    const seen = new Set<string>();
    const add = (text: string, tone?: 'info' | 'off') => {
      if (seen.has(text)) return;
      seen.add(text);
      chips.push(tone ? { text, tone } : { text });
    };

    if (cfg.link) add('share-link', 'info');
    if (cfg.transport) add(String(cfg.transport), 'info');

    // Decompose every wire URL into its parts. `URL()` parses the authority
    // and query of any `scheme://…` (vless://, ss://, ws(s)://, http(s)://)
    // uniformly; a malformed value is skipped. The userinfo (a vless UUID or
    // ss `method:password`) is the wire's secret and is deliberately never
    // emitted — everything else (schema/host/port/path and every query param:
    // type, security, alpn, mode, sni, fp, pbk, flow, …) becomes a chip.
    for (const raw of wireUrls(cfg)) {
      let u: URL;
      try {
        u = new URL(raw.trim());
      } catch {
        continue;
      }
      add(`schema ${u.protocol.replace(/:$/, '')}`);
      if (u.hostname) add(`host ${u.hostname}`);
      if (u.port) add(`port ${u.port}`);
      if (u.pathname && u.pathname !== '/') add(`path ${decodeURIComponent(u.pathname)}`);
      for (const [k, v] of u.searchParams) {
        if (v) add(`${k} ${v}`);
      }
    }

    // *_mode are explicit config keys, not URL query — fold them into the same
    // `mode <x>` shape (add() de-dupes against any URL `mode` param).
    for (const m of [cfg.tcp_mode, cfg.udp_mode, cfg.vless_mode, cfg.ss_mode]) {
      if (m) add(`mode ${m}`);
    }

    // method (cipher) is a public algorithm name, not a secret — password and
    // vless_id are, and are never rendered.
    if (cfg.method) add(String(cfg.method));
    if (cfg.weight != null) add(`w=${cfg.weight}`);
    if (cfg.fwmark != null) add(`fwmark=${cfg.fwmark}`);

    return chips.length ? chips : [{ text: 'no on-disk config', tone: 'off' }];
  }
</script>

<section class="view active">
  <div class="page-head">
    <div>
      <h1>Uplinks</h1>
      <p>Edit uplink definitions, then hot-apply to the running instance.</p>
    </div>
    <div class="toolbar">
      <InstanceSelector base="/ws" bind:selected={instance} bind:refreshSecs={refreshSecs} />
    </div>
  </div>

  {#if !instance}
    <div class="empty">Select a client instance to load uplinks.</div>
  {:else}
    <ErrorBanner message={uplinksPoll.error} />

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

    {#if groups.length}
      {#each groups as g (g.name)}
        <div class="panel" style="margin-bottom: var(--sp-4)">
          <div class="group-head">
            <span class="gname">{g.name}</span>
            <span class="gcount">{g.uplinks.length} uplinks</span>
            <div class="right">
              <button class="btn sm" disabled={mutating} onclick={() => openCreate(g.name)}>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg>
                Add uplink
              </button>
            </div>
          </div>
          <table>
            <thead>
              <tr><th>Uplink</th><th>Config</th><th>Actions</th></tr>
            </thead>
            <tbody>
              {#each g.uplinks as u, i (u.name)}
                <tr
                  class:dragging={draggingName === u.name}
                  class:drag-over={dragOverName === u.name && draggingName !== u.name}
                  draggable={!mutating}
                  ondragstart={(ev) => handleDragStart(ev, u.name)}
                  ondragover={(ev) => handleDragOver(ev, u.name)}
                  ondragleave={() => handleDragLeave(u.name)}
                  ondrop={(ev) => handleDrop(ev, g.name, g.uplinks, i)}
                  ondragend={handleDragEnd}
                >
                  <td>
                    <span class="route-idx">
                      <span class="drag-handle" aria-hidden="true" title="Drag to reorder">⠿</span>
                      {u.name}
                    </span>
                  </td>
                  <td>
                    <div style="display:flex; flex-wrap:wrap; gap:4px">
                      {#each chipsFor(u.config) as c}
                        <span class="chip {c.tone ?? ''}">{c.text}</span>
                      {/each}
                    </div>
                  </td>
                  <td>
                    <div class="rowactions">
                      <button class="iconbtn" title="Move up" disabled={mutating || i === 0} aria-label={`Move ${u.name} up`} onclick={() => move(g.name, g.uplinks, i, -1)}>↑</button>
                      <button class="iconbtn" title="Move down" disabled={mutating || i === g.uplinks.length - 1} aria-label={`Move ${u.name} down`} onclick={() => move(g.name, g.uplinks, i, 1)}>↓</button>
                      <button
                        class="iconbtn act-soft"
                        title="Edit"
                        disabled={mutating}
                        aria-label={`Edit ${u.name}`}
                        onclick={() => openEdit(g.name, u)}
                      >
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>
                      </button>
                      <button
                        class="iconbtn act-danger"
                        title="Delete"
                        disabled={mutating}
                        aria-label={`Delete ${u.name}`}
                        onclick={() => removeUplink(g.name, u.name)}
                      >
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14"/></svg>
                      </button>
                    </div>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/each}
    {:else if !uplinksPoll.error}
      <div class="empty">No uplinks configured for this instance.</div>
    {/if}
  {/if}
</section>

<UplinkDrawer open={drawerOpen} group={drawerGroup} {editingEntry} onclose={closeDrawer} onsave={saveUplink} />
