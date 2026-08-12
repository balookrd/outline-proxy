<script lang="ts">
  import { onDestroy, tick } from 'svelte';
  import { SvelteSet } from 'svelte/reactivity';
  import { uplinksList, uplinksMutate, apply } from '../../lib/api';
  import { createPoll } from '../../lib/poll.svelte';
  import { toast } from '../../lib/toast.svelte';
  import type { UplinkEntry, UplinksListResponse, UplinkConfig, ApplyResult } from '../../lib/types';
  import {
    emptyUplinkFields,
    fieldsFromConfig,
    validateUplinkForm,
    buildUplinkPayload,
    TRANSPORTS,
    WS_MODES,
    VLESS_MODES,
    type UplinkFormFields,
  } from '../../lib/uplinkForm';
  import InstanceSelector from '../../components/layout/InstanceSelector.svelte';
  import ErrorBanner from '../../components/layout/ErrorBanner.svelte';

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

  // Drawer (create/edit), always mounted so the backdrop/drawer CSS
  // transitions actually animate — same rationale as
  // features/ss/UserDrawer.svelte's top-of-file comment.
  let drawerOpen = $state(false);
  let drawerMode = $state<'create' | 'edit'>('create');
  let drawerGroup = $state('');
  let drawerName = $state(''); // edit target's identity; blank on create
  let fields = $state<UplinkFormFields>(emptyUplinkFields());
  // $state (not a plain `let`, unlike UserDrawer.svelte's always-rendered
  // idInput) because this element only exists while `drawerMode === 'create'`
  // (uplinks.html hides the name field entirely on edit) — the binding target
  // toggles to `undefined` on every mode switch, which is exactly what
  // svelte's non_reactive_update check warns a plain `let` won't propagate.
  let nameInput: HTMLInputElement | undefined = $state();

  function openCreate(group: string) {
    drawerMode = 'create';
    drawerGroup = group;
    drawerName = '';
    fields = emptyUplinkFields();
    drawerOpen = true;
    tick().then(() => nameInput?.focus());
  }
  function openEdit(group: string, entry: UplinkEntry) {
    drawerMode = 'edit';
    drawerGroup = group;
    drawerName = entry.name;
    fields = fieldsFromConfig(entry.config);
    drawerOpen = true;
  }
  function closeDrawer() {
    drawerOpen = false;
  }

  $effect(() => {
    if (!drawerOpen) return;
    const onKeydown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') closeDrawer();
    };
    window.addEventListener('keydown', onKeydown);
    return () => window.removeEventListener('keydown', onKeydown);
  });
  function onBackdropClick(e: MouseEvent) {
    if (e.target === e.currentTarget) closeDrawer();
  }

  async function submitDrawer(e: SubmitEvent) {
    e.preventDefault();
    const editing = drawerMode === 'edit';
    const error = validateUplinkForm(fields, editing);
    if (error) {
      toast(error, 'error');
      return;
    }
    const payload = buildUplinkPayload(fields, editing);
    mutating = true;
    try {
      if (editing) {
        await uplinksMutate('PATCH', instance, { group: drawerGroup, name: drawerName, patch: payload });
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

  // Row meta chips — mirrors uplinks.html's renderGroups() chip list exactly
  // (same fields, same order, same `!= null` checks for weight/fwmark). The
  // per-transport RTT EWMA chip uplinks.html also renders is deliberately
  // dropped: that data comes from /control/topology (u.tcp_rtt_ewma_ms /
  // u.udp_rtt_ewma_ms), which is out of scope here — see task-8-report.md.
  interface Chip {
    text: string;
    tone?: 'info' | 'off';
  }
  function chipsFor(cfg: UplinkConfig | null | undefined): Chip[] {
    const chips: Chip[] = [];
    if (cfg?.transport) chips.push({ text: String(cfg.transport), tone: 'info' });
    if (cfg?.tcp_ws_url) chips.push({ text: `TCP WS ${cfg.tcp_ws_url}` });
    if (cfg?.tcp_mode) chips.push({ text: `TCP mode ${cfg.tcp_mode}` });
    if (cfg?.udp_ws_url) chips.push({ text: `UDP WS ${cfg.udp_ws_url}` });
    if (cfg?.udp_mode) chips.push({ text: `UDP mode ${cfg.udp_mode}` });
    if (cfg?.vless_ws_url) chips.push({ text: `VLESS WS ${cfg.vless_ws_url}` });
    if (cfg?.vless_xhttp_url) chips.push({ text: `VLESS XHTTP ${cfg.vless_xhttp_url}` });
    if (cfg?.vless_mode) chips.push({ text: `VLESS mode ${cfg.vless_mode}` });
    if (cfg?.method) chips.push({ text: String(cfg.method) });
    if (cfg?.weight != null) chips.push({ text: `w=${cfg.weight}` });
    if (cfg?.fwmark != null) chips.push({ text: `fwmark=${cfg.fwmark}` });
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
              {#each g.uplinks as u (u.name)}
                <tr>
                  <td>{u.name}</td>
                  <td>
                    <div style="display:flex; flex-wrap:wrap; gap:4px">
                      {#each chipsFor(u.config) as c}
                        <span class="chip {c.tone ?? ''}">{c.text}</span>
                      {/each}
                    </div>
                  </td>
                  <td>
                    <div class="rowactions">
                      <button
                        class="iconbtn"
                        title="Edit"
                        disabled={mutating}
                        aria-label={`Edit ${u.name}`}
                        onclick={() => openEdit(g.name, u)}
                      >
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>
                      </button>
                      <button
                        class="iconbtn danger"
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

<div class="backdrop" class:open={drawerOpen} onclick={onBackdropClick} role="presentation"></div>
<aside class="drawer" class:open={drawerOpen} aria-hidden={!drawerOpen}>
  <header>
    <h3>
      {#if drawerMode === 'create'}
        Add uplink to &quot;{drawerGroup}&quot;
      {:else}
        Edit &quot;{drawerName}&quot; in &quot;{drawerGroup}&quot;
      {/if}
    </h3>
    <span class="spacer"></span>
    <button class="iconbtn" type="button" aria-label="Close" onclick={closeDrawer}>
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6 6 18M6 6l12 12"/></svg>
    </button>
  </header>
  <form class="body" id="uplink-drawer-form" onsubmit={submitDrawer}>
    {#if drawerMode === 'create'}
      <div class="fieldrow">
        <label for="uplink-name">Name</label>
        <input id="uplink-name" class="field-mono" type="text" bind:value={fields.name} bind:this={nameInput} required autocomplete="off" placeholder="cloud1" />
        <span class="hint">Required for create.</span>
      </div>
    {/if}
    <div class="fieldrow">
      <label for="uplink-transport">Transport</label>
      <select id="uplink-transport" class="field-mono" bind:value={fields.transport}>
        {#each TRANSPORTS as t}<option value={t}>{t}</option>{/each}
      </select>
    </div>
    <div class="fieldrow">
      <label for="uplink-method">Cipher</label>
      <input id="uplink-method" class="field-mono" type="text" bind:value={fields.method} autocomplete="off" />
    </div>
    <div class="fieldrow">
      <label for="uplink-password">Password</label>
      <input id="uplink-password" class="field-mono" type="text" bind:value={fields.password} autocomplete="off" />
    </div>
    <div class="fieldrow">
      <label for="uplink-vless-id">VLESS id</label>
      <input id="uplink-vless-id" class="field-mono" type="text" bind:value={fields.vlessId} autocomplete="off" />
    </div>
    <div class="fieldrow">
      <label for="uplink-tcp-ws-url">TCP WS URL (transport=ws)</label>
      <input id="uplink-tcp-ws-url" class="field-mono" type="text" bind:value={fields.tcpWsUrl} autocomplete="off" />
    </div>
    <div class="fieldrow">
      <label for="uplink-tcp-mode">TCP mode (transport=ws)</label>
      <select id="uplink-tcp-mode" class="field-mono" bind:value={fields.tcpMode}>
        {#each WS_MODES as m}<option value={m}>{m === '' ? '—' : m}</option>{/each}
      </select>
    </div>
    <div class="fieldrow">
      <label for="uplink-udp-ws-url">UDP WS URL (transport=ws)</label>
      <input id="uplink-udp-ws-url" class="field-mono" type="text" bind:value={fields.udpWsUrl} autocomplete="off" />
    </div>
    <div class="fieldrow">
      <label for="uplink-udp-mode">UDP mode (transport=ws)</label>
      <select id="uplink-udp-mode" class="field-mono" bind:value={fields.udpMode}>
        {#each WS_MODES as m}<option value={m}>{m === '' ? '—' : m}</option>{/each}
      </select>
    </div>
    <div class="fieldrow">
      <label for="uplink-vless-ws-url">VLESS WS URL (vless_mode=ws_*)</label>
      <input id="uplink-vless-ws-url" class="field-mono" type="text" bind:value={fields.vlessWsUrl} autocomplete="off" />
    </div>
    <div class="fieldrow">
      <label for="uplink-vless-xhttp-url">VLESS XHTTP URL (vless_mode=xhttp_*)</label>
      <input id="uplink-vless-xhttp-url" class="field-mono" type="text" bind:value={fields.vlessXhttpUrl} autocomplete="off" />
    </div>
    <div class="fieldrow">
      <label for="uplink-vless-mode">VLESS mode</label>
      <select id="uplink-vless-mode" class="field-mono" bind:value={fields.vlessMode}>
        {#each VLESS_MODES as m}<option value={m}>{m === '' ? '—' : m}</option>{/each}
      </select>
    </div>
    <div class="fieldrow">
      <label for="uplink-weight">Weight</label>
      <input id="uplink-weight" class="field-mono" type="number" step="0.1" bind:value={fields.weight} placeholder="default" />
    </div>
    <div class="fieldrow">
      <label for="uplink-fwmark">fwmark</label>
      <input id="uplink-fwmark" class="field-mono" type="number" step="1" bind:value={fields.fwmark} placeholder="default" />
    </div>
    <div class="fieldrow">
      <label for="uplink-ipv6-first">IPv6 first</label>
      <select id="uplink-ipv6-first" class="field-mono" bind:value={fields.ipv6First}>
        <option value="">—</option>
        <option value="true">true</option>
        <option value="false">false</option>
      </select>
    </div>
    {#if drawerMode === 'edit'}
      <span class="hint">Every non-empty field above is sent, including unchanged ones — blank fields stay untouched on the server.</span>
    {/if}
  </form>
  <div class="foot">
    <button class="btn ghost" type="button" onclick={closeDrawer} disabled={mutating}>Cancel</button>
    <button class="btn primary" type="submit" form="uplink-drawer-form" disabled={mutating}>
      {drawerMode === 'create' ? 'Create' : 'Update'}
    </button>
  </div>
</aside>
