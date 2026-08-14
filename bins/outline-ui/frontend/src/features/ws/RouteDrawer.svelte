<script lang="ts">
  import type { RouteEntry } from '../../lib/types';
  import {
    emptyRouteFields, fieldsFromConfig, validateRouteForm, buildRoutePayload,
    TARGET_KINDS, type RouteFormFields, type FallbackKind,
  } from '../../lib/routeForm';
  import { toast } from '../../lib/toast.svelte';

  let { open, groups, editingEntry = null, onclose, onsave }: {
    open: boolean;
    groups: string[];
    editingEntry?: RouteEntry | null;
    onclose: () => void;
    onsave: (payload: Record<string, unknown>, editingIndex: number | null) => Promise<void>;
  } = $props();

  const editing = $derived(editingEntry !== null);
  let fields = $state<RouteFormFields>(emptyRouteFields());
  let saving = $state(false);

  // Repopulate on open only (never mid-edit from a poll refresh).
  $effect(() => {
    if (!open) return;
    fields = editingEntry ? fieldsFromConfig(editingEntry.config) : emptyRouteFields();
  });

  $effect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onclose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  });
  function onBackdrop(e: MouseEvent) { if (e.target === e.currentTarget) onclose(); }

  // `via` picker: reserved targets + reported group names.
  const viaOptions = $derived<string[]>([...TARGET_KINDS, ...groups]);
  const fallbackKinds: { value: FallbackKind; label: string }[] = [
    { value: '', label: '— none —' },
    { value: 'via', label: 'group' },
    { value: 'direct', label: 'direct' },
    { value: 'drop', label: 'drop' },
  ];

  async function handleSubmit(e: SubmitEvent) {
    e.preventDefault();
    const err = validateRouteForm(fields);
    if (err) { toast(err, 'error'); return; }
    saving = true;
    try {
      await onsave(buildRoutePayload(fields), editing ? (editingEntry as RouteEntry).index : null);
    } finally { saving = false; }
  }
</script>

<div class="backdrop" class:open onclick={onBackdrop} role="presentation"></div>
<aside class="drawer" class:open aria-hidden={!open}>
  <header>
    <h3>{editing ? `Edit route #${editingEntry?.index}` : 'Add route'}</h3>
    <span class="spacer"></span>
    <button class="iconbtn" type="button" aria-label="Close" onclick={onclose}>
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6 6 18M6 6l12 12"/></svg>
    </button>
  </header>
  <form class="body" id="route-drawer-form" onsubmit={handleSubmit}>
    <div class="switch">
      <input id="route-default" type="checkbox" bind:checked={fields.isDefault} disabled={editing && editingEntry?.is_default} />
      <label for="route-default">Default rule (catch-all; no matchers)</label>
    </div>

    <div class="fieldrow">
      <label for="route-via">Target (via)</label>
      <select id="route-via" class="field-mono" bind:value={fields.via}>
        <option value="">— pick —</option>
        {#each viaOptions as v}<option value={v}>{v}</option>{/each}
      </select>
      <span class="hint">A group name, or reserved <code>direct</code> / <code>drop</code>.</span>
    </div>

    {#if !fields.isDefault}
      <fieldset class="fieldset">
        <legend>Matchers (one per line)</legend>
        <div class="fieldrow">
          <label for="route-prefixes">CIDR prefixes</label>
          <textarea id="route-prefixes" class="field-mono" rows="3" bind:value={fields.prefixes} placeholder="10.0.0.0/8"></textarea>
        </div>
        <div class="fieldrow">
          <label for="route-files">Prefix files</label>
          <textarea id="route-files" class="field-mono" rows="2" bind:value={fields.files} placeholder="/etc/outline-ws-rust/geoip-cn.list"></textarea>
        </div>
        <div class="fieldrow">
          <label for="route-domains">Domain suffixes</label>
          <textarea id="route-domains" class="field-mono" rows="3" bind:value={fields.domains} placeholder="example.com"></textarea>
        </div>
        <div class="fieldrow">
          <label for="route-domain-files">Domain files</label>
          <textarea id="route-domain-files" class="field-mono" rows="2" bind:value={fields.domainFiles}></textarea>
        </div>
        <div class="fieldrow">
          <label for="route-poll">File poll (secs)</label>
          <input id="route-poll" class="field-mono" type="number" step="1" bind:value={fields.filePollSecs} placeholder="60" />
        </div>
        <div class="switch">
          <input id="route-invert" type="checkbox" bind:checked={fields.invert} />
          <label for="route-invert">Invert (match addresses NOT in the CIDR set; CIDR-only)</label>
        </div>
      </fieldset>
    {/if}

    <fieldset class="fieldset">
      <legend>Fallback (when the via group has no healthy uplink)</legend>
      <div class="fieldrow">
        <label for="route-fb-kind">Fallback</label>
        <select id="route-fb-kind" class="field-mono" bind:value={fields.fallbackKind}>
          {#each fallbackKinds as k}<option value={k.value}>{k.label}</option>{/each}
        </select>
      </div>
      {#if fields.fallbackKind === 'via'}
        <div class="fieldrow">
          <label for="route-fb-via">Fallback group</label>
          <select id="route-fb-via" class="field-mono" bind:value={fields.fallbackVia}>
            <option value="">— pick —</option>
            {#each groups as g}<option value={g}>{g}</option>{/each}
          </select>
        </div>
      {/if}
    </fieldset>
  </form>
  <div class="foot">
    <button class="btn ghost" type="button" onclick={onclose} disabled={saving}>Cancel</button>
    <button class="btn primary" type="submit" form="route-drawer-form" disabled={saving}>{editing ? 'Update' : 'Create'}</button>
  </div>
</aside>
