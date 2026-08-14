<script lang="ts">
  import { tick } from 'svelte';
  import type { GroupEntry } from '../../lib/types';
  import {
    ADVANCED_FIELDS,
    MODES,
    SCOPES,
    emptyGroupFields,
    fieldsFromConfig,
    validateGroupForm,
    buildGroupPayload,
    type GroupFormFields,
  } from '../../lib/groupForm';
  import { toast } from '../../lib/toast.svelte';

  let {
    open,
    editingEntry = null,
    onclose,
    onsave,
  }: {
    open: boolean;
    editingEntry?: GroupEntry | null;
    onclose: () => void;
    onsave: (payload: Record<string, unknown>, editingName: string | null) => Promise<void>;
  } = $props();

  const editing = $derived(editingEntry !== null);
  let fields = $state<GroupFormFields>(emptyGroupFields());
  let saving = $state(false);
  let nameInput: HTMLInputElement | undefined = $state();

  // Sections in declaration order (Failover, Scoring, Keepalive, …).
  const sections = $derived.by(() => {
    const seen: string[] = [];
    for (const f of ADVANCED_FIELDS) if (!seen.includes(f.section)) seen.push(f.section);
    return seen;
  });
  function fieldsIn(section: string) {
    return ADVANCED_FIELDS.filter((f) => f.section === section);
  }

  $effect(() => {
    if (!open) return;
    fields = editingEntry ? fieldsFromConfig(editingEntry.config) : emptyGroupFields();
    if (!editingEntry) tick().then(() => nameInput?.focus());
  });

  $effect(() => {
    if (!open) return;
    const onKeydown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onclose();
    };
    window.addEventListener('keydown', onKeydown);
    return () => window.removeEventListener('keydown', onKeydown);
  });
  function onBackdropClick(e: MouseEvent) {
    if (e.target === e.currentTarget) onclose();
  }

  async function handleSubmit(e: SubmitEvent) {
    e.preventDefault();
    const error = validateGroupForm(fields, editing);
    if (error) {
      toast(error, 'error');
      return;
    }
    const payload = buildGroupPayload(fields, editing);
    saving = true;
    try {
      await onsave(payload, editing ? (editingEntry as GroupEntry).name : null);
    } finally {
      saving = false;
    }
  }
</script>

<div class="backdrop" class:open onclick={onBackdropClick} role="presentation"></div>
<aside class="drawer" class:open aria-hidden={!open}>
  <header>
    <h3>{#if editing}Edit group &quot;{editingEntry?.name}&quot;{:else}Add uplink group{/if}</h3>
    <span class="spacer"></span>
    <button class="iconbtn" type="button" aria-label="Close" onclick={onclose}>
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6 6 18M6 6l12 12"/></svg>
    </button>
  </header>
  <form class="body" id="group-drawer-form" onsubmit={handleSubmit}>
    {#if !editing}
      <div class="fieldrow">
        <label for="group-name">Name</label>
        <input id="group-name" class="field-mono" type="text" bind:value={fields.name} bind:this={nameInput} required autocomplete="off" placeholder="main" />
        <span class="hint">Immutable after creation. Create the group empty, then add uplinks in the Uplinks tab.</span>
      </div>
    {/if}

    <div class="fieldrow">
      <label for="group-mode">Mode</label>
      <select id="group-mode" class="field-mono" bind:value={fields.mode}>
        {#each MODES as m}<option value={m}>{m}</option>{/each}
      </select>
    </div>
    <div class="fieldrow">
      <label for="group-scope">Routing scope</label>
      <select id="group-scope" class="field-mono" bind:value={fields.routingScope}>
        {#each SCOPES as s}<option value={s}>{s}</option>{/each}
      </select>
    </div>
    <div class="fieldrow">
      <label for="group-wstcp">Warm standby TCP</label>
      <input id="group-wstcp" class="field-mono" type="number" step="1" bind:value={fields.warmStandbyTcp} placeholder="default" />
    </div>
    <div class="fieldrow">
      <label for="group-wsudp">Warm standby UDP</label>
      <input id="group-wsudp" class="field-mono" type="number" step="1" bind:value={fields.warmStandbyUdp} placeholder="default" />
    </div>
    <div class="switch">
      <input id="group-cluster" type="checkbox" bind:checked={fields.sharedResume} />
      <label for="group-cluster">Shared resume (cluster)</label>
    </div>

    <fieldset class="fieldset">
      <legend>Reselect</legend>
      <div class="fieldrow">
        <label for="group-reselect-mode">Schedule</label>
        <select id="group-reselect-mode" class="field-mono" bind:value={fields.reselectMode}>
          <option value="none">none</option>
          <option value="at">at times (HH:MM)</option>
          <option value="interval">interval</option>
        </select>
      </div>
      {#if fields.reselectMode === 'at'}
        <div class="fieldrow">
          <label for="group-reselect-at">Times</label>
          <textarea id="group-reselect-at" class="field-mono" rows="3" bind:value={fields.reselectAt} placeholder="03:00&#10;15:00"></textarea>
          <span class="hint">One HH:MM (local time) per line.</span>
        </div>
        <div class="switch">
          <input id="group-reselect-sync" type="checkbox" bind:checked={fields.reselectSync} />
          <label for="group-reselect-sync">Sync order across nodes</label>
        </div>
      {:else if fields.reselectMode === 'interval'}
        <div class="fieldrow">
          <label for="group-reselect-interval">Interval</label>
          <input id="group-reselect-interval" class="field-mono" type="text" bind:value={fields.reselectInterval} placeholder="10h / 1h30m" />
        </div>
      {/if}
      <span class="hint">Reselect requires mode = active_passive and routing_scope = global/per_uplink.</span>
    </fieldset>

    {#each sections as section}
      <details class="fieldset">
        <summary>{section}</summary>
        {#each fieldsIn(section) as fld (fld.key)}
          <div class="fieldrow">
            <label for={`group-adv-${fld.key}`}>{fld.label}</label>
            {#if fld.kind === 'bool'}
              <select id={`group-adv-${fld.key}`} class="field-mono" bind:value={fields.advanced[fld.key]}>
                <option value="">default</option>
                <option value="true">true</option>
                <option value="false">false</option>
              </select>
            {:else if fld.kind === 'enum'}
              <select id={`group-adv-${fld.key}`} class="field-mono" bind:value={fields.advanced[fld.key]}>
                <option value="">default</option>
                {#each fld.options ?? [] as opt}<option value={opt}>{opt}</option>{/each}
              </select>
            {:else}
              <input id={`group-adv-${fld.key}`} class="field-mono" type="number" step={fld.kind === 'float' ? 'any' : '1'} bind:value={fields.advanced[fld.key]} placeholder="default" />
            {/if}
          </div>
        {/each}
      </details>
    {/each}
  </form>
  <div class="foot">
    <button class="btn ghost" type="button" onclick={onclose} disabled={saving}>Cancel</button>
    <button class="btn primary" type="submit" form="group-drawer-form" disabled={saving}>{editing ? 'Update' : 'Create'}</button>
  </div>
</aside>
