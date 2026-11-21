<script lang="ts">
  import { tick } from 'svelte';
  import type { User, NewUser, PatchUser } from '../../lib/types';
  import {
    emptyUserFields, fieldsFromUser, validateUserForm, buildUserPayload,
    generatePassword, generateVlessId, webCryptoBytes,
  } from '../../lib/userForm';
  import type { UserFormFields } from '../../lib/userForm';
  import { toast } from '../../lib/toast.svelte';

  let {
    open,
    editingUser = null,
    seedFields = null,
    seedNeedsPassword = false,
    defaultMethod = '',
    clusterName = null,
    clusterMembers = [],
    onclose,
    onsave,
  }: {
    open: boolean;
    editingUser?: User | null;
    seedFields?: UserFormFields | null;
    seedNeedsPassword?: boolean;
    defaultMethod?: string;
    clusterName?: string | null;
    clusterMembers?: string[];
    onclose: () => void;
    onsave: (payload: NewUser | PatchUser, editingId: string | null) => Promise<void>;
  } = $props();

  const editing = $derived(editingUser !== null);
  const hasPassword = $derived(Boolean(editingUser?.has_password));
  const hasVlessId = $derived(Boolean(editingUser?.has_vless_id));
  const cloning = $derived(!editing && seedFields != null);
  let showSecret = $state(false);

  let fields = $state(emptyUserFields());
  let saving = $state(false);
  let idInput: HTMLInputElement | undefined;

  function regeneratePassword() {
    const effectiveMethod = fields.method || defaultMethod;
    const pw = generatePassword(effectiveMethod, webCryptoBytes);
    if (pw === null) {
      toast('Choose a method to generate a password.', 'error');
      return;
    }
    fields.password = pw;
    showSecret = true;
  }

  function regenerateVlessId() {
    fields.vlessId = generateVlessId();
    showSecret = true;
  }

  function onMethodChange(e: Event) {
    if (!cloning) return;
    const method = (e.currentTarget as HTMLSelectElement).value;
    const pw = generatePassword(method || defaultMethod, webCryptoBytes);
    fields.password = pw ?? '';
    showSecret = pw !== null;
  }

  $effect(() => {
    if (!open) return;
    fields = editingUser ? fieldsFromUser(editingUser) : (seedFields ? { ...seedFields } : emptyUserFields());
    showSecret = !editingUser && seedFields != null;
    tick().then(() => idInput?.focus());
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
    const error = validateUserForm(fields, editing);
    if (error) {
      toast(error, 'error');
      return;
    }
    const payload = buildUserPayload(fields, editing);
    saving = true;
    try {
      await onsave(payload, editing ? (editingUser as User).id : null);
    } finally {
      saving = false;
    }
  }
</script>

<div class="backdrop" class:open onclick={onBackdropClick} role="presentation"></div>
<aside class="drawer" class:open aria-hidden={!open}>
  <header>
    <div>
      <h3>{editing ? 'Edit user' : cloning ? 'Clone user' : 'Add user'}</h3>
      {#if clusterName}
        <span class="hint">Applies across cluster <strong class="mono">{clusterName}</strong> ({clusterMembers.join(', ')})</span>
      {/if}
    </div>
    <span class="spacer"></span>
    <button class="iconbtn" type="button" aria-label="Close" onclick={onclose}>
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6 6 18M6 6l12 12"/></svg>
    </button>
  </header>
  <form class="body" id="user-drawer-form" onsubmit={handleSubmit}>
    <div class="fieldrow">
      <label for="user-id">User id</label>
      <input
        id="user-id"
        class="field-mono"
        type="text"
        bind:value={fields.id}
        bind:this={idInput}
        disabled={editing}
        required
        autocomplete="off"
        placeholder="team-madrid"
      />
      <span class="hint">Unique key id{clusterName ? ` across ${clusterName}` : ' on this server'}.</span>
    </div>
    <div class="fieldrow">
      <label for="user-password">Password</label>
      <div class="secret-row">
        <input
          id="user-password"
          class="field-mono"
          type={showSecret ? 'text' : 'password'}
          bind:value={fields.password}
          autocomplete="new-password"
          placeholder={editing ? (hasPassword ? 'keep current or enter new' : 'add Shadowsocks password') : 'for Shadowsocks'}
        />
        <button class="iconbtn" type="button" title="Show/hide" aria-label="Show or hide password" onclick={() => (showSecret = !showSecret)}>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>
        </button>
        <button class="iconbtn" type="button" title={editing ? 'Rotate password' : 'Generate password'} aria-label="Generate password" onclick={regeneratePassword}>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-2.64-6.36M21 3v6h-6"/></svg>
        </button>
      </div>
      <span class="hint">{cloning && !fields.method && !defaultMethod && seedNeedsPassword ? 'Choose a method to generate the password.' : 'password or vless_id is required.'}</span>
    </div>
    <div class="fieldrow">
      <label for="user-vless-id">VLESS UUID</label>
      <div class="secret-row">
        <input
          id="user-vless-id"
          class="field-mono"
          type="text"
          bind:value={fields.vlessId}
          autocomplete="off"
          placeholder={editing ? (hasVlessId ? 'keep current or enter new' : 'add VLESS UUID') : 'xxxxxxxx-xxxx-...'}
        />
        <button class="iconbtn" type="button" title={editing ? 'Rotate UUID' : 'Generate UUID'} aria-label="Generate VLESS UUID" onclick={regenerateVlessId}>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-2.64-6.36M21 3v6h-6"/></svg>
        </button>
      </div>
    </div>
    <div class="fieldrow">
      <label for="user-method">Method</label>
      <select id="user-method" class="field-mono" bind:value={fields.method} onchange={onMethodChange}>
        <option value="">default{defaultMethod ? ` (${defaultMethod})` : ''}</option>
        <option value="aes-128-gcm">aes-128-gcm</option>
        <option value="aes-256-gcm">aes-256-gcm</option>
        <option value="chacha20-ietf-poly1305">chacha20-ietf-poly1305</option>
        <option value="2022-blake3-aes-128-gcm">2022-blake3-aes-128-gcm</option>
        <option value="2022-blake3-aes-256-gcm">2022-blake3-aes-256-gcm</option>
        <option value="2022-blake3-chacha20-poly1305">2022-blake3-chacha20-poly1305</option>
      </select>
    </div>
    <div class="fieldrow">
      <label for="user-fwmark">fwmark</label>
      <input id="user-fwmark" class="field-mono" type="number" min="0" step="1" bind:value={fields.fwmark} placeholder="default" />
    </div>
    <div class="fieldrow">
      <label for="user-aliases">Aliases</label>
      <textarea
        id="user-aliases"
        class="field-mono"
        rows="2"
        bind:value={fields.aliases}
        placeholder={"mobile = 10.0.0.0/8, 203.0.113.5\noffice = 192.0.2.0/24"}
      ></textarea>
      <span class="hint">One name = cidr, cidr per line. Relabels accounting (metrics/NAT/logs) by client source IP.</span>
    </div>
    <div class="switch">
      <input id="user-enabled" type="checkbox" bind:checked={fields.enabled} />
      <label for="user-enabled">Enabled</label>
    </div>
    {#if editing}
      <span class="hint">Leave password/UUID blank to keep them. Empty method, fwmark, and aliases reset to default.</span>
    {/if}
  </form>
  <div class="foot">
    <button class="btn ghost" type="button" onclick={onclose} disabled={saving}>Cancel</button>
    <button class="btn primary" type="submit" form="user-drawer-form" disabled={saving}>
      {editing ? 'Save' : 'Create'}
    </button>
  </div>
</aside>
