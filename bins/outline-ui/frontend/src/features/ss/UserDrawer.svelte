<script lang="ts">
  import { tick } from 'svelte';
  import type { User, NewUser, PatchUser } from '../../lib/types';
  import { emptyUserFields, fieldsFromUser, validateUserForm, buildUserPayload } from '../../lib/userForm';
  import { toast } from '../../lib/toast.svelte';

  // Always mounted (not `{#if open}`) so the `.backdrop`/`.drawer` CSS
  // transitions from docs/superpowers/specs/...-prototype.html (opacity +
  // translateX, gated on an `.open` class) actually animate — an `{#if}`
  // would insert the drawer already in its open state instead of sliding it
  // in. Field values reset from `editingUser` (or blank, for create) each
  // time `open` flips to true; see the $effect below.
  let {
    open,
    editingUser = null,
    onclose,
    onsave,
  }: {
    open: boolean;
    editingUser?: User | null;
    onclose: () => void;
    // Parent (Users.svelte) owns the actual API call, its success/error
    // toast, and the post-mutation refresh — this component only builds and
    // validates the payload. `editingId` is passed separately (rather than
    // making the caller re-derive it from `editingUser`) because `id` itself
    // is deliberately excluded from the built payload on edit.
    onsave: (payload: NewUser | PatchUser, editingId: string | null) => Promise<void>;
  } = $props();

  const editing = $derived(editingUser !== null);
  const hasPassword = $derived(Boolean(editingUser?.has_password));
  const hasVlessId = $derived(Boolean(editingUser?.has_vless_id));

  let fields = $state(emptyUserFields());
  let saving = $state(false);
  let idInput: HTMLInputElement | undefined;

  // editingUser is stable for as long as `open` stays true (Users.svelte
  // snapshots it once, at the moment the drawer opens, and doesn't reassign
  // it from later poll refreshes) — so this only actually repopulates the
  // form at the open transition, never mid-edit out from under the user.
  $effect(() => {
    if (!open) return;
    fields = editingUser ? fieldsFromUser(editingUser) : emptyUserFields();
    tick().then(() => idInput?.focus());
  });

  // Matches dashboard.html's drawer (Escape closes it); backdrop click below
  // covers the click-outside case.
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
    <h3>{editing ? 'Edit user' : 'New user'}</h3>
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
      <span class="hint">Unique key id on this server.</span>
    </div>
    <div class="fieldrow">
      <label for="user-password">Password</label>
      <input
        id="user-password"
        class="field-mono"
        type="password"
        bind:value={fields.password}
        autocomplete="new-password"
        placeholder={editing ? (hasPassword ? 'keep current password' : 'add Shadowsocks password') : 'for Shadowsocks'}
      />
      <span class="hint">password or vless_id is required.</span>
    </div>
    <div class="fieldrow">
      <label for="user-vless-id">VLESS UUID</label>
      <input
        id="user-vless-id"
        class="field-mono"
        type="text"
        bind:value={fields.vlessId}
        autocomplete="off"
        placeholder={editing ? (hasVlessId ? 'keep current UUID' : 'add VLESS UUID') : 'xxxxxxxx-xxxx-...'}
      />
    </div>
    <div class="fieldrow">
      <label for="user-method">Method</label>
      <select id="user-method" class="field-mono" bind:value={fields.method}>
        <option value="">default</option>
        <option value="aes-128-gcm">aes-128-gcm</option>
        <option value="aes-256-gcm">aes-256-gcm</option>
        <option value="chacha20-ietf-poly1305">chacha20-ietf-poly1305</option>
        <option value="2022-blake3-aes-128-gcm">2022-blake3-aes-128-gcm</option>
        <option value="2022-blake3-aes-256-gcm">2022-blake3-aes-256-gcm</option>
        <option value="2022-blake3-chacha20-poly1305">2022-blake3-chacha20-poly1305</option>
      </select>
    </div>
    <div class="fieldrow">
      <label for="user-ws-tcp">TCP path</label>
      <input id="user-ws-tcp" class="field-mono" type="text" bind:value={fields.wsPathTcp} placeholder="/tcp" />
    </div>
    <div class="fieldrow">
      <label for="user-ws-udp">UDP path</label>
      <input id="user-ws-udp" class="field-mono" type="text" bind:value={fields.wsPathUdp} placeholder="/udp" />
    </div>
    <div class="fieldrow">
      <label for="user-ws-vless">VLESS path</label>
      <input id="user-ws-vless" class="field-mono" type="text" bind:value={fields.wsPathVless} placeholder="/vless" />
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
      <span class="hint">Leave password/UUID blank to keep them. Empty method, fwmark, paths, and aliases reset to default.</span>
    {/if}
  </form>
  <div class="foot">
    <button class="btn ghost" type="button" onclick={onclose} disabled={saving}>Cancel</button>
    <button class="btn primary" type="submit" form="user-drawer-form" disabled={saving}>
      {editing ? 'Save' : 'Create'}
    </button>
  </div>
</aside>
