<script lang="ts">
  import { tick } from 'svelte';
  import type { UplinkEntry } from '../../lib/types';
  import {
    emptyUplinkFields,
    fieldsFromConfig,
    validateUplinkForm,
    buildUplinkPayload,
    emptyFallbackFields,
    fallbacksFromConfig,
    validateFallbackForm,
    TRANSPORTS,
    MODES,
    type FallbackFormFields,
  } from '../../lib/uplinkForm';
  import { toast } from '../../lib/toast.svelte';

  // Split out of Uplinks.svelte (Task 8 review Minor #4), mirroring
  // features/ss/UserDrawer.svelte's shape: the parent owns instance
  // selection, polling, and the actual API call/toast/refresh; this
  // component only owns form state, validation, and payload-building
  // (lib/uplinkForm.ts), then hands the built payload to `onsave`.
  //
  // Always mounted (not `{#if open}`) so the `.backdrop`/`.drawer` CSS
  // transitions actually animate — same rationale as UserDrawer.svelte.
  let {
    open,
    group,
    editingEntry = null,
    onclose,
    onsave,
  }: {
    open: boolean;
    /// Create target group, or the group the uplink being edited currently
    /// lives in. Never itself editable (matches uplinks.html: group isn't a
    /// form field either — moving an uplink between groups isn't supported).
    group: string;
    editingEntry?: UplinkEntry | null;
    onclose: () => void;
    // editingName mirrors UserDrawer's editingId: the identity to PATCH, or
    // null on create. Parent (Uplinks.svelte) owns the actual uplinksMutate
    // call, its success/error toast, the dirty-instance flag, and the
    // post-mutation refresh.
    onsave: (payload: Record<string, unknown>, editingName: string | null) => Promise<void>;
  } = $props();

  const editing = $derived(editingEntry !== null);

  let fields = $state(emptyUplinkFields());
  let saving = $state(false);
  // $state (not a plain `let`, unlike UserDrawer.svelte's always-rendered
  // idInput) because this element only exists while in create mode —
  // uplinks.html hides the name field entirely on edit (identity is
  // immutable) — the binding target toggles to `undefined` on every mode
  // switch, which is exactly what svelte's non_reactive_update check warns a
  // plain `let` won't propagate.
  let nameInput: HTMLInputElement | undefined = $state();

  // Repeatable fallbacks[] sub-form (Task 8c). Each row pairs a
  // FallbackFormFields with a `key` that's stable across add/remove/reorder
  // — assigned once when the row is created (either from `fallbacksFromConfig`
  // on open, or by `addFallback`) and never recomputed from the row's
  // position. Two things depend on that stability:
  //  1. The `{#each fallbackRows as row (row.key)}` below keys off it, so
  //     Svelte moves/preserves the actual DOM node across a reorder instead
  //     of recreating it — which in turn means each entry's native
  //     `<details>` open/closed state (how collapsing is implemented; no
  //     separate expanded-tracking state needed) survives "Move up"/"Move
  //     down" instead of snapping shut or reopening at the wrong index.
  //  2. removeFallback/moveFallback below address rows by key, not by
  //     index, so they can't be fooled by a stale index after a prior
  //     add/remove in the same render.
  // `nextFallbackKey` only ever increases (never reset), so a key can never
  // collide with one still referenced by an in-flight Svelte transition from
  // the previous open/close cycle.
  let fallbackRows: { key: number; fields: FallbackFormFields }[] = $state([]);
  let nextFallbackKey = 0;

  // editingEntry is a snapshot Uplinks.svelte takes once, at the moment
  // "Edit" is clicked, and doesn't reassign from later poll refreshes — so
  // this only actually repopulates the form at the open transition, never
  // mid-edit out from under the user. Only create mode autofocuses: unlike
  // UserDrawer.svelte (which focuses its always-rendered, edit-disabled `id`
  // input unconditionally regardless of mode — see task-7-report.md minor
  // finding #1), the name field here doesn't exist in the DOM at all on
  // edit, so there is nothing to focus.
  $effect(() => {
    if (!open) return;
    fields = editingEntry ? fieldsFromConfig(editingEntry.config) : emptyUplinkFields();
    fallbackRows = fallbacksFromConfig(editingEntry?.config).map((fb) => ({
      key: nextFallbackKey++,
      fields: fb,
    }));
    if (!editingEntry) {
      tick().then(() => nameInput?.focus());
    }
  });

  function addFallback() {
    fallbackRows = [...fallbackRows, { key: nextFallbackKey++, fields: emptyFallbackFields() }];
  }
  function removeFallback(key: number) {
    fallbackRows = fallbackRows.filter((row) => row.key !== key);
  }
  // direction -1 = move earlier in the chain (tried sooner), +1 = move
  // later. Order is meaningful on the wire: fallbacks are tried in array
  // order (`[primary, fallbacks[0], fallbacks[1], …]`, see the doc comment
  // on `UplinkSection::shuffle_wires` in bins/outline-ws-rust/src/config/
  // schema.rs) unless `shuffle_wires` reshuffles the chain at load time —
  // which is opt-in and off by default, so the order set here is the order
  // that actually ships in the common case.
  function moveFallback(key: number, direction: -1 | 1) {
    const index = fallbackRows.findIndex((row) => row.key === key);
    const target = index + direction;
    if (index < 0 || target < 0 || target >= fallbackRows.length) return;
    const next = fallbackRows.slice();
    [next[index], next[target]] = [next[target], next[index]];
    fallbackRows = next;
  }

  // Matches uplinks.html's drawer (Escape closes it); backdrop click below
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
    const error = validateUplinkForm(fields, editing);
    if (error) {
      toast(error, 'error');
      return;
    }
    for (let i = 0; i < fallbackRows.length; i++) {
      const fbError = validateFallbackForm(fallbackRows[i].fields);
      if (fbError) {
        toast(`fallback ${i + 1}: ${fbError}`, 'error');
        return;
      }
    }
    const payload = buildUplinkPayload(
      fields,
      editing,
      fallbackRows.map((row) => row.fields),
    );
    saving = true;
    try {
      await onsave(payload, editing ? (editingEntry as UplinkEntry).name : null);
    } finally {
      saving = false;
    }
  }
</script>

<div class="backdrop" class:open onclick={onBackdropClick} role="presentation"></div>
<aside class="drawer" class:open aria-hidden={!open}>
  <header>
    <h3>
      {#if editing}
        Edit &quot;{editingEntry?.name}&quot; in &quot;{group}&quot;
      {:else}
        Add uplink to &quot;{group}&quot;
      {/if}
    </h3>
    <span class="spacer"></span>
    <button class="iconbtn" type="button" aria-label="Close" onclick={onclose}>
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6 6 18M6 6l12 12"/></svg>
    </button>
  </header>
  <form class="body" id="uplink-drawer-form" onsubmit={handleSubmit}>
    {#if !editing}
      <div class="fieldrow">
        <label for="uplink-name">Name</label>
        <input
          id="uplink-name"
          class="field-mono"
          type="text"
          bind:value={fields.name}
          bind:this={nameInput}
          required
          autocomplete="off"
          placeholder="cloud1"
        />
        <span class="hint">Required for create.</span>
      </div>
    {/if}

    <div class="switch">
      <input id="uplink-use-link" type="checkbox" bind:checked={fields.useShareLink} />
      <label for="uplink-use-link">Use a share link</label>
    </div>

    {#if fields.useShareLink}
      <div class="fieldrow">
        <label for="uplink-link">Share link</label>
        <input
          id="uplink-link"
          class="field-mono"
          type="text"
          bind:value={fields.link}
          autocomplete="off"
          placeholder="vless://... or ss://..."
          required={!editing}
        />
        <span class="hint">
          vless:// or ss:// URI. Expands into the matching transport's fields on the server; mutually
          exclusive with transport/carrier fields, so they're hidden while this is on.
          {#if editing}Leave blank to keep the current link unchanged.{/if}
        </span>
      </div>
    {:else}
      <div class="fieldrow">
        <label for="uplink-transport">Transport</label>
        <select id="uplink-transport" class="field-mono" bind:value={fields.transport}>
          {#each TRANSPORTS as t}<option value={t}>{t}</option>{/each}
        </select>
      </div>

      <fieldset class="fieldset">
        <legend>TCP (transport=ss)</legend>
        <div class="fieldrow">
          <label for="uplink-tcp-ws-url">WS URL</label>
          <input id="uplink-tcp-ws-url" class="field-mono" type="text" bind:value={fields.tcpWsUrl} autocomplete="off" />
        </div>
        <div class="fieldrow">
          <label for="uplink-tcp-xhttp-url">XHTTP URL</label>
          <input id="uplink-tcp-xhttp-url" class="field-mono" type="text" bind:value={fields.tcpXhttpUrl} autocomplete="off" />
        </div>
        <div class="fieldrow">
          <label for="uplink-tcp-mode">Mode</label>
          <select id="uplink-tcp-mode" class="field-mono" bind:value={fields.tcpMode}>
            {#each MODES as m}<option value={m}>{m === '' ? '—' : m}</option>{/each}
          </select>
        </div>
      </fieldset>

      <fieldset class="fieldset">
        <legend>UDP (transport=ss)</legend>
        <div class="fieldrow">
          <label for="uplink-udp-ws-url">WS URL</label>
          <input id="uplink-udp-ws-url" class="field-mono" type="text" bind:value={fields.udpWsUrl} autocomplete="off" />
        </div>
        <div class="fieldrow">
          <label for="uplink-udp-xhttp-url">XHTTP URL</label>
          <input id="uplink-udp-xhttp-url" class="field-mono" type="text" bind:value={fields.udpXhttpUrl} autocomplete="off" />
        </div>
        <div class="fieldrow">
          <label for="uplink-udp-mode">Mode</label>
          <select id="uplink-udp-mode" class="field-mono" bind:value={fields.udpMode}>
            {#each MODES as m}<option value={m}>{m === '' ? '—' : m}</option>{/each}
          </select>
        </div>
      </fieldset>

      <fieldset class="fieldset">
        <legend>SS combined-path (transport=ss)</legend>
        <div class="fieldrow">
          <label for="uplink-ss-ws-url">WS URL</label>
          <input id="uplink-ss-ws-url" class="field-mono" type="text" bind:value={fields.ssWsUrl} autocomplete="off" />
        </div>
        <div class="fieldrow">
          <label for="uplink-ss-xhttp-url">XHTTP URL</label>
          <input id="uplink-ss-xhttp-url" class="field-mono" type="text" bind:value={fields.ssXhttpUrl} autocomplete="off" />
        </div>
        <div class="fieldrow">
          <label for="uplink-ss-mode">Mode</label>
          <select id="uplink-ss-mode" class="field-mono" bind:value={fields.ssMode}>
            {#each MODES as m}<option value={m}>{m === '' ? '—' : m}</option>{/each}
          </select>
        </div>
        <div class="fieldrow">
          <label for="uplink-method">Cipher (method)</label>
          <input id="uplink-method" class="field-mono" type="text" bind:value={fields.method} autocomplete="off" />
        </div>
        <div class="fieldrow">
          <label for="uplink-password">Password</label>
          <input id="uplink-password" class="field-mono" type="text" bind:value={fields.password} autocomplete="off" />
        </div>
        <span class="hint">Cipher/password apply to transport=ss as a whole (split TCP/UDP above or combined-path here).</span>
      </fieldset>

      <fieldset class="fieldset">
        <legend>VLESS</legend>
        <div class="fieldrow">
          <label for="uplink-vless-ws-url">WS URL</label>
          <input id="uplink-vless-ws-url" class="field-mono" type="text" bind:value={fields.vlessWsUrl} autocomplete="off" />
        </div>
        <div class="fieldrow">
          <label for="uplink-vless-xhttp-url">XHTTP URL</label>
          <input id="uplink-vless-xhttp-url" class="field-mono" type="text" bind:value={fields.vlessXhttpUrl} autocomplete="off" />
        </div>
        <div class="fieldrow">
          <label for="uplink-vless-mode">Mode</label>
          <select id="uplink-vless-mode" class="field-mono" bind:value={fields.vlessMode}>
            {#each MODES as m}<option value={m}>{m === '' ? '—' : m}</option>{/each}
          </select>
        </div>
        <div class="fieldrow">
          <label for="uplink-vless-id">VLESS UUID</label>
          <input id="uplink-vless-id" class="field-mono" type="text" bind:value={fields.vlessId} autocomplete="off" />
        </div>
      </fieldset>
    {/if}

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
    {#if editing}
      <span class="hint">Every non-empty field above is sent, including unchanged ones — blank fields stay untouched on the server.</span>
    {/if}

    <div class="fallbacks-section">
      <div class="fallbacks-header">
        <h4>Fallbacks</h4>
        <button class="btn ghost sm" type="button" onclick={addFallback}>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg>
          Add fallback
        </button>
      </div>
      <span class="hint">
        Wires tried, in order, when the primary transport fails to dial. Saving always replaces the whole
        list with what's shown here (including an empty list, which clears any existing fallbacks).
      </span>

      {#if fallbackRows.length === 0}
        <p class="hint">No fallbacks configured.</p>
      {/if}

      {#each fallbackRows as row, i (row.key)}
        <details class="fallback-entry" open>
          <summary>
            <span>Fallback {i + 1}</span>
            {#if row.fields.useShareLink}
              <span class="chip info">share-link</span>
            {:else}
              <span class="chip info">{row.fields.transport || 'ss'}</span>
            {/if}
          </summary>
          <div class="fallback-body">
            <div class="switch">
              <input id={`fb-${row.key}-use-link`} type="checkbox" bind:checked={row.fields.useShareLink} />
              <label for={`fb-${row.key}-use-link`}>Use a share link</label>
            </div>

            {#if row.fields.useShareLink}
              <div class="fieldrow">
                <label for={`fb-${row.key}-link`}>Share link</label>
                <input
                  id={`fb-${row.key}-link`}
                  class="field-mono"
                  type="text"
                  bind:value={row.fields.link}
                  autocomplete="off"
                  placeholder="vless://... or ss://..."
                />
                <span class="hint">
                  vless:// or ss:// URI. Expands into the matching transport's fields on the server;
                  mutually exclusive with this fallback's transport/carrier fields.
                </span>
              </div>
            {:else}
              <div class="fieldrow">
                <label for={`fb-${row.key}-transport`}>Transport</label>
                <select id={`fb-${row.key}-transport`} class="field-mono" bind:value={row.fields.transport}>
                  {#each TRANSPORTS as t}<option value={t}>{t}</option>{/each}
                </select>
              </div>

              <fieldset class="fieldset">
                <legend>TCP (transport=ss)</legend>
                <div class="fieldrow">
                  <label for={`fb-${row.key}-tcp-ws-url`}>WS URL</label>
                  <input id={`fb-${row.key}-tcp-ws-url`} class="field-mono" type="text" bind:value={row.fields.tcpWsUrl} autocomplete="off" />
                </div>
                <div class="fieldrow">
                  <label for={`fb-${row.key}-tcp-xhttp-url`}>XHTTP URL</label>
                  <input id={`fb-${row.key}-tcp-xhttp-url`} class="field-mono" type="text" bind:value={row.fields.tcpXhttpUrl} autocomplete="off" />
                </div>
                <div class="fieldrow">
                  <label for={`fb-${row.key}-tcp-mode`}>Mode</label>
                  <select id={`fb-${row.key}-tcp-mode`} class="field-mono" bind:value={row.fields.tcpMode}>
                    {#each MODES as m}<option value={m}>{m === '' ? '—' : m}</option>{/each}
                  </select>
                </div>
              </fieldset>

              <fieldset class="fieldset">
                <legend>UDP (transport=ss)</legend>
                <div class="fieldrow">
                  <label for={`fb-${row.key}-udp-ws-url`}>WS URL</label>
                  <input id={`fb-${row.key}-udp-ws-url`} class="field-mono" type="text" bind:value={row.fields.udpWsUrl} autocomplete="off" />
                </div>
                <div class="fieldrow">
                  <label for={`fb-${row.key}-udp-xhttp-url`}>XHTTP URL</label>
                  <input id={`fb-${row.key}-udp-xhttp-url`} class="field-mono" type="text" bind:value={row.fields.udpXhttpUrl} autocomplete="off" />
                </div>
                <div class="fieldrow">
                  <label for={`fb-${row.key}-udp-mode`}>Mode</label>
                  <select id={`fb-${row.key}-udp-mode`} class="field-mono" bind:value={row.fields.udpMode}>
                    {#each MODES as m}<option value={m}>{m === '' ? '—' : m}</option>{/each}
                  </select>
                </div>
              </fieldset>

              <fieldset class="fieldset">
                <legend>SS combined-path (transport=ss)</legend>
                <div class="fieldrow">
                  <label for={`fb-${row.key}-ss-ws-url`}>WS URL</label>
                  <input id={`fb-${row.key}-ss-ws-url`} class="field-mono" type="text" bind:value={row.fields.ssWsUrl} autocomplete="off" />
                </div>
                <div class="fieldrow">
                  <label for={`fb-${row.key}-ss-xhttp-url`}>XHTTP URL</label>
                  <input id={`fb-${row.key}-ss-xhttp-url`} class="field-mono" type="text" bind:value={row.fields.ssXhttpUrl} autocomplete="off" />
                </div>
                <div class="fieldrow">
                  <label for={`fb-${row.key}-ss-mode`}>Mode</label>
                  <select id={`fb-${row.key}-ss-mode`} class="field-mono" bind:value={row.fields.ssMode}>
                    {#each MODES as m}<option value={m}>{m === '' ? '—' : m}</option>{/each}
                  </select>
                </div>
                <div class="fieldrow">
                  <label for={`fb-${row.key}-method`}>Cipher (method)</label>
                  <input id={`fb-${row.key}-method`} class="field-mono" type="text" bind:value={row.fields.method} autocomplete="off" placeholder="inherit parent" />
                </div>
                <div class="fieldrow">
                  <label for={`fb-${row.key}-password`}>Password</label>
                  <input id={`fb-${row.key}-password`} class="field-mono" type="text" bind:value={row.fields.password} autocomplete="off" placeholder="inherit parent" />
                </div>
                <span class="hint">Blank cipher/password inherit the parent uplink's (split TCP/UDP above or combined-path here).</span>
              </fieldset>

              <fieldset class="fieldset">
                <legend>VLESS</legend>
                <div class="fieldrow">
                  <label for={`fb-${row.key}-vless-ws-url`}>WS URL</label>
                  <input id={`fb-${row.key}-vless-ws-url`} class="field-mono" type="text" bind:value={row.fields.vlessWsUrl} autocomplete="off" />
                </div>
                <div class="fieldrow">
                  <label for={`fb-${row.key}-vless-xhttp-url`}>XHTTP URL</label>
                  <input id={`fb-${row.key}-vless-xhttp-url`} class="field-mono" type="text" bind:value={row.fields.vlessXhttpUrl} autocomplete="off" />
                </div>
                <div class="fieldrow">
                  <label for={`fb-${row.key}-vless-mode`}>Mode</label>
                  <select id={`fb-${row.key}-vless-mode`} class="field-mono" bind:value={row.fields.vlessMode}>
                    {#each MODES as m}<option value={m}>{m === '' ? '—' : m}</option>{/each}
                  </select>
                </div>
                <div class="fieldrow">
                  <label for={`fb-${row.key}-vless-id`}>VLESS UUID</label>
                  <input id={`fb-${row.key}-vless-id`} class="field-mono" type="text" bind:value={row.fields.vlessId} autocomplete="off" />
                </div>
                <span class="hint">Not inherited from the parent — required when this fallback's transport is vless.</span>
              </fieldset>
            {/if}

            <div class="fieldrow">
              <label for={`fb-${row.key}-fwmark`}>fwmark</label>
              <input id={`fb-${row.key}-fwmark`} class="field-mono" type="number" step="1" bind:value={row.fields.fwmark} placeholder="inherit parent" />
            </div>
            <div class="fieldrow">
              <label for={`fb-${row.key}-ipv6-first`}>IPv6 first</label>
              <select id={`fb-${row.key}-ipv6-first`} class="field-mono" bind:value={row.fields.ipv6First}>
                <option value="">inherit parent</option>
                <option value="true">true</option>
                <option value="false">false</option>
              </select>
            </div>

            <div class="fallback-actions">
              <button class="btn ghost sm" type="button" onclick={() => moveFallback(row.key, -1)} disabled={i === 0}>
                Move up
              </button>
              <button class="btn ghost sm" type="button" onclick={() => moveFallback(row.key, 1)} disabled={i === fallbackRows.length - 1}>
                Move down
              </button>
              <button class="btn danger sm" type="button" onclick={() => removeFallback(row.key)}>Remove</button>
            </div>
          </div>
        </details>
      {/each}
    </div>
  </form>
  <div class="foot">
    <button class="btn ghost" type="button" onclick={onclose} disabled={saving}>Cancel</button>
    <button class="btn primary" type="submit" form="uplink-drawer-form" disabled={saving}>
      {editing ? 'Update' : 'Create'}
    </button>
  </div>
</aside>
