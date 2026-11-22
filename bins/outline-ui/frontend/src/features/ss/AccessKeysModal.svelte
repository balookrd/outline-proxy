<script lang="ts">
  import { getClusterUserAccessKeys, getUserAccessKeys, ApiError } from '../../lib/api';
  import type { SsTarget, UserAccessKeysBundle } from '../../lib/types';
  import QrCode from '../../components/layout/QrCode.svelte';

  let {
    open = $bindable(false),
    target,
    userId,
    onclose,
  }: {
    open: boolean;
    target: SsTarget | null;
    userId: string | null;
    onclose?: () => void;
  } = $props();

  type TabId = 'outline' | 'happ' | 'app' | 'links';
  const TABS: ReadonlyArray<{ id: TabId; label: string }> = [
    { id: 'outline', label: 'Outline' },
    { id: 'happ', label: 'Happ / Xray' },
    { id: 'app', label: 'App Config' },
    { id: 'links', label: 'Share Links' },
  ];

  let dialogEl: HTMLDialogElement | undefined;
  let pressedOutside = false;
  let activeTab = $state<TabId>('outline');
  let selectedPerNode = $state('');
  let loading = $state(false);
  let errorMsg = $state<string | null>(null);
  let notConfigured = $state(false);
  let bundle = $state<UserAccessKeysBundle | null>(null);
  let copiedKey = $state<string | null>(null);
  let liveAnnouncement = $state('');
  let selectedShareQr = $state(0);

  let tabRefs: Record<TabId, HTMLButtonElement | undefined> = {
    outline: undefined,
    happ: undefined,
    app: undefined,
    links: undefined,
  };

  let fetchSeq = 0;

  $effect(() => {
    const el = dialogEl;
    if (!el) return;
    if (open && !el.open) {
      el.returnValue = '';
      el.showModal();
    } else if (!open && el.open) {
      el.close();
    }
  });

  $effect(() => {
    if (!open || !target || !userId) return;
    activeTab = 'outline';
    selectedShareQr = 0;
    void fetchLinks(target, userId);
  });

  async function fetchLinks(t: SsTarget, uid: string) {
    const seq = ++fetchSeq;
    loading = true;
    errorMsg = null;
    notConfigured = false;
    bundle = null;
    try {
      const data =
        t.kind === 'cluster'
          ? await getClusterUserAccessKeys(t.name, uid)
          : await getUserAccessKeys(t.name, uid);
      if (seq !== fetchSeq) return;
      bundle = data;
      if (data.mode === 'per_node' && data.nodes?.length) {
        const firstOk = data.nodes.find((n) => n.ok && n.links);
        selectedPerNode = firstOk?.instance ?? data.nodes[0].instance;
      } else {
        selectedPerNode = '';
      }
    } catch (e) {
      if (seq !== fetchSeq) return;
      if (e instanceof ApiError && e.status === 501) {
        notConfigured = true;
      }
      errorMsg = e instanceof Error ? e.message : String(e);
    } finally {
      if (seq === fetchSeq) loading = false;
    }
  }

  const activeNodeBundle = $derived.by<UserAccessKeysBundle | null>(() => {
    if (!bundle) return null;
    if (bundle.mode === 'per_node' && bundle.nodes?.length) {
      const entry = bundle.nodes.find((n) => n.instance === selectedPerNode) ?? bundle.nodes[0];
      return entry?.links ?? null;
    }
    return bundle;
  });

  const shareLinks = $derived.by(() => {
    if (!bundle) return [];
    if (bundle.share_links?.length) return bundle.share_links;
    return activeNodeBundle?.share_links ?? [];
  });

  const warnings = $derived(bundle?.warnings ?? activeNodeBundle?.warnings ?? []);

  function isOutside(e: PointerEvent, el: HTMLDialogElement): boolean {
    const r = el.getBoundingClientRect();
    return e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom;
  }

  function onPointerDown(e: PointerEvent) {
    if (!dialogEl || 'closedBy' in HTMLDialogElement.prototype) return;
    pressedOutside = isOutside(e, dialogEl);
  }

  function onPointerUp(e: PointerEvent) {
    if (!dialogEl || 'closedBy' in HTMLDialogElement.prototype) return;
    if (pressedOutside && isOutside(e, dialogEl)) {
      dialogEl.close();
    }
    pressedOutside = false;
  }

  function onClose() {
    if (dialogEl) dialogEl.returnValue = '';
    open = false;
    onclose?.();
  }

  function selectTab(id: TabId, focus = false) {
    activeTab = id;
    const btn = tabRefs[id];
    btn?.scrollIntoView({ block: 'nearest', inline: 'nearest' });
    if (focus) btn?.focus();
  }

  function onTabKeyDown(e: KeyboardEvent, idx: number) {
    let nextIdx = idx;
    if (e.key === 'ArrowRight') nextIdx = (idx + 1) % TABS.length;
    else if (e.key === 'ArrowLeft') nextIdx = (idx - 1 + TABS.length) % TABS.length;
    else if (e.key === 'Home') nextIdx = 0;
    else if (e.key === 'End') nextIdx = TABS.length - 1;
    else return;
    e.preventDefault();
    selectTab(TABS[nextIdx].id, true);
  }

  async function copyText(key: string, value: string, label: string) {
    try {
      await navigator.clipboard.writeText(value);
      copiedKey = key;
      liveAnnouncement = `${label} copied to clipboard.`;
      setTimeout(() => {
        if (copiedKey === key) copiedKey = null;
      }, 1500);
    } catch {
      liveAnnouncement = 'Clipboard copy failed.';
    }
  }

  function downloadText(filename: string, content: string, mime = 'text/plain;charset=utf-8') {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
</script>

<dialog
  bind:this={dialogEl}
  class="ui-dialog links-dialog"
  closedby="any"
  aria-labelledby="access-keys-modal-title"
  onclose={onClose}
  onpointerdown={onPointerDown}
  onpointerup={onPointerUp}
>
  <div class="dialog-card">
    <header class="dialog-head">
      <div>
        <h2 id="access-keys-modal-title">
          Access links &amp; subscriptions · <span class="mono">{userId ?? ''}</span>
        </h2>
        {#if bundle?.source_node}
          <span class="hint">Generated via <span class="mono">{bundle.source_node}</span></span>
        {/if}
      </div>
      <span class="spacer"></span>
      <button type="button" class="iconbtn" aria-label="Close" onclick={() => dialogEl?.close()}>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6 6 18M6 6l12 12"/></svg>
      </button>
    </header>

    <div class="dialog-body">
      {#if loading}
        <div class="empty">Generating subscription links…</div>
      {:else if notConfigured}
        <div class="info-banner">
          <span>
            Generator is not configured on this server (<code>[control].access_keys_generator</code> is unset in <code>config.toml</code>).
          </span>
        </div>
      {:else if errorMsg}
        <div class="error-banner" role="alert">
          <span>{errorMsg}</span>
        </div>
      {:else if bundle}
        {#if bundle.mode === 'per_node' && bundle.nodes?.length}
          <div class="fieldrow">
            <label for="ak-per-node-select">Node subscription view</label>
            <select id="ak-per-node-select" class="field-mono" bind:value={selectedPerNode}>
              {#each bundle.nodes as n (n.instance)}
                <option value={n.instance}>
                  {n.instance} {n.ok ? '' : `(${n.error ?? 'error'})`}
                </option>
              {/each}
            </select>
          </div>
        {/if}

        <div class="tablist-row" role="tablist" aria-label="Subscription formats">
          {#each TABS as t, idx (t.id)}
            <button
              bind:this={tabRefs[t.id]}
              type="button"
              role="tab"
              id={`ak-tab-${t.id}`}
              class="tab-btn"
              aria-selected={activeTab === t.id}
              tabindex={activeTab === t.id ? 0 : -1}
              onclick={() => selectTab(t.id)}
              onkeydown={(e) => onTabKeyDown(e, idx)}
            >
              {t.label}
            </button>
          {/each}
        </div>

        <div class="tab-panels">
          <div
            role="tabpanel"
            aria-labelledby="ak-tab-outline"
            hidden={activeTab !== 'outline'}
            class="ak-panel"
          >
            {#if activeNodeBundle?.outline_url}
              <div class="ak-grid">
                <QrCode value={activeNodeBundle.outline_url} label="Outline subscription QR code" />
                <div class="ak-details">
                  <div class="fieldrow">
                    <label for="ak-outline-url">Outline dynamic key URL (ssconf://)</label>
                    <input id="ak-outline-url" class="field-mono" type="text" readonly value={activeNodeBundle.outline_url} />
                  </div>
                  <div class="ak-actions">
                    <button type="button" class="btn primary sm" onclick={() => copyText('outline', activeNodeBundle.outline_url!, 'Outline URL')}>
                      {copiedKey === 'outline' ? 'Copied' : 'Copy URL'}
                    </button>
                    {#if activeNodeBundle.artifacts?.conf}
                      <button type="button" class="btn sm" onclick={() => downloadText(`${bundle?.user ?? 'user'}.conf`, activeNodeBundle.artifacts!.conf!, 'application/json')}>
                        Download .conf
                      </button>
                    {/if}
                  </div>
                </div>
              </div>
            {:else}
              <div class="empty">
                Outline subscription is unavailable for this user (requires Shadowsocks password and split WS endpoints or access_keys.url_base).
              </div>
            {/if}
          </div>

          <div
            role="tabpanel"
            aria-labelledby="ak-tab-happ"
            hidden={activeTab !== 'happ'}
            class="ak-panel"
          >
            {#if activeNodeBundle?.happ_url}
              <div class="ak-grid">
                <QrCode value={activeNodeBundle.happ_url} label="Happ Xray subscription QR code" />
                <div class="ak-details">
                  <div class="fieldrow">
                    <label for="ak-happ-url">Happ / Xray subscription URL</label>
                    <input id="ak-happ-url" class="field-mono" type="text" readonly value={activeNodeBundle.happ_url} />
                  </div>
                  <div class="ak-actions">
                    <button type="button" class="btn primary sm" onclick={() => copyText('happ', activeNodeBundle.happ_url!, 'Happ URL')}>
                      {copiedKey === 'happ' ? 'Copied' : 'Copy URL'}
                    </button>
                    {#if activeNodeBundle.artifacts?.json}
                      <button type="button" class="btn sm" onclick={() => downloadText(`${bundle?.user ?? 'user'}.json`, activeNodeBundle.artifacts!.json!, 'application/json')}>
                        Download .json
                      </button>
                    {/if}
                  </div>
                </div>
              </div>
            {:else}
              <div class="empty">
                Happ / Xray JSON subscription is unavailable for this user (requires Shadowsocks password and url_base).
              </div>
            {/if}
          </div>

          <div
            role="tabpanel"
            aria-labelledby="ak-tab-app"
            hidden={activeTab !== 'app'}
            class="ak-panel"
          >
            {#if activeNodeBundle?.ws_url || activeNodeBundle?.artifacts?.toml}
              <div class="ak-grid">
                {#if activeNodeBundle.ws_url}
                  <QrCode value={activeNodeBundle.ws_url} label="App Config subscription QR code" />
                {/if}
                <div class="ak-details">
                  {#if activeNodeBundle.ws_url}
                    <div class="fieldrow">
                      <label for="ak-ws-url">outline-client config URL (.toml)</label>
                      <input id="ak-ws-url" class="field-mono" type="text" readonly value={activeNodeBundle.ws_url} />
                    </div>
                  {/if}
                  <div class="ak-actions">
                    {#if activeNodeBundle.ws_url}
                      <button type="button" class="btn primary sm" onclick={() => copyText('app', activeNodeBundle.ws_url!, 'App Config URL')}>
                        {copiedKey === 'app' ? 'Copied' : 'Copy URL'}
                      </button>
                    {/if}
                    {#if activeNodeBundle.artifacts?.toml}
                      <button type="button" class="btn sm" onclick={() => downloadText(`${bundle?.user ?? 'user'}.toml`, activeNodeBundle.artifacts!.toml!, 'application/toml')}>
                        Download .toml
                      </button>
                    {/if}
                  </div>
                </div>
              </div>
            {:else}
              <div class="empty">App Config (.toml) is unavailable for the current server endpoints and user credentials.</div>
            {/if}
          </div>

          <div
            role="tabpanel"
            aria-labelledby="ak-tab-links"
            hidden={activeTab !== 'links'}
            class="ak-panel"
          >
            {#if shareLinks.length}
              <div class="ak-grid">
                <QrCode value={shareLinks[selectedShareQr] ?? shareLinks[0]} label="Share link QR code" />
                <div class="ak-details">
                  <div class="ak-actions">
                    <button type="button" class="btn primary sm" onclick={() => copyText('all-links', shareLinks.join('\n'), 'All share links')}>
                      {copiedKey === 'all-links' ? 'Copied' : 'Copy all'}
                    </button>
                    {#if activeNodeBundle?.artifacts?.txt || shareLinks.length}
                      <button type="button" class="btn sm" onclick={() => downloadText(`${bundle?.user ?? 'user'}.txt`, activeNodeBundle?.artifacts?.txt ?? shareLinks.join('\n') + '\n')}>
                        Download .txt
                      </button>
                    {/if}
                  </div>
                  {#if activeNodeBundle?.txt_url}
                    <div class="fieldrow">
                      <label for="ak-txt-url">Text bundle URL</label>
                      <div class="secret-row">
                        <input id="ak-txt-url" class="field-mono" type="text" readonly value={activeNodeBundle.txt_url} />
                        <button type="button" class="btn sm" onclick={() => copyText('txt-url', activeNodeBundle.txt_url!, 'TXT URL')}>
                          {copiedKey === 'txt-url' ? 'Copied' : 'Copy'}
                        </button>
                      </div>
                    </div>
                  {/if}
                  <div class="share-links-list">
                    {#each shareLinks as link, idx (link)}
                      <div class="share-link-item" class:selected={selectedShareQr === idx}>
                        <input class="field-mono" type="text" readonly value={link} aria-label={`Share link ${idx + 1}`} />
                        <button type="button" class="btn ghost sm" onclick={() => (selectedShareQr = idx)} title="Show QR">
                          QR
                        </button>
                        <button type="button" class="btn sm" onclick={() => copyText(`link-${idx}`, link, `Share link ${idx + 1}`)}>
                          {copiedKey === `link-${idx}` ? 'Copied' : 'Copy'}
                        </button>
                      </div>
                    {/each}
                  </div>
                </div>
              </div>
            {:else}
              <div class="empty">No share links generated for this user.</div>
            {/if}
          </div>
        </div>

        {#if warnings.length}
          <div class="ak-warnings" role="status">
            <strong>Warnings:</strong>
            <ul>
              {#each warnings as w, idx (idx)}
                <li>{w}</li>
              {/each}
            </ul>
          </div>
        {/if}
      {/if}
      <span class="sr-only" aria-live="polite">{liveAnnouncement}</span>
    </div>
  </div>
</dialog>
