<script lang="ts">
  import { onDestroy, tick } from 'svelte';
  import {
    ApiError,
    getClusterConfig,
    getServerConfig,
    patchClusterConfig,
    patchServerConfig,
    regenerateAccessKeys,
    regenerateClusterAccessKeys,
  } from '../../lib/api';
  import { createPoll } from '../../lib/poll.svelte';
  import { toast } from '../../lib/toast.svelte';
  import { ssTargetState, getClusterSummary } from '../../lib/ssTarget.svelte';
  import {
    CIPHER_KINDS,
    ENDPOINT_KIND_OPTIONS,
    TUNING_FIELD_SPECS,
    TUNING_PRESETS,
    buildPerNodePatch,
    buildSharedPatch,
    inferEndpointKind,
    perNodeFromConfig,
    sharedFromConfig,
    splitListText,
    validateEndpoints,
    validateMtu,
    validateNodeHostEntry,
    validatePerNodeSettings,
    validatePublicScheme,
    validateSharedSettings,
    validateSocketAddr,
    type EditableEndpoint,
    type PerNodeSettingsModel,
    type SharedSettingsModel,
    type TuningPresetName,
  } from '../../lib/serverConfigForm';
  import type {
    ClusterConfigResponse,
    ClusterRegenerateResponse,
    NodeActionResult,
    ServerConfigPatch,
    ServerConfigResponse,
    SsTarget,
  } from '../../lib/types';
  import SsTargetSelector from '../../components/layout/SsTargetSelector.svelte';
  import ErrorBanner from '../../components/layout/ErrorBanner.svelte';
  import ConfirmDialog from '../../components/layout/ConfirmDialog.svelte';
  import ClusterStatusStrip from './ClusterStatusStrip.svelte';
  import DriftBadge from './DriftBadge.svelte';
  import PerNodeResultPanel from './PerNodeResultPanel.svelte';
  import RegenerateBanner from './RegenerateBanner.svelte';

  type SettingsTabId = 'carriers' | 'network' | 'camouflage' | 'subscriptions' | 'tuning';

  const SETTINGS_TABS: ReadonlyArray<{ id: SettingsTabId; label: string }> = [
    { id: 'carriers', label: 'Carriers & Endpoints' },
    { id: 'network', label: 'Network & TLS' },
    { id: 'camouflage', label: 'Resumption & Camouflage' },
    { id: 'subscriptions', label: 'Subscriptions' },
    { id: 'tuning', label: 'Tuning & System' },
  ];

  const EMPTY_CFG: ServerConfigResponse = {
    config_path: null,
    cluster: null,
    server: null,
    session_resumption: null,
    outbound: null,
    tuning_profile: 'large',
    endpoints: [],
  };

  function cloneShared(src: SharedSettingsModel): SharedSettingsModel {
    return JSON.parse(JSON.stringify(src)) as SharedSettingsModel;
  }

  function clonePerNodeMap(
    src: Record<string, PerNodeSettingsModel>,
  ): Record<string, PerNodeSettingsModel> {
    return JSON.parse(JSON.stringify(src)) as Record<string, PerNodeSettingsModel>;
  }

  const target = $derived(ssTargetState.target);
  const isCluster = $derived(target?.kind === 'cluster');
  const clusterSummary = $derived(
    target?.kind === 'cluster' ? getClusterSummary(target.name) : null,
  );
  const refreshMs = $derived(Math.max(1000, ssTargetState.refreshSecs * 1000));

  let activeTab = $state<SettingsTabId>('carriers');
  let tabRefs: Record<SettingsTabId, HTMLButtonElement | undefined> = {
    carriers: undefined,
    network: undefined,
    camouflage: undefined,
    subscriptions: undefined,
    tuning: undefined,
  };

  let mutating = $state(false);
  let regenerating = $state(false);
  let showWriteDir = $state(false);
  let submitAttempted = $state(false);
  let touched = $state<Record<string, boolean>>({});
  let h3AlpnText = $state('h3');

  // Target switch confirmation when dirty
  let pendingTarget = $state<SsTarget | null>(null);
  let confirmSwitchOpen = $derived(pendingTarget !== null);

  // Saved snapshot vs editable state
  let initialShared = $state<SharedSettingsModel>(sharedFromConfig(EMPTY_CFG));
  let currShared = $state<SharedSettingsModel>(sharedFromConfig(EMPTY_CFG));
  let initialPerNodeByHost = $state<Record<string, PerNodeSettingsModel>>({});
  let currPerNodeByHost = $state<Record<string, PerNodeSettingsModel>>({});
  let activeNode = $state('');

  // Banners & action results
  let actionResults = $state<NodeActionResult[]>([]);
  let actionTitle = $state('');
  let showRegenerateBanner = $state(false);
  let bannerRestartNodes = $state<string[]>([]);

  // Single polite live region for blur validation announcements
  let liveAnnouncement = $state('');
  let liveTimer: ReturnType<typeof setTimeout> | undefined;
  let lastAnnouncedKey = '';

  type PollData =
    | { kind: 'cluster'; payload: ClusterConfigResponse }
    | { kind: 'single'; payload: ServerConfigResponse }
    | null;

  const configPoll = createPoll<PollData>(
    async () => {
      if (!target) return null;
      if (target.kind === 'cluster') {
        const payload = await getClusterConfig(target.name);
        return { kind: 'cluster', payload };
      }
      const payload = await getServerConfig(target.name);
      return { kind: 'single', payload };
    },
    () => refreshMs,
  );

  $effect(() => {
    void target;
    actionResults = [];
    showRegenerateBanner = false;
    bannerRestartNodes = [];
    touched = {};
    submitAttempted = false;
    lastAnnouncedKey = '';
    liveAnnouncement = '';
    configPoll.start();
  });

  onDestroy(() => {
    configPoll.stop();
    if (liveTimer) clearTimeout(liveTimer);
  });

  const clusterRes = $derived(
    configPoll.data?.kind === 'cluster' ? configPoll.data.payload : null,
  );
  const singleRes = $derived(
    configPoll.data?.kind === 'single' ? configPoll.data.payload : null,
  );

  const clusterNodes = $derived(clusterRes?.nodes ?? []);
  const aliveClusterNodes = $derived(clusterNodes.filter((n) => n.ok && n.config));
  const drift = $derived(clusterRes?.drift ?? []);
  const restartPendingNodes = $derived.by(() => {
    if (clusterRes) return clusterRes.mesh_health.restart_pending_nodes;
    if (singleRes?.restart_pending && target?.kind === 'instance') return [target.name];
    return [];
  });

  const sharedDirtyResult = $derived(buildSharedPatch(currShared, initialShared));
  const dirtyPerNodeByHost = $derived.by(() => {
    const out: Record<string, { patch: ServerConfigPatch; dirtySections: string[] }> = {};
    for (const host of Object.keys(currPerNodeByHost)) {
      const curr = currPerNodeByHost[host];
      const init = initialPerNodeByHost[host];
      if (!curr || !init) continue;
      const res = buildPerNodePatch(curr, init);
      if (res.dirtySections.length > 0) {
        out[host] = res;
      }
    }
    return out;
  });

  const dirtySectionLabels = $derived.by(() => {
    const labels = [...sharedDirtyResult.dirtySections];
    for (const host of Object.keys(dirtyPerNodeByHost)) {
      labels.push(`node:${host}`);
    }
    return labels;
  });

  const formDirty = $derived(dirtySectionLabels.length > 0);

  $effect(() => {
    if (formDirty) return;
    if (clusterRes) {
      const firstAlive = clusterRes.nodes.find((n) => n.ok && n.config)?.config;
      const shared = sharedFromConfig(firstAlive ?? EMPTY_CFG);
      initialShared = shared;
      currShared = cloneShared(shared);
      h3AlpnText = shared.h3Alpn.join(', ');

      const perMap: Record<string, PerNodeSettingsModel> = {};
      for (const n of clusterRes.nodes) {
        if (n.ok && n.config) {
          perMap[n.instance] = perNodeFromConfig(n.config);
        }
      }
      initialPerNodeByHost = perMap;
      currPerNodeByHost = clonePerNodeMap(perMap);

      const hosts = Object.keys(perMap);
      if (!activeNode || !perMap[activeNode]) {
        activeNode = hosts[0] ?? '';
      }
    } else if (singleRes && target?.kind === 'instance') {
      const shared = sharedFromConfig(singleRes);
      initialShared = shared;
      currShared = cloneShared(shared);
      h3AlpnText = shared.h3Alpn.join(', ');

      const per = perNodeFromConfig(singleRes);
      initialPerNodeByHost = { [target.name]: per };
      currPerNodeByHost = { [target.name]: clonePerNodeMap({ x: per }).x };
      activeNode = target.name;
    }
  });

  const activePerNode = $derived<PerNodeSettingsModel | null>(
    activeNode && currPerNodeByHost[activeNode] ? currPerNodeByHost[activeNode] : null,
  );

  // Field-level client validation mapped to key -> error text + target tab
  interface ValidationEntry {
    key: string;
    tab: SettingsTabId;
    node?: string;
    message: string;
  }

  const validationEntries = $derived.by<ValidationEntry[]>(() => {
    const list: ValidationEntry[] = [];

    currShared.endpoints.forEach((ep, idx) => {
      const p = ep.path.trim();
      let msg: string | null = null;
      if (!p) msg = 'Path cannot be empty.';
      else if (!p.startsWith('/')) msg = 'Path must start with "/".';
      else if (/\s/.test(p)) msg = 'Path cannot contain spaces.';
      else if (currShared.endpoints.findIndex((other) => other.path.trim() === p) !== idx) {
        msg = `Duplicate endpoint path "${p}".`;
      }
      if (msg) {
        list.push({ key: `ep:${idx}:path`, tab: 'carriers', message: msg });
      }
    });

    const epWholeErr = validateEndpoints(currShared.endpoints);
    if (epWholeErr && list.length === 0) {
      list.push({ key: 'endpoints', tab: 'carriers', message: epWholeErr });
    }

    const mtuErr = validateMtu(currShared.h3InitialMtu);
    if (mtuErr) list.push({ key: 'h3_initial_mtu', tab: 'network', message: mtuErr });

    const probeErr = validateMtu(currShared.h3MtuFirstProbe);
    if (probeErr) list.push({ key: 'h3_mtu_first_probe', tab: 'network', message: probeErr });

    for (const [host, nodeModel] of Object.entries(currPerNodeByHost)) {
      if (!nodeModel.listen.trim()) {
        list.push({
          key: `node:${host}:listen`,
          tab: 'network',
          node: host,
          message: 'TCP/TLS listen address is required.',
        });
      } else {
        const lErr = validateSocketAddr(nodeModel.listen);
        if (lErr) {
          list.push({ key: `node:${host}:listen`, tab: 'network', node: host, message: lErr });
        }
      }

      const h3Err = validateSocketAddr(nodeModel.h3_listen);
      if (h3Err) {
        list.push({ key: `node:${host}:h3_listen`, tab: 'network', node: host, message: h3Err });
      }

      nodeModel.certs.forEach((c, idx) => {
        if (!c.cert_path.trim() || !c.key_path.trim()) {
          list.push({
            key: `node:${host}:cert:${idx}`,
            tab: 'network',
            node: host,
            message: 'Both cert_path and key_path are required.',
          });
        } else {
          for (const s of splitListText(c.sniText)) {
            if (s.includes('*')) {
              list.push({
                key: `node:${host}:cert:${idx}`,
                tab: 'network',
                node: host,
                message: `Explicit SNI resolver does not support wildcards ("${s}").`,
              });
              break;
            }
          }
        }
      });

      if (nodeModel.h3CertsCustom) {
        nodeModel.h3_certs.forEach((c, idx) => {
          if (!c.cert_path.trim() || !c.key_path.trim()) {
            list.push({
              key: `node:${host}:h3cert:${idx}`,
              tab: 'network',
              node: host,
              message: 'Both cert_path and key_path are required.',
            });
          } else {
            for (const s of splitListText(c.sniText)) {
              if (s.includes('*')) {
                list.push({
                  key: `node:${host}:h3cert:${idx}`,
                  tab: 'network',
                  node: host,
                  message: `Explicit SNI resolver does not support wildcards ("${s}").`,
                });
                break;
              }
            }
          }
        });
      }
    }

    if (
      currShared.padding.min_bytes != null &&
      currShared.padding.max_bytes != null &&
      currShared.padding.min_bytes > currShared.padding.max_bytes
    ) {
      list.push({
        key: 'padding.max_bytes',
        tab: 'camouflage',
        message: 'Padding max_bytes must be >= min_bytes.',
      });
    }

    if (
      currShared.padding.cover_jitter_min_ms != null &&
      currShared.padding.cover_jitter_max_ms != null &&
      currShared.padding.cover_jitter_min_ms > currShared.padding.cover_jitter_max_ms
    ) {
      list.push({
        key: 'padding.jitter_max',
        tab: 'camouflage',
        message: 'Padding cover_jitter_max_ms must be >= cover_jitter_min_ms.',
      });
    }

    if (
      currShared.httpFallback.backend.trim() &&
      !currShared.httpFallback.backend.trim().startsWith('http://')
    ) {
      list.push({
        key: 'http_fallback.backend',
        tab: 'camouflage',
        message: 'Backend URL must start with "http://".',
      });
    }

    if (
      currShared.sniFallback.max_client_hello_bytes != null &&
      currShared.sniFallback.max_client_hello_bytes < 256
    ) {
      list.push({
        key: 'sni_fallback.max_hello',
        tab: 'camouflage',
        message: 'max_client_hello_bytes must be >= 256.',
      });
    }

    const hasSniConfig =
      splitListText(currShared.sniFallback.matchSniText).length > 0 ||
      currShared.sniFallback.backends.length > 0;
    if (hasSniConfig) {
      if (splitListText(currShared.sniFallback.matchSniText).length === 0) {
        list.push({
          key: 'sni_fallback.match_sni',
          tab: 'camouflage',
          message: 'Specify at least one SNI pattern when SNI fallback backends are configured.',
        });
      }
      if (currShared.sniFallback.backends.length === 0) {
        list.push({
          key: 'sni_fallback.match_sni',
          tab: 'camouflage',
          message: 'Add at least one SNI backend when match_sni is configured.',
        });
      }
      currShared.sniFallback.backends.forEach((b, idx) => {
        if (!b.backend.trim()) {
          list.push({
            key: `sni_fallback.backend:${idx}`,
            tab: 'camouflage',
            message: 'Backend host:port is required.',
          });
        } else if (
          splitListText(b.matchSniText).length === 0 &&
          idx !== currShared.sniFallback.backends.length - 1
        ) {
          list.push({
            key: `sni_fallback.backend:${idx}`,
            tab: 'camouflage',
            message: 'Empty match_sni (catch-all) is only allowed on the last backend.',
          });
        }
      });
    }

    const schemeErr = validatePublicScheme(currShared.accessKeys.public_scheme);
    if (schemeErr) {
      list.push({ key: 'access_keys.public_scheme', tab: 'subscriptions', message: schemeErr });
    }

    for (const nodeHost of splitListText(currShared.accessKeys.nodesText)) {
      const nodeErr = validateNodeHostEntry(nodeHost);
      if (nodeErr) {
        list.push({ key: 'access_keys.nodes', tab: 'subscriptions', message: nodeErr });
        break;
      }
    }

    return list;
  });

  const errorMap = $derived.by(() => {
    const map: Record<string, string> = {};
    for (const item of validationEntries) {
      if (!map[item.key]) map[item.key] = item.message;
    }
    return map;
  });

  function fieldError(key: string): string | null {
    if (!touched[key] && !submitAttempted) return null;
    return errorMap[key] ?? null;
  }

  const padBytesErr = $derived(fieldError('padding.max_bytes'));
  const padJitterErr = $derived(fieldError('padding.jitter_max'));
  const hfErr = $derived(fieldError('http_fallback.backend'));
  const sniMatchErr = $derived(fieldError('sni_fallback.match_sni'));
  const sniHelloErr = $derived(fieldError('sni_fallback.max_hello'));
  const schemeErr = $derived(fieldError('access_keys.public_scheme'));
  const nodesErr = $derived(fieldError('access_keys.nodes'));

  function describedBy(...ids: Array<string | null | undefined>): string | undefined {
    const list = ids.filter((id): id is string => Boolean(id));
    return list.length ? list.join(' ') : undefined;
  }

  function onFieldBlur(key: string, label?: string) {
    touched = { ...touched, [key]: true };
    const msg = errorMap[key];
    if (msg) {
      if (lastAnnouncedKey !== `${key}:${msg}`) {
        lastAnnouncedKey = `${key}:${msg}`;
        if (liveTimer) clearTimeout(liveTimer);
        liveAnnouncement = '';
        const prefix = label ? `${label}: ` : '';
        liveTimer = setTimeout(() => {
          liveAnnouncement = `${prefix}Error: ${msg}`;
        }, 400);
      }
    } else if (lastAnnouncedKey.startsWith(`${key}:`)) {
      if (liveTimer) clearTimeout(liveTimer);
      liveAnnouncement = '';
      lastAnnouncedKey = '';
    }
  }

  function optInt(raw: string): number | null {
    const trimmed = raw.trim();
    if (!trimmed) return null;
    const n = Number(trimmed);
    return Number.isFinite(n) ? Math.trunc(n) : null;
  }

  function onH3AlpnInput(raw: string) {
    h3AlpnText = raw;
    const parsed = splitListText(raw);
    currShared.h3Alpn = parsed.length ? parsed : ['h3'];
  }

  async function selectTab(id: SettingsTabId) {
    activeTab = id;
    await tick();
    tabRefs[id]?.scrollIntoView({ block: 'nearest', inline: 'nearest' });
  }

  function onTabKeyDown(e: KeyboardEvent, idx: number) {
    let nextIdx = -1;
    if (e.key === 'ArrowRight') nextIdx = (idx + 1) % SETTINGS_TABS.length;
    else if (e.key === 'ArrowLeft') nextIdx = (idx - 1 + SETTINGS_TABS.length) % SETTINGS_TABS.length;
    else if (e.key === 'Home') nextIdx = 0;
    else if (e.key === 'End') nextIdx = SETTINGS_TABS.length - 1;
    if (nextIdx >= 0) {
      e.preventDefault();
      const next = SETTINGS_TABS[nextIdx];
      void selectTab(next.id).then(() => tabRefs[next.id]?.focus());
    }
  }

  function onBeforeTargetChange(next: SsTarget): boolean {
    if (!formDirty) return true;
    pendingTarget = next;
    return false;
  }

  function confirmDiscardTargetSwitch() {
    const next = pendingTarget;
    pendingTarget = null;
    if (!next) return;
    currShared = cloneShared(initialShared);
    currPerNodeByHost = clonePerNodeMap(initialPerNodeByHost);
    h3AlpnText = initialShared.h3Alpn.join(', ');
    touched = {};
    submitAttempted = false;
    ssTargetState.target = next;
  }

  function discardChanges() {
    currShared = cloneShared(initialShared);
    currPerNodeByHost = clonePerNodeMap(initialPerNodeByHost);
    h3AlpnText = initialShared.h3Alpn.join(', ');
    touched = {};
    submitAttempted = false;
    liveAnnouncement = 'Unsaved settings discarded.';
  }

  function addEndpoint() {
    const existing = new Set(currShared.endpoints.map((e) => e.path));
    let candidate = '/ws';
    let idx = 2;
    while (existing.has(candidate)) {
      candidate = `/ws-${idx++}`;
    }
    currShared.endpoints.push({ path: candidate, kind: 'ws_ss', padded: false });
  }

  function removeEndpoint(index: number) {
    currShared.endpoints.splice(index, 1);
  }

  function addCert(list: 'certs' | 'h3_certs') {
    if (!activePerNode) return;
    activePerNode[list].push({ cert_path: '', key_path: '', sniText: '' });
  }

  function removeCert(list: 'certs' | 'h3_certs', index: number) {
    if (!activePerNode) return;
    activePerNode[list].splice(index, 1);
  }

  function addSniBackend() {
    currShared.sniFallback.backends.push({
      backend: '',
      proxy_protocol: '',
      matchSniText: '',
    });
  }

  function removeSniBackend(index: number) {
    currShared.sniFallback.backends.splice(index, 1);
  }

  function clearAllTuningOverrides() {
    for (const spec of TUNING_FIELD_SPECS) {
      currShared.tuningOverrides[spec.key] = null;
    }
  }

  function fillNodesFromCluster() {
    if (!clusterSummary?.subscription_nodes.length) return;
    currShared.accessKeys.nodesText = clusterSummary.subscription_nodes.join('\n');
    onFieldBlur('access_keys.nodes', 'Subscription nodes');
  }

  async function focusFirstValidationError() {
    const first = validationEntries[0];
    if (!first) return;
    activeTab = first.tab;
    if (first.node && currPerNodeByHost[first.node]) {
      activeNode = first.node;
    }
    await tick();
    const el = document.querySelector<HTMLElement>(`[data-val-key="${CSS.escape(first.key)}"]`);
    el?.focus();
    el?.scrollIntoView({ block: 'center', inline: 'nearest' });
  }

  async function save() {
    if (!target || mutating) return;
    submitAttempted = true;

    const sharedErr = validateSharedSettings(currShared);
    let perErr: string | null = null;
    for (const [host, model] of Object.entries(currPerNodeByHost)) {
      const e = validatePerNodeSettings(model);
      if (e) {
        perErr = `${host}: ${e}`;
        break;
      }
    }

    if (validationEntries.length > 0 || sharedErr || perErr) {
      const summary = validationEntries[0]?.message ?? sharedErr ?? perErr ?? 'Fix validation errors before saving.';
      toast(summary, 'error');
      liveAnnouncement = `Cannot save. Error: ${summary}`;
      await focusFirstValidationError();
      return;
    }

    if (!formDirty) {
      toast('No changes to save.');
      return;
    }

    mutating = true;
    actionResults = [];
    try {
      if (target.kind === 'cluster') {
        const per_node: Record<string, ServerConfigPatch> = {};
        for (const [host, item] of Object.entries(dirtyPerNodeByHost)) {
          per_node[host] = item.patch;
        }
        const shared =
          sharedDirtyResult.dirtySections.length > 0 ? sharedDirtyResult.patch : undefined;

        const res = await patchClusterConfig(target.name, {
          ...(shared ? { shared } : {}),
          ...(Object.keys(per_node).length ? { per_node } : {}),
        });
        actionTitle = `Config save · ${target.name}`;
        actionResults = res.results;

        const restartNodes = res.results
          .filter((r) => r.ok && r.requires_restart)
          .map((r) => r.instance);
        bannerRestartNodes = restartNodes;
        showRegenerateBanner = true;

        if (res.ok) {
          initialShared = cloneShared(currShared);
          initialPerNodeByHost = clonePerNodeMap(currPerNodeByHost);
          touched = {};
          submitAttempted = false;
          toast(
            restartNodes.length
              ? `Saved to cluster. Restart pending on: ${restartNodes.join(', ')}.`
              : 'Saved to cluster (applied immediately, no server restart needed).',
          );
          await configPoll.refresh();
        } else {
          toast(res.error ?? 'Cluster settings save partially failed.', 'error');
        }
      } else {
        const singlePer = dirtyPerNodeByHost[target.name]?.patch ?? {};
        const merged: ServerConfigPatch = {
          ...sharedDirtyResult.patch,
          ...singlePer,
          ...(sharedDirtyResult.patch.server || singlePer.server
            ? { server: { ...(sharedDirtyResult.patch.server ?? {}), ...(singlePer.server ?? {}) } }
            : {}),
          ...(sharedDirtyResult.patch.outbound || singlePer.outbound
            ? {
                outbound: {
                  ...(sharedDirtyResult.patch.outbound ?? {}),
                  ...(singlePer.outbound ?? {}),
                },
              }
            : {}),
        };

        const res = await patchServerConfig(target.name, merged);
        bannerRestartNodes = res.requires_restart ? [target.name] : [];
        showRegenerateBanner = true;
        initialShared = cloneShared(currShared);
        initialPerNodeByHost = clonePerNodeMap(currPerNodeByHost);
        touched = {};
        submitAttempted = false;
        toast(
          res.requires_restart
            ? 'Settings saved. Restart outline-server to apply listener/TLS/tuning changes.'
            : 'Settings saved (applied immediately, no server restart needed).',
        );
        await configPoll.refresh();
      }
    } catch (e) {
      const msg = e instanceof ApiError || e instanceof Error ? e.message : String(e);
      toast(msg, 'error');
    } finally {
      mutating = false;
    }
  }

  async function regenerateNow() {
    if (!target || regenerating) return;
    regenerating = true;
    try {
      if (target.kind === 'cluster') {
        const nodes = clusterSummary?.subscription_nodes?.length
          ? clusterSummary.subscription_nodes
          : undefined;
        const res: ClusterRegenerateResponse = await regenerateClusterAccessKeys(target.name, {
          prune: true,
          ...(nodes ? { nodes } : {}),
        });
        actionTitle = `Regenerate subscriptions · ${target.name}`;
        actionResults = res.results;
        if (res.ok) {
          toast('Subscriptions regenerated across cluster (deleted users pruned).');
          showRegenerateBanner = false;
        } else {
          toast('Subscription regeneration had errors on some nodes.', 'error');
        }
      } else {
        const nodes = splitListText(currShared.accessKeys.nodesText);
        const rep = await regenerateAccessKeys(target.name, {
          prune: true,
          ...(nodes.length ? { nodes } : {}),
        });
        const written = rep.written?.length ?? 0;
        const pruned = rep.pruned?.length ?? 0;
        toast(`Subscriptions regenerated (${written} written, ${pruned} pruned).`);
        showRegenerateBanner = false;
      }
    } catch (e) {
      toast(e instanceof Error ? e.message : String(e), 'error');
    } finally {
      regenerating = false;
    }
  }

  function applyAlignedOutboundField(key: keyof SharedSettingsModel['outboundShared'], value: unknown) {
    if (key === 'allowedSubnetsText') {
      currShared.outboundShared.allowedSubnetsText = Array.isArray(value)
        ? value.map(String).join(', ')
        : '';
    } else if (key === 'prefer_ipv4' || key === 'ipv6_sticky' || key === 'block_private_ips') {
      currShared.outboundShared[key] = Boolean(value);
    } else {
      currShared.outboundShared[key] = typeof value === 'number' ? value : null;
    }
  }
</script>

<section class="view active" class:view-has-savebar={formDirty}>
  <div class="sr-only" aria-live="polite">{liveAnnouncement}</div>

  <div class="page-head">
    <div>
      <h1>Server Settings</h1>
      <p>
        Manage endpoints, listeners, TLS, camouflage, subscriptions, and runtime tuning
        {#if isCluster}across the cluster{:else}for the selected server{/if}.
      </p>
    </div>
    <div class="toolbar">
      <SsTargetSelector onBeforeChange={onBeforeTargetChange} />
      <button
        type="button"
        class="btn primary sm"
        disabled={!target || mutating || !formDirty}
        onclick={save}
      >
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
        {#if mutating}
          Saving…
        {:else if isCluster}
          Save to cluster ({aliveClusterNodes.length} nodes)
        {:else}
          Save changes
        {/if}
      </button>
    </div>
  </div>

  {#if !target}
    <div class="empty">Select a cluster or server to inspect and configure its settings.</div>
  {:else}
    {#if isCluster && clusterRes}
      <ClusterStatusStrip
        cluster={clusterSummary}
        reachableNodes={aliveClusterNodes.length}
        totalNodes={clusterNodes.length}
        {restartPendingNodes}
        {regenerating}
        onRegenerate={regenerateNow}
      />
    {:else if restartPendingNodes.length > 0}
      <div class="applybar" role="status" aria-live="polite">
        <span class="pill">RESTART PENDING</span>
        <span>Config has changes waiting for a manual <code>outline-server</code> restart.</span>
      </div>
    {/if}

    <ErrorBanner message={configPoll.error} />

    {#if isCluster && clusterNodes.some((n) => !n.ok)}
      <div class="error-banner" role="alert">
        <span>
          Offline nodes:
          {clusterNodes
            .filter((n) => !n.ok)
            .map((n) => `${n.instance} (${n.error ?? `HTTP ${n.status}`})`)
            .join(', ')}
        </span>
      </div>
    {/if}

    <RegenerateBanner
      visible={showRegenerateBanner}
      restartPendingNodes={bannerRestartNodes}
      {regenerating}
      onRegenerate={regenerateNow}
      onDismiss={() => (showRegenerateBanner = false)}
    />

    <PerNodeResultPanel
      title={actionTitle}
      results={actionResults}
      onDismiss={() => (actionResults = [])}
    />

    {#if clusterRes || singleRes}
      <div class="tablist-row" role="tablist" aria-label="Server configuration sections">
        {#each SETTINGS_TABS as tab, idx (tab.id)}
          <button
            bind:this={tabRefs[tab.id]}
            type="button"
            role="tab"
            id={`settings-tab-${tab.id}`}
            class="tab-btn"
            aria-selected={activeTab === tab.id}
            tabindex={activeTab === tab.id ? 0 : -1}
            onclick={() => void selectTab(tab.id)}
            onkeydown={(e) => onTabKeyDown(e, idx)}
          >
            {tab.label}
          </button>
        {/each}
      </div>

      <div class="tabpanels-host">
        <!-- Tab 1: Carriers & Endpoints -->
        <div
          role="tabpanel"
          aria-labelledby="settings-tab-carriers"
          hidden={activeTab === 'carriers' ? undefined : ('until-found' as unknown as boolean)}
          tabindex={activeTab === 'carriers' ? 0 : undefined}
          onbeforematch={() => (activeTab = 'carriers')}
        >
          <div class="tabpanel-inner">
            <div class="settings-two-col">
              <div class="panel panel-form panel-pad">
                <div class="section-head-row">
                  <h3>[[endpoint]] Endpoints</h3>
                  {#if isCluster}
                    <DriftBadge
                      fieldKey="endpoints"
                      {drift}
                      nodes={clusterNodes}
                      extractValue={(c) =>
                        (c.endpoints ?? []).map((ep) => ({
                          path: ep.path,
                          kind: inferEndpointKind(ep),
                          padded: Boolean(ep.padded),
                        }))}
                      onAlign={(v) => {
                        currShared.endpoints = (v as EditableEndpoint[]).map((ep) => ({ ...ep }));
                      }}
                    />
                  {/if}
                  <span class="spacer"></span>
                  <button type="button" class="btn ghost sm" onclick={addEndpoint}>
                    + Add endpoint
                  </button>
                </div>
                <p class="panel-head-desc">
                  Path-independent carrier routes. Changing endpoint paths or kinds requires restarting the server and regenerating subscriptions.
                </p>

                {#if currShared.endpoints.length === 0}
                  <div class="empty">No endpoints configured. Add at least one WebSocket or XHTTP endpoint.</div>
                {:else}
                  <div class="stack-form">
                    {#each currShared.endpoints as ep, idx (idx)}
                      {@const epKey = `ep:${idx}:path`}
                      {@const epErr = fieldError(epKey)}
                      <div class="subcard">
                        <div class="form-grid-endpoint">
                          <div class="fieldrow">
                            <label for={`ep-path-${idx}`}>Path</label>
                            <input
                              id={`ep-path-${idx}`}
                              data-val-key={epKey}
                              type="text"
                              class="field-mono"
                              placeholder="/ws-ss"
                              bind:value={ep.path}
                              aria-invalid={epErr ? 'true' : 'false'}
                              aria-describedby={describedBy(`ep-path-hint-${idx}`, epErr ? `ep-path-err-${idx}` : null)}
                              onblur={() => onFieldBlur(epKey, `Endpoint #${idx + 1} path`)}
                            />
                            <span id={`ep-path-hint-${idx}`} class="hint">Must start with <code>/</code> without whitespace.</span>
                            {#if epErr}
                              <div id={`ep-path-err-${idx}`} class="field-error">
                                <span class="err-prefix" aria-hidden="true">Error:</span> {epErr}
                              </div>
                            {/if}
                          </div>

                          <div class="fieldrow">
                            <label for={`ep-kind-${idx}`}>Carrier &amp; Protocol (kind)</label>
                            <select
                              id={`ep-kind-${idx}`}
                              class="field-mono"
                              bind:value={ep.kind}
                            >
                              {#each ENDPOINT_KIND_OPTIONS as opt (opt.kind)}
                                <option value={opt.kind}>{opt.label}</option>
                              {/each}
                            </select>
                          </div>
                        </div>

                        <div class="subcard-foot">
                          <label class="switch">
                            <input type="checkbox" bind:checked={ep.padded} />
                            <span>Padding enabled (<code>padded</code>)</span>
                          </label>
                          <button
                            type="button"
                            class="btn danger sm"
                            onclick={() => removeEndpoint(idx)}
                          >
                            Remove
                          </button>
                        </div>
                      </div>
                    {/each}
                  </div>
                {/if}
              </div>

              <div class="stack-form">
                <div class="panel panel-form panel-pad">
                  <div class="section-head-row">
                    <h3>[shadowsocks] Cipher Method</h3>
                    {#if isCluster}
                      <DriftBadge
                        fieldKey="shadowsocks.method"
                        {drift}
                        nodes={clusterNodes}
                        extractValue={(c) => c.shadowsocks?.method ?? ''}
                        onAlign={(v) => {
                          currShared.shadowsocksMethod = String(v ?? '');
                        }}
                      />
                    {/if}
                  </div>
                  <div class="fieldrow">
                    <label for="ss-method-select">Shadowsocks AEAD / 2022 Method</label>
                    <select
                      id="ss-method-select"
                      class="field-mono"
                      bind:value={currShared.shadowsocksMethod}
                      aria-describedby="ss-method-hint"
                    >
                      <option value="">Not configured (VLESS-only)</option>
                      {#each CIPHER_KINDS as kind (kind)}
                        <option value={kind}>{kind}</option>
                      {/each}
                    </select>
                    <span id="ss-method-hint" class="hint">
                      Shared server cipher method for Shadowsocks endpoints. Empty if running VLESS-only.
                    </span>
                  </div>
                </div>

                <div class="panel panel-form panel-pad">
                  <div class="section-head-row">
                    <h3>[http_root] HTTP Root Probe</h3>
                    {#if isCluster}
                      <DriftBadge
                        fieldKey="http_root"
                        {drift}
                        nodes={clusterNodes}
                        extractValue={(c) => ({
                          auth: Boolean(c.http_root?.auth),
                          realm: c.http_root?.realm ?? '',
                        })}
                        onAlign={(v) => {
                          const x = v as { auth: boolean; realm: string };
                          currShared.httpRootAuth = Boolean(x.auth);
                          currShared.httpRootRealm = x.realm ?? '';
                        }}
                      />
                    {/if}
                  </div>
                  <div class="stack-form">
                    <label class="switch">
                      <input type="checkbox" bind:checked={currShared.httpRootAuth} />
                      <span>Require HTTP auth / 401 camouflage on <code>/</code></span>
                    </label>
                    <div class="fieldrow">
                      <label for="http-root-realm">WWW-Authenticate Realm</label>
                      <input
                        id="http-root-realm"
                        type="text"
                        placeholder="Restricted Area"
                        bind:value={currShared.httpRootRealm}
                        aria-describedby="http-root-realm-hint"
                      />
                      <span id="http-root-realm-hint" class="hint">
                        Optional realm string returned when HTTP root auth is enabled.
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Tab 2: Network & TLS -->
        <div
          role="tabpanel"
          aria-labelledby="settings-tab-network"
          hidden={activeTab === 'network' ? undefined : ('until-found' as unknown as boolean)}
          tabindex={activeTab === 'network' ? 0 : undefined}
          onbeforematch={() => (activeTab = 'network')}
        >
          <div class="tabpanel-inner">
            {#if isCluster && clusterNodes.length > 0}
              <div class="node-switcher panel panel-pad" style="margin-bottom: var(--sp-4);">
                <span class="hint" style="font-size: 12px; font-weight: 600;">
                  Per-node network settings (editing node):
                </span>
                <div class="health-chips">
                  {#each clusterNodes as n (n.instance)}
                    {@const nodeDirty = Boolean(dirtyPerNodeByHost[n.instance])}
                    <button
                      type="button"
                      class="btn sm"
                      class:primary={activeNode === n.instance}
                      disabled={!n.ok || !currPerNodeByHost[n.instance]}
                      onclick={() => (activeNode = n.instance)}
                    >
                      <span class="mono">{n.instance}</span>
                      {#if nodeDirty}<span>*</span>{/if}
                      {#if !n.ok}<span class="muted">(offline)</span>{/if}
                    </button>
                  {/each}
                </div>
              </div>
            {/if}

            <div class="settings-two-col">
              <!-- TCP/TLS Listener + Certs (Per-node) + Shared limit -->
              <div class="panel panel-form panel-pad">
                <div class="section-head-row">
                  <h3>TCP / TLS Listener {#if isCluster && activeNode}· <span class="mono">{activeNode}</span>{/if}</h3>
                  {#if isCluster}
                    <DriftBadge
                      fieldKey="server.max_connections_per_ip"
                      label="max_conn drift"
                      {drift}
                      nodes={clusterNodes}
                      extractValue={(c) => c.server?.max_connections_per_ip ?? null}
                      onAlign={(v) => {
                        currShared.maxConnectionsPerIp = typeof v === 'number' ? v : null;
                      }}
                    />
                  {/if}
                </div>

                {#if activePerNode}
                  {@const listenKey = `node:${activeNode}:listen`}
                  {@const listenErr = fieldError(listenKey)}
                  <div class="stack-form">
                    <div class="fieldrow">
                      <label for="srv-listen">Listen address (per-node)</label>
                      <input
                        id="srv-listen"
                        data-val-key={listenKey}
                        type="text"
                        class="field-mono"
                        placeholder="0.0.0.0:443"
                        bind:value={activePerNode.listen}
                        aria-invalid={listenErr ? 'true' : 'false'}
                        aria-describedby={describedBy('srv-listen-hint', listenErr ? 'srv-listen-err' : null)}
                        onblur={() => onFieldBlur(listenKey, 'Listen address')}
                      />
                      <span id="srv-listen-hint" class="hint">
                        Format: <code>0.0.0.0:443</code> or <code>[::]:443</code>.
                      </span>
                      {#if listenErr}
                        <div id="srv-listen-err" class="field-error">
                          <span class="err-prefix" aria-hidden="true">Error:</span> {listenErr}
                        </div>
                      {/if}
                    </div>

                    <div class="fieldrow">
                      <label for="srv-cert-path">Default cert_path (per-node)</label>
                      <input
                        id="srv-cert-path"
                        type="text"
                        class="field-mono"
                        placeholder="/etc/letsencrypt/live/fleet.example/fullchain.pem"
                        bind:value={activePerNode.cert_path}
                        aria-describedby="srv-cert-hint"
                      />
                      <span id="srv-cert-hint" class="hint">
                        Setting TCP cert_path/key_path is also inherited by HTTP/3 unless <code>[[server.h3.certs]]</code> overrides it as empty.
                      </span>
                    </div>

                    <div class="fieldrow">
                      <label for="srv-key-path">Default key_path (per-node)</label>
                      <input
                        id="srv-key-path"
                        type="text"
                        class="field-mono"
                        placeholder="/etc/letsencrypt/live/fleet.example/privkey.pem"
                        bind:value={activePerNode.key_path}
                      />
                    </div>

                    <div class="fieldrow">
                      <label for="srv-max-conn">max_connections_per_ip (shared)</label>
                      <input
                        id="srv-max-conn"
                        type="number"
                        min="0"
                        class="field-mono"
                        value={currShared.maxConnectionsPerIp ?? ''}
                        aria-describedby="srv-max-conn-hint"
                        oninput={(e) => (currShared.maxConnectionsPerIp = optInt(e.currentTarget.value))}
                      />
                      <span id="srv-max-conn-hint" class="hint">
                        Leave empty for server default / unlimited. Applies to all nodes in cluster.
                      </span>
                    </div>

                    <div class="section-head-row" style="margin-top: var(--sp-2);">
                      <strong>[[server.certs]] Multi-SNI Certificates</strong>
                      <span class="spacer"></span>
                      <button type="button" class="btn ghost sm" onclick={() => addCert('certs')}>
                        + Add cert
                      </button>
                    </div>
                    {#each activePerNode.certs as cert, idx (idx)}
                      {@const cKey = `node:${activeNode}:cert:${idx}`}
                      {@const cErr = fieldError(cKey)}
                      <div class="subcard">
                        <div class="stack-form">
                          <div class="fieldrow">
                            <label for={`cert-path-${idx}`}>cert_path</label>
                            <input
                              id={`cert-path-${idx}`}
                              data-val-key={cKey}
                              type="text"
                              class="field-mono"
                              bind:value={cert.cert_path}
                              aria-invalid={cErr ? 'true' : 'false'}
                              aria-describedby={describedBy(cErr ? `cert-err-${idx}` : null)}
                              onblur={() => onFieldBlur(cKey, `TCP cert #${idx + 1}`)}
                            />
                          </div>
                          <div class="fieldrow">
                            <label for={`cert-key-${idx}`}>key_path</label>
                            <input
                              id={`cert-key-${idx}`}
                              type="text"
                              class="field-mono"
                              bind:value={cert.key_path}
                              onblur={() => onFieldBlur(cKey, `TCP cert #${idx + 1}`)}
                            />
                          </div>
                          <div class="fieldrow">
                            <label for={`cert-sni-${idx}`}>SNI hostnames (comma-separated, no wildcards)</label>
                            <input
                              id={`cert-sni-${idx}`}
                              type="text"
                              class="field-mono"
                              placeholder="edge-a.fleet.example, cdn.fleet.example"
                              bind:value={cert.sniText}
                              onblur={() => onFieldBlur(cKey, `TCP cert #${idx + 1} SNI`)}
                            />
                          </div>
                          {#if cErr}
                            <div id={`cert-err-${idx}`} class="field-error">
                              <span class="err-prefix" aria-hidden="true">Error:</span> {cErr}
                            </div>
                          {/if}
                          <div class="subcard-foot">
                            <span class="spacer"></span>
                            <button
                              type="button"
                              class="btn danger sm"
                              onclick={() => removeCert('certs', idx)}
                            >
                              Remove
                            </button>
                          </div>
                        </div>
                      </div>
                    {/each}
                  </div>
                {/if}
              </div>

              <!-- HTTP/3 & QUIC -->
              <div class="panel panel-form panel-pad">
                <div class="section-head-row">
                  <h3>HTTP/3 &amp; QUIC {#if isCluster && activeNode}· <span class="mono">{activeNode}</span>{/if}</h3>
                  {#if isCluster}
                    <DriftBadge
                      fieldKey="server.h3_alpn"
                      label="h3 drift"
                      {drift}
                      nodes={clusterNodes}
                      extractValue={(c) => c.server?.h3_alpn ?? ['h3']}
                      onAlign={(v) => {
                        const arr = Array.isArray(v) ? v.map(String) : ['h3'];
                        currShared.h3Alpn = arr.length ? arr : ['h3'];
                        h3AlpnText = currShared.h3Alpn.join(', ');
                      }}
                    />
                  {/if}
                </div>

                {#if activePerNode}
                  {@const h3ListenKey = `node:${activeNode}:h3_listen`}
                  {@const h3ListenErr = fieldError(h3ListenKey)}
                  {@const mtuErr = fieldError('h3_initial_mtu')}
                  {@const probeErr = fieldError('h3_mtu_first_probe')}
                  <div class="stack-form">
                    <div class="fieldrow">
                      <label for="h3-listen">h3_listen (UDP socket, per-node)</label>
                      <input
                        id="h3-listen"
                        data-val-key={h3ListenKey}
                        type="text"
                        class="field-mono"
                        placeholder="0.0.0.0:443"
                        bind:value={activePerNode.h3_listen}
                        aria-invalid={h3ListenErr ? 'true' : 'false'}
                        aria-describedby={describedBy('h3-listen-hint', h3ListenErr ? 'h3-listen-err' : null)}
                        onblur={() => onFieldBlur(h3ListenKey, 'H3 listen address')}
                      />
                      <span id="h3-listen-hint" class="hint">
                        Leave empty to disable HTTP/3 listener (only valid when H3 does not inherit TCP certs).
                      </span>
                      {#if h3ListenErr}
                        <div id="h3-listen-err" class="field-error">
                          <span class="err-prefix" aria-hidden="true">Error:</span> {h3ListenErr}
                        </div>
                      {/if}
                    </div>

                    <div class="fieldrow">
                      <label for="h3-cert-path">h3_cert_path override (per-node)</label>
                      <input
                        id="h3-cert-path"
                        type="text"
                        class="field-mono"
                        placeholder="Inherit server.cert_path"
                        bind:value={activePerNode.h3_cert_path}
                      />
                    </div>

                    <div class="fieldrow">
                      <label for="h3-key-path">h3_key_path override (per-node)</label>
                      <input
                        id="h3-key-path"
                        type="text"
                        class="field-mono"
                        placeholder="Inherit server.key_path"
                        bind:value={activePerNode.h3_key_path}
                      />
                    </div>

                    <label class="switch">
                      <input type="checkbox" bind:checked={activePerNode.h3CertsCustom} />
                      <span>Override <code>[[server.h3.certs]]</code> independently from TCP certs</span>
                    </label>

                    {#if activePerNode.h3CertsCustom}
                      <div class="section-head-row">
                        <strong>[[server.h3.certs]] Custom H3 Certs</strong>
                        <span class="spacer"></span>
                        <button type="button" class="btn ghost sm" onclick={() => addCert('h3_certs')}>
                          + Add H3 cert
                        </button>
                      </div>
                      {#each activePerNode.h3_certs as cert, idx (idx)}
                        {@const hcKey = `node:${activeNode}:h3cert:${idx}`}
                        {@const hcErr = fieldError(hcKey)}
                        <div class="subcard">
                          <div class="stack-form">
                            <div class="fieldrow">
                              <label for={`h3cert-path-${idx}`}>cert_path</label>
                              <input
                                id={`h3cert-path-${idx}`}
                                data-val-key={hcKey}
                                type="text"
                                class="field-mono"
                                bind:value={cert.cert_path}
                                aria-invalid={hcErr ? 'true' : 'false'}
                                aria-describedby={describedBy(hcErr ? `h3cert-err-${idx}` : null)}
                                onblur={() => onFieldBlur(hcKey, `H3 cert #${idx + 1}`)}
                              />
                            </div>
                            <div class="fieldrow">
                              <label for={`h3cert-key-${idx}`}>key_path</label>
                              <input
                                id={`h3cert-key-${idx}`}
                                type="text"
                                class="field-mono"
                                bind:value={cert.key_path}
                                onblur={() => onFieldBlur(hcKey, `H3 cert #${idx + 1}`)}
                              />
                            </div>
                            <div class="fieldrow">
                              <label for={`h3cert-sni-${idx}`}>SNI hostnames (comma-separated)</label>
                              <input
                                id={`h3cert-sni-${idx}`}
                                type="text"
                                class="field-mono"
                                bind:value={cert.sniText}
                                onblur={() => onFieldBlur(hcKey, `H3 cert #${idx + 1} SNI`)}
                              />
                            </div>
                            {#if hcErr}
                              <div id={`h3cert-err-${idx}`} class="field-error">
                                <span class="err-prefix" aria-hidden="true">Error:</span> {hcErr}
                              </div>
                            {/if}
                            <div class="subcard-foot">
                              <span class="spacer"></span>
                              <button
                                type="button"
                                class="btn danger sm"
                                onclick={() => removeCert('h3_certs', idx)}
                              >
                                Remove
                              </button>
                            </div>
                          </div>
                        </div>
                      {/each}
                    {/if}

                    <div class="fieldrow">
                      <label for="h3-alpn">h3_alpn protocols (shared)</label>
                      <input
                        id="h3-alpn"
                        type="text"
                        class="field-mono"
                        value={h3AlpnText}
                        aria-describedby="h3-alpn-hint"
                        oninput={(e) => onH3AlpnInput(e.currentTarget.value)}
                      />
                      <span id="h3-alpn-hint" class="hint">Comma-separated ALPN tokens, default: <code>h3</code>.</span>
                    </div>

                    <div class="section-head-row">
                      <label class="switch">
                        <input type="checkbox" bind:checked={currShared.h3UdpDatagrams} />
                        <span>Enable QUIC H3 datagrams (<code>h3_udp_datagrams</code>, shared)</span>
                      </label>
                      {#if isCluster}
                        <DriftBadge
                          fieldKey="server.h3_udp_datagrams"
                          {drift}
                          nodes={clusterNodes}
                          extractValue={(c) => c.server?.h3_udp_datagrams ?? true}
                          onAlign={(v) => (currShared.h3UdpDatagrams = Boolean(v))}
                        />
                      {/if}
                    </div>

                    <div class="form-grid-2">
                      <div class="fieldrow">
                        <div class="field-head">
                          <label for="h3-init-mtu">h3_initial_mtu (shared)</label>
                          {#if isCluster}
                            <DriftBadge
                              fieldKey="server.h3_initial_mtu"
                              {drift}
                              nodes={clusterNodes}
                              extractValue={(c) => c.server?.h3_initial_mtu ?? null}
                              onAlign={(v) => (currShared.h3InitialMtu = typeof v === 'number' ? v : null)}
                            />
                          {/if}
                        </div>
                        <input
                          id="h3-init-mtu"
                          data-val-key="h3_initial_mtu"
                          type="number"
                          min="1200"
                          max="1452"
                          class="field-mono"
                          value={currShared.h3InitialMtu ?? ''}
                          aria-invalid={mtuErr ? 'true' : 'false'}
                          aria-describedby={describedBy('h3-init-mtu-hint', mtuErr ? 'h3-init-mtu-err' : null)}
                          oninput={(e) => (currShared.h3InitialMtu = optInt(e.currentTarget.value))}
                          onblur={() => onFieldBlur('h3_initial_mtu', 'H3 initial MTU')}
                        />
                        <span id="h3-init-mtu-hint" class="hint">1200–1452 bytes (blank resets to default).</span>
                        {#if mtuErr}
                          <div id="h3-init-mtu-err" class="field-error">
                            <span class="err-prefix" aria-hidden="true">Error:</span> {mtuErr}
                          </div>
                        {/if}
                      </div>

                      <div class="fieldrow">
                        <div class="field-head">
                          <label for="h3-probe-mtu">h3_mtu_first_probe (shared)</label>
                          {#if isCluster}
                            <DriftBadge
                              fieldKey="server.h3_mtu_first_probe"
                              {drift}
                              nodes={clusterNodes}
                              extractValue={(c) => c.server?.h3_mtu_first_probe ?? null}
                              onAlign={(v) => (currShared.h3MtuFirstProbe = typeof v === 'number' ? v : null)}
                            />
                          {/if}
                        </div>
                        <input
                          id="h3-probe-mtu"
                          data-val-key="h3_mtu_first_probe"
                          type="number"
                          min="1200"
                          max="1452"
                          class="field-mono"
                          value={currShared.h3MtuFirstProbe ?? ''}
                          aria-invalid={probeErr ? 'true' : 'false'}
                          aria-describedby={describedBy('h3-probe-mtu-hint', probeErr ? 'h3-probe-mtu-err' : null)}
                          oninput={(e) => (currShared.h3MtuFirstProbe = optInt(e.currentTarget.value))}
                          onblur={() => onFieldBlur('h3_mtu_first_probe', 'H3 first MTU probe')}
                        />
                        <span id="h3-probe-mtu-hint" class="hint">1200–1452 bytes (blank resets to default).</span>
                        {#if probeErr}
                          <div id="h3-probe-mtu-err" class="field-error">
                            <span class="err-prefix" aria-hidden="true">Error:</span> {probeErr}
                          </div>
                        {/if}
                      </div>
                    </div>
                  </div>
                {/if}
              </div>

              <!-- Outbound Routing -->
              <div class="panel panel-form panel-pad full-span">
                <div class="section-head-row">
                  <h3>[outbound] Outbound Routing &amp; IPv6</h3>
                  {#if isCluster}
                    <DriftBadge
                      fieldKey="outbound.prefer_ipv4"
                      label="prefer_ipv4 drift"
                      {drift}
                      nodes={clusterNodes}
                      extractValue={(c) => Boolean(c.outbound?.prefer_ipv4)}
                      onAlign={(v) => applyAlignedOutboundField('prefer_ipv4', v)}
                    />
                    <DriftBadge
                      fieldKey="outbound.block_private_ips"
                      label="block_private_ips drift"
                      {drift}
                      nodes={clusterNodes}
                      extractValue={(c) => Boolean(c.outbound?.block_private_ips)}
                      onAlign={(v) => applyAlignedOutboundField('block_private_ips', v)}
                    />
                    <DriftBadge
                      fieldKey="outbound.allowed_subnets"
                      label="allowed_subnets drift"
                      {drift}
                      nodes={clusterNodes}
                      extractValue={(c) => c.outbound?.allowed_subnets ?? []}
                      onAlign={(v) => applyAlignedOutboundField('allowedSubnetsText', v)}
                    />
                  {/if}
                </div>

                <div class="settings-two-col">
                  <div class="stack-form">
                    <label class="switch">
                      <input type="checkbox" bind:checked={currShared.outboundShared.prefer_ipv4} />
                      <span>Prefer IPv4 DNS targets (<code>prefer_ipv4</code>, shared)</span>
                    </label>
                    <label class="switch">
                      <input type="checkbox" bind:checked={currShared.outboundShared.ipv6_sticky} />
                      <span>Sticky IPv6 source per destination (<code>ipv6_sticky</code>, shared)</span>
                    </label>
                    <label class="switch">
                      <input type="checkbox" bind:checked={currShared.outboundShared.block_private_ips} />
                      <span>Block outbound private/loopback IP ranges (SSRF guard, shared)</span>
                    </label>
                    <div class="form-grid-2">
                      <div class="fieldrow">
                        <label for="out-sticky-ttl">ipv6_sticky_ttl_secs</label>
                        <input
                          id="out-sticky-ttl"
                          type="number"
                          min="1"
                          class="field-mono"
                          value={currShared.outboundShared.ipv6_sticky_ttl_secs ?? ''}
                          oninput={(e) =>
                            (currShared.outboundShared.ipv6_sticky_ttl_secs = optInt(e.currentTarget.value))}
                        />
                      </div>
                      <div class="fieldrow">
                        <label for="out-refresh">ipv6_refresh_secs</label>
                        <input
                          id="out-refresh"
                          type="number"
                          min="0"
                          class="field-mono"
                          value={currShared.outboundShared.ipv6_refresh_secs ?? ''}
                          oninput={(e) =>
                            (currShared.outboundShared.ipv6_refresh_secs = optInt(e.currentTarget.value))}
                        />
                      </div>
                    </div>
                    <div class="fieldrow">
                      <label for="out-subnets">allowed_subnets (shared CIDR whitelist override)</label>
                      <textarea
                        id="out-subnets"
                        rows="2"
                        class="field-mono"
                        placeholder="198.51.100.0/24"
                        bind:value={currShared.outboundShared.allowedSubnetsText}
                        aria-describedby="out-subnets-hint"
                      ></textarea>
                      <span id="out-subnets-hint" class="hint">
                        Comma- or newline-separated CIDRs permitted even when <code>block_private_ips</code> is active.
                      </span>
                    </div>
                  </div>

                  {#if activePerNode}
                    <div class="stack-form">
                      <div class="fieldrow">
                        <label for="out-v6-prefix">ipv6_prefix ({activeNode || 'node'} per-node)</label>
                        <input
                          id="out-v6-prefix"
                          type="text"
                          class="field-mono"
                          placeholder="2001:db8:1::/48"
                          bind:value={activePerNode.ipv6_prefix}
                        />
                      </div>
                      <div class="fieldrow">
                        <label for="out-v6-iface">ipv6_interface ({activeNode || 'node'} per-node)</label>
                        <input
                          id="out-v6-iface"
                          type="text"
                          class="field-mono"
                          placeholder="eth0"
                          bind:value={activePerNode.ipv6_interface}
                        />
                      </div>
                      <div class="fieldrow">
                        <label for="out-v6-piface">ipv6_prefix_interface ({activeNode || 'node'} per-node)</label>
                        <input
                          id="out-v6-piface"
                          type="text"
                          class="field-mono"
                          placeholder="eth0"
                          bind:value={activePerNode.ipv6_prefix_interface}
                        />
                      </div>
                    </div>
                  {/if}
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Tab 3: Resumption & Camouflage -->
        <div
          role="tabpanel"
          aria-labelledby="settings-tab-camouflage"
          hidden={activeTab === 'camouflage' ? undefined : ('until-found' as unknown as boolean)}
          tabindex={activeTab === 'camouflage' ? 0 : undefined}
          onbeforematch={() => (activeTab = 'camouflage')}
        >
          <div class="tabpanel-inner">
            <div class="settings-two-col">
              <!-- Session Resumption -->
              <div class="panel panel-form panel-pad">
                <div class="section-head-row">
                  <h3>[session_resumption] Session Resumption</h3>
                  {#if isCluster}
                    <DriftBadge
                      fieldKey="session_resumption"
                      {drift}
                      nodes={clusterNodes}
                      extractValue={(c) => c.session_resumption}
                      onAlign={(v) => {
                        const sr = sharedFromConfig({
                          ...EMPTY_CFG,
                          session_resumption: v as ServerConfigResponse['session_resumption'],
                        }).sessionResumption;
                        currShared.sessionResumption = sr;
                      }}
                    />
                  {/if}
                </div>
                <div class="stack-form">
                  <label class="switch">
                    <input type="checkbox" bind:checked={currShared.sessionResumption.enabled} />
                    <span>Enable cross-carrier session resumption</span>
                  </label>
                  <div class="form-grid-2">
                    <div class="fieldrow">
                      <label for="sr-ttl-tcp">orphan_ttl_tcp_secs</label>
                      <input
                        id="sr-ttl-tcp"
                        type="number"
                        min="1"
                        class="field-mono"
                        value={currShared.sessionResumption.orphan_ttl_tcp_secs ?? ''}
                        oninput={(e) =>
                          (currShared.sessionResumption.orphan_ttl_tcp_secs = optInt(e.currentTarget.value))}
                      />
                    </div>
                    <div class="fieldrow">
                      <label for="sr-ttl-udp">orphan_ttl_udp_secs</label>
                      <input
                        id="sr-ttl-udp"
                        type="number"
                        min="1"
                        class="field-mono"
                        value={currShared.sessionResumption.orphan_ttl_udp_secs ?? ''}
                        oninput={(e) =>
                          (currShared.sessionResumption.orphan_ttl_udp_secs = optInt(e.currentTarget.value))}
                      />
                    </div>
                  </div>
                  <div class="form-grid-2">
                    <div class="fieldrow">
                      <label for="sr-user-cap">orphan_per_user_cap</label>
                      <input
                        id="sr-user-cap"
                        type="number"
                        min="0"
                        class="field-mono"
                        value={currShared.sessionResumption.orphan_per_user_cap ?? ''}
                        oninput={(e) =>
                          (currShared.sessionResumption.orphan_per_user_cap = optInt(e.currentTarget.value))}
                      />
                    </div>
                    <div class="fieldrow">
                      <label for="sr-global-cap">orphan_global_cap</label>
                      <input
                        id="sr-global-cap"
                        type="number"
                        min="0"
                        class="field-mono"
                        value={currShared.sessionResumption.orphan_global_cap ?? ''}
                        oninput={(e) =>
                          (currShared.sessionResumption.orphan_global_cap = optInt(e.currentTarget.value))}
                      />
                    </div>
                  </div>
                  <div class="fieldrow">
                    <label for="sr-downlink">downlink_buffer_bytes</label>
                    <input
                      id="sr-downlink"
                      type="number"
                      min="1024"
                      class="field-mono"
                      value={currShared.sessionResumption.downlink_buffer_bytes ?? ''}
                      aria-describedby="sr-downlink-hint"
                      oninput={(e) =>
                        (currShared.sessionResumption.downlink_buffer_bytes = optInt(e.currentTarget.value))}
                    />
                    <span id="sr-downlink-hint" class="hint">
                      Per-session orphan buffer in bytes{' '}{#if currShared.sessionResumption.downlink_buffer_bytes != null}({Math.round(currShared.sessionResumption.downlink_buffer_bytes / 1024)} KiB){/if}.
                    </span>
                  </div>
                </div>
              </div>

              <!-- Padding (all 11 fields) -->
              <div class="panel panel-form panel-pad">
                <div class="section-head-row">
                  <h3>[padding] Traffic Padding &amp; Throttle Guard</h3>
                  {#if isCluster}
                    <DriftBadge
                      fieldKey="padding"
                      {drift}
                      nodes={clusterNodes}
                      extractValue={(c) => c.padding}
                      onAlign={(v) => {
                        currShared.padding = sharedFromConfig({
                          ...EMPTY_CFG,
                          padding: v as ServerConfigResponse['padding'],
                        }).padding;
                      }}
                    />
                  {/if}
                </div>
                <div class="stack-form">
                  <label class="switch">
                    <input type="checkbox" bind:checked={currShared.padding.cover} />
                    <span>Enable periodic cover traffic (<code>cover</code>)</span>
                  </label>
                  <div class="form-grid-2">
                    <div class="fieldrow">
                      <label for="pad-min">min_bytes</label>
                      <input
                        id="pad-min"
                        type="number"
                        min="0"
                        class="field-mono"
                        value={currShared.padding.min_bytes ?? ''}
                        oninput={(e) => (currShared.padding.min_bytes = optInt(e.currentTarget.value))}
                        onblur={() => onFieldBlur('padding.max_bytes', 'Padding min/max bytes')}
                      />
                    </div>
                    <div class="fieldrow">
                      <label for="pad-max">max_bytes</label>
                      <input
                        id="pad-max"
                        data-val-key="padding.max_bytes"
                        type="number"
                        min="0"
                        class="field-mono"
                        value={currShared.padding.max_bytes ?? ''}
                        aria-invalid={padBytesErr ? 'true' : 'false'}
                        aria-describedby={describedBy(padBytesErr ? 'pad-bytes-err' : null)}
                        oninput={(e) => (currShared.padding.max_bytes = optInt(e.currentTarget.value))}
                        onblur={() => onFieldBlur('padding.max_bytes', 'Padding max_bytes')}
                      />
                    </div>
                  </div>
                  {#if padBytesErr}
                    <div id="pad-bytes-err" class="field-error">
                      <span class="err-prefix" aria-hidden="true">Error:</span> {padBytesErr}
                    </div>
                  {/if}

                  <div class="form-grid-2">
                    <div class="fieldrow">
                      <label for="pad-jmin">cover_jitter_min_ms</label>
                      <input
                        id="pad-jmin"
                        type="number"
                        min="0"
                        class="field-mono"
                        value={currShared.padding.cover_jitter_min_ms ?? ''}
                        oninput={(e) =>
                          (currShared.padding.cover_jitter_min_ms = optInt(e.currentTarget.value))}
                        onblur={() => onFieldBlur('padding.jitter_max', 'Padding jitter min/max')}
                      />
                    </div>
                    <div class="fieldrow">
                      <label for="pad-jmax">cover_jitter_max_ms</label>
                      <input
                        id="pad-jmax"
                        data-val-key="padding.jitter_max"
                        type="number"
                        min="0"
                        class="field-mono"
                        value={currShared.padding.cover_jitter_max_ms ?? ''}
                        aria-invalid={padJitterErr ? 'true' : 'false'}
                        aria-describedby={describedBy(padJitterErr ? 'pad-jitter-err' : null)}
                        oninput={(e) =>
                          (currShared.padding.cover_jitter_max_ms = optInt(e.currentTarget.value))}
                        onblur={() => onFieldBlur('padding.jitter_max', 'Padding cover_jitter_max_ms')}
                      />
                    </div>
                  </div>
                  {#if padJitterErr}
                    <div id="pad-jitter-err" class="field-error">
                      <span class="err-prefix" aria-hidden="true">Error:</span> {padJitterErr}
                    </div>
                  {/if}

                  <div class="form-divider"></div>

                  <label class="switch">
                    <input type="checkbox" bind:checked={currShared.padding.throttle_detect_enabled} />
                    <span>Detect provider throttling (<code>throttle_detect_enabled</code>)</span>
                  </label>

                  <div class="form-grid-2">
                    <div class="fieldrow">
                      <label for="pad-tratio">throttle_ratio_percent</label>
                      <input
                        id="pad-tratio"
                        type="number"
                        min="1"
                        max="100"
                        class="field-mono"
                        value={currShared.padding.throttle_ratio_percent ?? ''}
                        oninput={(e) =>
                          (currShared.padding.throttle_ratio_percent = optInt(e.currentTarget.value))}
                      />
                    </div>
                    <div class="fieldrow">
                      <label for="pad-twindow">throttle_window_secs</label>
                      <input
                        id="pad-twindow"
                        type="number"
                        min="1"
                        class="field-mono"
                        value={currShared.padding.throttle_window_secs ?? ''}
                        oninput={(e) =>
                          (currShared.padding.throttle_window_secs = optInt(e.currentTarget.value))}
                      />
                    </div>
                  </div>
                  <div class="form-grid-2">
                    <div class="fieldrow">
                      <label for="pad-tsustain">throttle_sustain_windows</label>
                      <input
                        id="pad-tsustain"
                        type="number"
                        min="1"
                        class="field-mono"
                        value={currShared.padding.throttle_sustain_windows ?? ''}
                        oninput={(e) =>
                          (currShared.padding.throttle_sustain_windows = optInt(e.currentTarget.value))}
                      />
                    </div>
                    <div class="fieldrow">
                      <label for="pad-tminbps">throttle_min_bytes_per_sec</label>
                      <input
                        id="pad-tminbps"
                        type="number"
                        min="0"
                        class="field-mono"
                        value={currShared.padding.throttle_min_bytes_per_sec ?? ''}
                        oninput={(e) =>
                          (currShared.padding.throttle_min_bytes_per_sec = optInt(e.currentTarget.value))}
                      />
                    </div>
                  </div>
                  <div class="fieldrow">
                    <label for="pad-tcooldown">throttle_signal_cooldown_secs</label>
                    <input
                      id="pad-tcooldown"
                      type="number"
                      min="0"
                      class="field-mono"
                      value={currShared.padding.throttle_signal_cooldown_secs ?? ''}
                      oninput={(e) =>
                        (currShared.padding.throttle_signal_cooldown_secs = optInt(e.currentTarget.value))}
                    />
                  </div>
                </div>
              </div>

              <!-- HTTP Fallback -->
              <div class="panel panel-form panel-pad">
                <div class="section-head-row">
                  <h3>[http_fallback] Reverse Proxy Fallback</h3>
                  {#if isCluster}
                    <DriftBadge
                      fieldKey="http_fallback"
                      {drift}
                      nodes={clusterNodes}
                      extractValue={(c) => c.http_fallback}
                      onAlign={(v) => {
                        currShared.httpFallback = sharedFromConfig({
                          ...EMPTY_CFG,
                          http_fallback: v as ServerConfigResponse['http_fallback'],
                        }).httpFallback;
                      }}
                    />
                  {/if}
                </div>
                <div class="stack-form">
                  <div class="fieldrow">
                    <label for="hf-backend">Backend URL</label>
                    <input
                      id="hf-backend"
                      data-val-key="http_fallback.backend"
                      type="text"
                      class="field-mono"
                      placeholder="http://127.0.0.1:8080"
                      bind:value={currShared.httpFallback.backend}
                      aria-invalid={hfErr ? 'true' : 'false'}
                      aria-describedby={describedBy('hf-backend-hint', hfErr ? 'hf-backend-err' : null)}
                      onblur={() => onFieldBlur('http_fallback.backend', 'HTTP fallback backend')}
                    />
                    <span id="hf-backend-hint" class="hint">
                      Plain HTTP upstream (e.g. <code>http://127.0.0.1:8080</code>). Leave blank to disable HTTP fallback.
                    </span>
                    {#if hfErr}
                      <div id="hf-backend-err" class="field-error">
                        <span class="err-prefix" aria-hidden="true">Error:</span> {hfErr}
                      </div>
                    {/if}
                  </div>
                  <div class="form-grid-3">
                    <div class="fieldrow">
                      <label for="hf-proto">backend_proto</label>
                      <select id="hf-proto" bind:value={currShared.httpFallback.backend_proto}>
                        <option value="">auto</option>
                        <option value="h1">h1</option>
                        <option value="h2">h2</option>
                      </select>
                    </div>
                    <div class="fieldrow">
                      <label for="hf-proxy">proxy_protocol</label>
                      <select id="hf-proxy" bind:value={currShared.httpFallback.proxy_protocol}>
                        <option value="">none</option>
                        <option value="v1">v1</option>
                        <option value="v2">v2</option>
                      </select>
                    </div>
                    <div class="fieldrow">
                      <label for="hf-timeout">request_timeout_secs</label>
                      <input
                        id="hf-timeout"
                        type="number"
                        min="1"
                        class="field-mono"
                        value={currShared.httpFallback.request_timeout_secs ?? ''}
                        oninput={(e) =>
                          (currShared.httpFallback.request_timeout_secs = optInt(e.currentTarget.value))}
                      />
                    </div>
                  </div>
                  <div class="form-divider"></div>
                  <label class="switch">
                    <input type="checkbox" bind:checked={currShared.httpFallback.apply_to_h1} />
                    <span>Apply to HTTP/1.1 &amp; HTTP/2 (<code>apply_to_h1</code>)</span>
                  </label>
                  <label class="switch">
                    <input type="checkbox" bind:checked={currShared.httpFallback.apply_to_h3} />
                    <span>Apply to HTTP/3 (<code>apply_to_h3</code>)</span>
                  </label>
                  <label class="switch">
                    <input type="checkbox" bind:checked={currShared.httpFallback.add_x_forwarded_for} />
                    <span>Add X-Forwarded-For</span>
                  </label>
                  <label class="switch">
                    <input type="checkbox" bind:checked={currShared.httpFallback.add_x_forwarded_proto} />
                    <span>Add X-Forwarded-Proto</span>
                  </label>
                  <label class="switch">
                    <input type="checkbox" bind:checked={currShared.httpFallback.add_x_forwarded_host} />
                    <span>Add X-Forwarded-Host</span>
                  </label>
                </div>
              </div>

              <!-- SNI Fallback -->
              <div class="panel panel-form panel-pad">
                <div class="section-head-row">
                  <h3>[sni_fallback] TLS Passthrough</h3>
                  {#if isCluster}
                    <DriftBadge
                      fieldKey="sni_fallback"
                      {drift}
                      nodes={clusterNodes}
                      extractValue={(c) => c.sni_fallback}
                      onAlign={(v) => {
                        currShared.sniFallback = sharedFromConfig({
                          ...EMPTY_CFG,
                          sni_fallback: v as ServerConfigResponse['sni_fallback'],
                        }).sniFallback;
                      }}
                    />
                  {/if}
                  <span class="spacer"></span>
                  <button type="button" class="btn ghost sm" onclick={addSniBackend}>
                    + Add SNI backend
                  </button>
                </div>
                <div class="stack-form">
                  <div class="fieldrow">
                    <label for="sni-match">match_sni patterns (comma/newline-separated)</label>
                    <textarea
                      id="sni-match"
                      data-val-key="sni_fallback.match_sni"
                      rows="2"
                      class="field-mono"
                      placeholder="decoy.fleet.example"
                      bind:value={currShared.sniFallback.matchSniText}
                      aria-invalid={sniMatchErr ? 'true' : 'false'}
                      aria-describedby={describedBy('sni-match-hint', sniMatchErr ? 'sni-match-err' : null)}
                      onblur={() => onFieldBlur('sni_fallback.match_sni', 'SNI fallback match_sni')}
                    ></textarea>
                    <span id="sni-match-hint" class="hint">
                      SNI hostnames or patterns intercepted before local TLS termination. Clear both lists to disable SNI fallback.
                    </span>
                    {#if sniMatchErr}
                      <div id="sni-match-err" class="field-error">
                        <span class="err-prefix" aria-hidden="true">Error:</span> {sniMatchErr}
                      </div>
                    {/if}
                  </div>
                  <label class="switch">
                    <input type="checkbox" bind:checked={currShared.sniFallback.allow_no_sni} />
                    <span>Allow TLS connections without SNI (<code>allow_no_sni</code>)</span>
                  </label>
                  <div class="fieldrow">
                    <label for="sni-hello-bytes">max_client_hello_bytes (&gt;= 256)</label>
                    <input
                      id="sni-hello-bytes"
                      data-val-key="sni_fallback.max_hello"
                      type="number"
                      min="256"
                      class="field-mono"
                      value={currShared.sniFallback.max_client_hello_bytes ?? ''}
                      aria-invalid={sniHelloErr ? 'true' : 'false'}
                      aria-describedby={describedBy(sniHelloErr ? 'sni-hello-err' : null)}
                      oninput={(e) =>
                        (currShared.sniFallback.max_client_hello_bytes = optInt(e.currentTarget.value))}
                      onblur={() => onFieldBlur('sni_fallback.max_hello', 'max_client_hello_bytes')}
                    />
                    {#if sniHelloErr}
                      <div id="sni-hello-err" class="field-error">
                        <span class="err-prefix" aria-hidden="true">Error:</span> {sniHelloErr}
                      </div>
                    {/if}
                  </div>

                  {#each currShared.sniFallback.backends as b, idx (idx)}
                    {@const sbKey = `sni_fallback.backend:${idx}`}
                    {@const sbErr = fieldError(sbKey)}
                    <div class="subcard">
                      <div class="stack-form">
                        <div class="form-grid-2-1">
                          <div class="fieldrow">
                            <label for={`sni-b-addr-${idx}`}>Backend host:port</label>
                            <input
                              id={`sni-b-addr-${idx}`}
                              data-val-key={sbKey}
                              type="text"
                              class="field-mono"
                              placeholder="127.0.0.1:8443"
                              bind:value={b.backend}
                              aria-invalid={sbErr ? 'true' : 'false'}
                              aria-describedby={describedBy(sbErr ? `sni-b-err-${idx}` : null)}
                              onblur={() => onFieldBlur(sbKey, `SNI backend #${idx + 1}`)}
                            />
                          </div>
                          <div class="fieldrow">
                            <label for={`sni-b-pp-${idx}`}>proxy_protocol</label>
                            <select id={`sni-b-pp-${idx}`} bind:value={b.proxy_protocol}>
                              <option value="">none</option>
                              <option value="v1">v1</option>
                              <option value="v2">v2</option>
                            </select>
                          </div>
                        </div>
                        <div class="fieldrow">
                          <label for={`sni-b-match-${idx}`}>match_sni (optional for last catch-all backend)</label>
                          <input
                            id={`sni-b-match-${idx}`}
                            type="text"
                            class="field-mono"
                            placeholder="decoy.fleet.example"
                            bind:value={b.matchSniText}
                            onblur={() => onFieldBlur(sbKey, `SNI backend #${idx + 1} match_sni`)}
                          />
                        </div>
                        {#if sbErr}
                          <div id={`sni-b-err-${idx}`} class="field-error">
                            <span class="err-prefix" aria-hidden="true">Error:</span> {sbErr}
                          </div>
                        {/if}
                        <div class="subcard-foot">
                          <span class="spacer"></span>
                          <button
                            type="button"
                            class="btn danger sm"
                            onclick={() => removeSniBackend(idx)}
                          >
                            Remove
                          </button>
                        </div>
                      </div>
                    </div>
                  {/each}
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Tab 4: Subscriptions -->
        <div
          role="tabpanel"
          aria-labelledby="settings-tab-subscriptions"
          hidden={activeTab === 'subscriptions' ? undefined : ('until-found' as unknown as boolean)}
          tabindex={activeTab === 'subscriptions' ? 0 : undefined}
          onbeforematch={() => (activeTab = 'subscriptions')}
        >
          <div class="tabpanel-inner">
            <div class="panel panel-form panel-pad">
              <div class="section-head-row">
                <h3>[access_keys] Subscription Generation &amp; Links</h3>
                {#if isCluster}
                  <DriftBadge
                    fieldKey="access_keys.nodes"
                    label="nodes drift"
                    {drift}
                    nodes={clusterNodes}
                    extractValue={(c) => c.access_keys?.nodes ?? []}
                    onAlign={(v) => {
                      currShared.accessKeys.nodesText = Array.isArray(v) ? v.map(String).join('\n') : '';
                    }}
                  />
                {/if}
                <span class="spacer"></span>
                {#if !isCluster}
                  <button
                    type="button"
                    class="btn sm"
                    disabled={regenerating || !singleRes?.control?.access_keys_enabled}
                    onclick={regenerateNow}
                    title={singleRes?.control?.access_keys_enabled
                      ? 'Run generator with --prune now'
                      : 'Configure [control].access_keys_generator first'}
                  >
                    {regenerating ? 'Regenerating…' : 'Regenerate subscriptions'}
                  </button>
                {/if}
              </div>
              <p class="panel-head-desc">
                Changes inside <code>[access_keys]</code> apply immediately without restarting <code>outline-server</code>. Always regenerate subscriptions afterward to publish updated links and prune removed users.
              </p>

              <div class="settings-two-col">
                <div class="stack-form">
                  <div class="fieldrow">
                    <div class="field-head">
                      <label for="ak-public-host">public_host</label>
                      {#if isCluster}
                        <DriftBadge
                          fieldKey="access_keys.public_host"
                          {drift}
                          nodes={clusterNodes}
                          extractValue={(c) => c.access_keys?.public_host ?? ''}
                          onAlign={(v) => (currShared.accessKeys.public_host = String(v ?? ''))}
                        />
                      {/if}
                    </div>
                    <input
                      id="ak-public-host"
                      type="text"
                      class="field-mono"
                      placeholder="edge.fleet.example"
                      bind:value={currShared.accessKeys.public_host}
                      aria-describedby="ak-public-host-hint"
                    />
                    <span id="ak-public-host-hint" class="hint">
                      Public domain or address clients connect to for single-node links.
                    </span>
                  </div>

                  <div class="fieldrow">
                    <div class="field-head">
                      <label for="ak-public-scheme">public_scheme</label>
                      {#if isCluster}
                        <DriftBadge
                          fieldKey="access_keys.public_scheme"
                          {drift}
                          nodes={clusterNodes}
                          extractValue={(c) => c.access_keys?.public_scheme ?? ''}
                          onAlign={(v) => {
                            const s = String(v ?? '');
                            currShared.accessKeys.public_scheme = s === 'ws' || s === 'wss' ? s : '';
                          }}
                        />
                      {/if}
                    </div>
                    <select
                      id="ak-public-scheme"
                      data-val-key="access_keys.public_scheme"
                      class="field-mono"
                      bind:value={currShared.accessKeys.public_scheme}
                      aria-invalid={schemeErr ? 'true' : 'false'}
                      aria-describedby={describedBy(schemeErr ? 'ak-scheme-err' : null)}
                      onblur={() => onFieldBlur('access_keys.public_scheme', 'public_scheme')}
                    >
                      <option value="">auto (infer from TLS config)</option>
                      <option value="wss">wss</option>
                      <option value="ws">ws</option>
                    </select>
                    {#if schemeErr}
                      <div id="ak-scheme-err" class="field-error">
                        <span class="err-prefix" aria-hidden="true">Error:</span> {schemeErr}
                      </div>
                    {/if}
                  </div>

                  <div class="fieldrow">
                    <div class="field-head">
                      <label for="ak-url-base">url_base</label>
                      {#if isCluster}
                        <DriftBadge
                          fieldKey="access_keys.url_base"
                          {drift}
                          nodes={clusterNodes}
                          extractValue={(c) => c.access_keys?.url_base ?? ''}
                          onAlign={(v) => (currShared.accessKeys.url_base = String(v ?? ''))}
                        />
                      {/if}
                    </div>
                    <input
                      id="ak-url-base"
                      type="text"
                      class="field-mono"
                      placeholder="https://sub.fleet.example/keys"
                      bind:value={currShared.accessKeys.url_base}
                      aria-describedby="ak-url-base-hint"
                    />
                    <span id="ak-url-base-hint" class="hint">
                      Base HTTP URL serving generated subscription artifacts (for <code>ssconf://</code> / <code>wsconf://</code> / <code>happ://</code> links).
                    </span>
                  </div>

                  <div class="fieldrow">
                    <div class="field-head">
                      <label for="ak-file-ext">file_extension</label>
                      {#if isCluster}
                        <DriftBadge
                          fieldKey="access_keys.file_extension"
                          {drift}
                          nodes={clusterNodes}
                          extractValue={(c) => c.access_keys?.file_extension ?? ''}
                          onAlign={(v) => (currShared.accessKeys.file_extension = String(v ?? ''))}
                        />
                      {/if}
                    </div>
                    <input
                      id="ak-file-ext"
                      type="text"
                      class="field-mono"
                      placeholder=".txt or leave blank"
                      bind:value={currShared.accessKeys.file_extension}
                    />
                  </div>
                </div>

                <div class="stack-form">
                  <div class="fieldrow">
                    <label for="ak-write-dir">write_dir (filesystem output directory)</label>
                    <div class="secret-row">
                      <input
                        id="ak-write-dir"
                        type={showWriteDir ? 'text' : 'password'}
                        class="field-mono"
                        placeholder="<keys-dir>"
                        bind:value={currShared.accessKeys.write_dir}
                        aria-describedby="ak-write-dir-hint"
                      />
                      <button
                        type="button"
                        class="btn ghost sm"
                        onclick={() => (showWriteDir = !showWriteDir)}
                      >
                        {showWriteDir ? 'Hide' : 'Show'}
                      </button>
                    </div>
                    <span id="ak-write-dir-hint" class="hint">
                      Server-side directory where subscription artifacts are written. Hidden by default.
                    </span>
                  </div>

                  <div class="fieldrow">
                    <div class="field-head">
                      <label for="ak-nodes">nodes (subscription uplink/balancer hosts)</label>
                      {#if isCluster && clusterSummary?.subscription_nodes.length}
                        <button
                          type="button"
                          class="btn ghost sm"
                          onclick={fillNodesFromCluster}
                        >
                          Fill from cluster subscription_nodes
                        </button>
                      {/if}
                    </div>
                    <textarea
                      id="ak-nodes"
                      data-val-key="access_keys.nodes"
                      rows="5"
                      class="field-mono"
                      placeholder={"exit-a.fleet.example\nexit-b.fleet.example"}
                      bind:value={currShared.accessKeys.nodesText}
                      aria-invalid={nodesErr ? 'true' : 'false'}
                      aria-describedby={describedBy('ak-nodes-hint', nodesErr ? 'ak-nodes-err' : null)}
                      onblur={() => onFieldBlur('access_keys.nodes', 'Subscription nodes')}
                    ></textarea>
                    <span id="ak-nodes-hint" class="hint">
                      One host per line (or comma-separated). Empty = single-server subscription without balancer group; &gt;=1 host = multi-node subscription with active/fallback balancer.
                    </span>
                    {#if nodesErr}
                      <div id="ak-nodes-err" class="field-error">
                        <span class="err-prefix" aria-hidden="true">Error:</span> {nodesErr}
                      </div>
                    {/if}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Tab 5: Tuning & System -->
        <div
          role="tabpanel"
          aria-labelledby="settings-tab-tuning"
          hidden={activeTab === 'tuning' ? undefined : ('until-found' as unknown as boolean)}
          tabindex={activeTab === 'tuning' ? 0 : undefined}
          onbeforematch={() => (activeTab = 'tuning')}
        >
          <div class="tabpanel-inner">
            <div class="stack-form">
              <div class="panel panel-form panel-pad">
                <div class="section-head-row">
                  <h3>tuning_profile &amp; [tuning] Overrides</h3>
                  {#if isCluster}
                    <DriftBadge
                      fieldKey="tuning_profile"
                      label="profile drift"
                      {drift}
                      nodes={clusterNodes}
                      extractValue={(c) => c.tuning_profile ?? 'large'}
                      onAlign={(v) => {
                        const tp = String(v ?? 'large');
                        currShared.tuningProfile =
                          tp === 'small' || tp === 'medium' || tp === 'large' ? tp : 'large';
                      }}
                    />
                    <DriftBadge
                      fieldKey="tuning"
                      label="overrides drift"
                      {drift}
                      nodes={clusterNodes}
                      extractValue={(c) => c.tuning ?? null}
                      onAlign={(v) => {
                        currShared.tuningOverrides = sharedFromConfig({
                          ...EMPTY_CFG,
                          tuning: v as ServerConfigResponse['tuning'],
                        }).tuningOverrides;
                      }}
                    />
                  {/if}
                </div>

                <div class="fieldrow tuning-preset-row">
                  <label for="tuning-profile-select">tuning_profile (VPS sizing preset)</label>
                  <select
                    id="tuning-profile-select"
                    class="field-mono"
                    bind:value={currShared.tuningProfile}
                    aria-describedby="tuning-profile-hint"
                  >
                    <option value="small">small (1 vCPU / &le;1 GB RAM)</option>
                    <option value="medium">medium (2 vCPU / 2–4 GB RAM)</option>
                    <option value="large">large (4+ vCPU / 8+ GB RAM)</option>
                  </select>
                  <span id="tuning-profile-hint" class="hint">
                    Selects baseline buffer sizes and connection table caps (<code>small</code>, <code>medium</code>, or <code>large</code>). Empty override fields below inherit this preset.
                  </span>
                </div>

                <!-- Do not put headings inside <summary> per accordion accessibility guidance -->
                <details class="tuning-details">
                  <summary>
                    Advanced [tuning] overrides (23 parameters · effective defaults shown as placeholders)
                  </summary>
                  <div class="tuning-details-body">
                    <div class="section-head-row" style="margin-bottom: var(--sp-3);">
                      <span class="hint">
                        Leave a field blank to clear its explicit override and inherit the <code>{currShared.tuningProfile}</code> preset value.
                      </span>
                      <span class="spacer"></span>
                      <button
                        type="button"
                        class="btn ghost sm"
                        onclick={clearAllTuningOverrides}
                      >
                        Clear all overrides
                      </button>
                    </div>
                    <div class="tuning-grid">
                      {#each TUNING_FIELD_SPECS as spec (spec.key)}
                        {@const presetDefault = TUNING_PRESETS[currShared.tuningProfile as TuningPresetName][spec.key]}
                        <div class="fieldrow">
                          <label for={`tuning-${spec.key}`}>{spec.label}</label>
                          <input
                            id={`tuning-${spec.key}`}
                            type="number"
                            min={spec.zeroOptOut ? '0' : '1'}
                            class="field-mono"
                            placeholder={String(presetDefault)}
                            value={currShared.tuningOverrides[spec.key] ?? ''}
                            aria-describedby={`tuning-hint-${spec.key}`}
                            oninput={(e) =>
                              (currShared.tuningOverrides[spec.key] = optInt(e.currentTarget.value))}
                          />
                          {#if spec.zeroOptOut}
                            <span id={`tuning-hint-${spec.key}`} class="hint"><code>0</code> disables limit; blank = preset ({presetDefault}).</span>
                          {:else}
                            <span id={`tuning-hint-${spec.key}`} class="hint">Preset default: <code>{presetDefault}</code>.</span>
                          {/if}
                        </div>
                      {/each}
                    </div>
                  </div>
                </details>
              </div>

              <!-- Read-only System Status -->
              <div class="panel">
                <div class="panel-pad panel-table-head">
                  <h3>System, Control &amp; Metrics (Read-Only)</h3>
                </div>
                <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
                <div
                  tabindex="0"
                  role="region"
                  aria-label="Read-only server control and metrics status"
                  class="table-wrapper"
                >
                  <table>
                    <thead>
                      <tr>
                        <th>Node</th>
                        <th>Config path</th>
                        <th>Control listen</th>
                        <th>Generator</th>
                        <th>Metrics</th>
                        <th>Restart</th>
                      </tr>
                    </thead>
                    <tbody>
                      {#if isCluster}
                        {#each clusterNodes as n (n.instance)}
                          <tr>
                            <td class="mono">{n.instance}</td>
                            {#if n.ok && n.config}
                              <td class="mono muted">{n.config.config_path ?? '—'}</td>
                              <td class="mono">{n.config.control?.listen ?? '—'}</td>
                              <td>
                                {#if n.config.control?.access_keys_enabled}
                                  <span class="chip ok">enabled</span>
                                {:else}
                                  <span class="chip off">disabled</span>
                                {/if}
                              </td>
                              <td class="mono">
                                {n.config.metrics?.listen ?? '—'}{n.config.metrics?.path ?? ''}
                              </td>
                              <td>
                                {#if n.config.restart_pending}
                                  <span class="chip warn">pending</span>
                                {:else}
                                  <span class="chip ok">clean</span>
                                {/if}
                              </td>
                            {:else}
                              <td colspan="5" class="muted">Offline ({n.error ?? `HTTP ${n.status}`})</td>
                            {/if}
                          </tr>
                        {/each}
                      {:else if singleRes && target}
                        <tr>
                          <td class="mono">{target.name}</td>
                          <td class="mono muted">{singleRes.config_path ?? '—'}</td>
                          <td class="mono">{singleRes.control?.listen ?? '—'}</td>
                          <td>
                            {#if singleRes.control?.access_keys_enabled}
                              <span class="chip ok">enabled</span>
                            {:else}
                              <span class="chip off">disabled</span>
                            {/if}
                          </td>
                          <td class="mono">
                            {singleRes.metrics?.listen ?? '—'}{singleRes.metrics?.path ?? ''}
                          </td>
                          <td>
                            {#if singleRes.restart_pending}
                              <span class="chip warn">pending</span>
                            {:else}
                              <span class="chip ok">clean</span>
                            {/if}
                          </td>
                        </tr>
                      {/if}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {#if formDirty}
        <div class="sticky-savebar" role="region" aria-label="Unsaved settings bar">
          <span class="chip warn">
            Unsaved changes ({dirtySectionLabels.length}):
            <span class="mono">{dirtySectionLabels.join(', ')}</span>
          </span>
          <span class="spacer"></span>
          <button type="button" class="btn ghost sm" disabled={mutating} onclick={discardChanges}>
            Discard
          </button>
          <button type="button" class="btn primary sm" disabled={mutating} onclick={save}>
            {#if mutating}
              Saving…
            {:else if isCluster}
              Save to cluster ({aliveClusterNodes.length} nodes)
            {:else}
              Save changes
            {/if}
          </button>
        </div>
      {/if}
    {/if}
  {/if}

  <ConfirmDialog
    open={confirmSwitchOpen}
    title="Discard unsaved settings?"
    message={`You have unsaved changes in ${dirtySectionLabels.join(', ')}. Switch target and discard them?`}
    confirmLabel="Discard and switch"
    cancelLabel="Stay here"
    danger={true}
    onconfirm={confirmDiscardTargetSwitch}
    oncancel={() => (pendingTarget = null)}
  />
</section>
