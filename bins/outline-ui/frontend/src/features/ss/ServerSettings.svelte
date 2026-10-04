<script lang="ts">
  import { onDestroy } from 'svelte';
  import { getServerConfig, patchServerConfig } from '../../lib/api';
  import { createPoll } from '../../lib/poll.svelte';
  import { toast } from '../../lib/toast.svelte';
  import type {
    ServerConfigResponse,
    ServerListenersConfig,
    SessionResumptionConfig,
    OutboundConfig,
    ServerPaddingConfig,
    ServerHttpFallbackConfig,
    ServerSniFallbackConfig,
    EndpointConfigItem,
  } from '../../lib/types';
  import InstanceSelector from '../../components/layout/InstanceSelector.svelte';
  import ErrorBanner from '../../components/layout/ErrorBanner.svelte';

  let instance = $state('');
  let refreshSecs = $state(10);
  const refreshMs = $derived(Math.max(1000, refreshSecs * 1000));

  let mutating = $state(false);
  let formDirty = $state(false);

  // Form states: Listeners
  let listen = $state('');
  let certPath = $state('');
  let keyPath = $state('');
  let h3Listen = $state('');
  let h3CertPath = $state('');
  let h3KeyPath = $state('');
  let h3InitialMtu = $state<number | null>(null);

  // Form states: Session Resumption
  let resumeEnabled = $state(false);
  let orphanTtlTcpSecs = $state(300);
  let orphanTtlUdpSecs = $state(180);
  let orphanPerUserCap = $state(8);
  let orphanGlobalCap = $state(1024);
  let downlinkBufferKib = $state(64);

  // Form states: Outbound
  let outboundPreferIpv4 = $state(false);
  let outboundIpv6Prefix = $state('');
  let outboundIpv6Interface = $state('');
  let outboundIpv6PrefixInterface = $state('');
  let outboundIpv6Sticky = $state(false);
  let outboundIpv6StickyTtl = $state(300);
  let outboundIpv6RefreshSecs = $state<number | null>(null);

  // Form states: Carrier Padding
  let paddingCover = $state(false);
  let paddingMinBytes = $state(0);
  let paddingMaxBytes = $state(0);
  let paddingCoverJitterMinMs = $state(0);
  let paddingCoverJitterMaxMs = $state(0);
  let paddingThrottleDetect = $state(false);

  // Form states: HTTP Camouflage & Fallback
  let fallbackBackend = $state('');
  let fallbackBackendProto = $state<'' | 'h1' | 'h2'>('');
  let fallbackProxyProtocol = $state<'' | 'v1' | 'v2'>('');
  let fallbackTimeoutSecs = $state(15);
  let fallbackApplyH1 = $state(true);
  let fallbackApplyH3 = $state(true);
  let fallbackXFwdFor = $state(true);
  let fallbackXFwdProto = $state(true);
  let fallbackXFwdHost = $state(true);

  // Form states: Tuning profile (small, medium, large)
  let tuningProfile = $state('large');

  // Form states: SNI Fallback & Camouflage
  let sniMatchSni = $state('');
  let sniAllowNoSni = $state(false);
  let sniMaxClientHelloBytes = $state(8192);
  let sniBackends = $state<Array<{ backend: string; proxy_protocol: '' | 'v1' | 'v2'; match_sni: string }>>([]);

  function addSniBackend() {
    sniBackends = [...sniBackends, { backend: '', proxy_protocol: '', match_sni: '' }];
    markDirty();
  }

  function removeSniBackend(index: number) {
    sniBackends = sniBackends.filter((_, i) => i !== index);
    markDirty();
  }

  const configPoll = createPoll<ServerConfigResponse | null>(
    () => (instance ? getServerConfig(instance) : Promise.resolve(null)),
    () => refreshMs,
  );

  $effect(() => {
    void instance;
    formDirty = false;
    configPoll.start();
  });
  onDestroy(() => configPoll.stop());

  const config = $derived(configPoll.data);
  let editableEndpoints = $state<EndpointConfigItem[]>([]);

  // Sync state from server on fetch if clean
  $effect(() => {
    if (config && !formDirty) {
      if (config.server) {
        listen = config.server.listen ?? '';
        certPath = config.server.cert_path ?? '';
        keyPath = config.server.key_path ?? '';
        h3Listen = config.server.h3_listen ?? '';
        h3CertPath = config.server.h3_cert_path ?? '';
        h3KeyPath = config.server.h3_key_path ?? '';
        h3InitialMtu = config.server.h3_initial_mtu ?? null;
      }
      if (config.session_resumption) {
        resumeEnabled = config.session_resumption.enabled;
        orphanTtlTcpSecs = config.session_resumption.orphan_ttl_tcp_secs ?? 300;
        orphanTtlUdpSecs = config.session_resumption.orphan_ttl_udp_secs ?? 180;
        orphanPerUserCap = config.session_resumption.orphan_per_user_cap ?? 8;
        orphanGlobalCap = config.session_resumption.orphan_global_cap ?? 1024;
        const bytes = config.session_resumption.downlink_buffer_bytes ?? 65536;
        downlinkBufferKib = Math.round(bytes / 1024);
      }
      if (config.outbound) {
        outboundPreferIpv4 = config.outbound.prefer_ipv4 ?? false;
        outboundIpv6Prefix = config.outbound.ipv6_prefix ?? '';
        outboundIpv6Interface = config.outbound.ipv6_interface ?? '';
        outboundIpv6PrefixInterface = config.outbound.ipv6_prefix_interface ?? '';
        outboundIpv6Sticky = config.outbound.ipv6_sticky ?? false;
        outboundIpv6StickyTtl = config.outbound.ipv6_sticky_ttl_secs ?? 300;
        outboundIpv6RefreshSecs = config.outbound.ipv6_refresh_secs ?? null;
      }
      if (config.padding) {
        paddingCover = config.padding.cover ?? false;
        paddingMinBytes = config.padding.min_bytes ?? 0;
        paddingMaxBytes = config.padding.max_bytes ?? 0;
        paddingCoverJitterMinMs = config.padding.cover_jitter_min_ms ?? 0;
        paddingCoverJitterMaxMs = config.padding.cover_jitter_max_ms ?? 0;
        paddingThrottleDetect = config.padding.throttle_detect_enabled ?? false;
      }
      if (config.http_fallback) {
        fallbackBackend = config.http_fallback.backend ?? '';
        const proto = config.http_fallback.backend_proto;
        fallbackBackendProto = proto === 'h1' || proto === 'h2' ? proto : '';
        const pp = config.http_fallback.proxy_protocol;
        fallbackProxyProtocol = pp === 'v1' || pp === 'v2' ? pp : '';
        fallbackTimeoutSecs = config.http_fallback.request_timeout_secs ?? 15;
        fallbackApplyH1 = config.http_fallback.apply_to_h1 ?? true;
        fallbackApplyH3 = config.http_fallback.apply_to_h3 ?? true;
        fallbackXFwdFor = config.http_fallback.add_x_forwarded_for ?? true;
        fallbackXFwdProto = config.http_fallback.add_x_forwarded_proto ?? true;
        fallbackXFwdHost = config.http_fallback.add_x_forwarded_host ?? true;
      }
      if (config.sni_fallback) {
        sniMatchSni = (config.sni_fallback.match_sni ?? []).join(', ');
        sniAllowNoSni = config.sni_fallback.allow_no_sni ?? false;
        sniMaxClientHelloBytes = config.sni_fallback.max_client_hello_bytes ?? 8192;
        sniBackends = (config.sni_fallback.backends ?? []).map((b) => ({
          backend: b.backend ?? '',
          proxy_protocol: (b.proxy_protocol === 'v1' || b.proxy_protocol === 'v2') ? b.proxy_protocol : '',
          match_sni: (b.match_sni ?? []).join(', '),
        }));
      } else {
        sniMatchSni = '';
        sniAllowNoSni = false;
        sniMaxClientHelloBytes = 8192;
        sniBackends = [];
      }
      if (config.tuning_profile) {
        tuningProfile = config.tuning_profile;
      }
      editableEndpoints = (config.endpoints ?? []).map((ep) => ({ ...ep }));
    }
  });

  function markDirty() {
    formDirty = true;
  }

  async function save() {
    if (!instance) return;

    if (!listen.trim()) {
      toast('TCP/TLS listen address cannot be empty.', 'error');
      return;
    }

    mutating = true;
    try {
      const serverPatch: Partial<ServerListenersConfig> = {
        listen: listen.trim(),
        cert_path: certPath.trim() ? certPath.trim() : null,
        key_path: keyPath.trim() ? keyPath.trim() : null,
        h3_listen: h3Listen.trim() ? h3Listen.trim() : null,
        h3_cert_path: h3CertPath.trim() ? h3CertPath.trim() : null,
        h3_key_path: h3KeyPath.trim() ? h3KeyPath.trim() : null,
        h3_initial_mtu: h3InitialMtu && h3InitialMtu > 0 ? h3InitialMtu : null,
      };

      const resumePatch: Partial<SessionResumptionConfig> = {
        enabled: resumeEnabled,
        orphan_ttl_tcp_secs: orphanTtlTcpSecs,
        orphan_ttl_udp_secs: orphanTtlUdpSecs,
        orphan_per_user_cap: orphanPerUserCap,
        orphan_global_cap: orphanGlobalCap,
        downlink_buffer_bytes: downlinkBufferKib * 1024,
      };

      const outboundPatch: Partial<OutboundConfig> = {
        prefer_ipv4: outboundPreferIpv4,
        ipv6_prefix: outboundIpv6Prefix.trim() ? outboundIpv6Prefix.trim() : null,
        ipv6_interface: outboundIpv6Interface.trim() ? outboundIpv6Interface.trim() : null,
        ipv6_prefix_interface: outboundIpv6PrefixInterface.trim() ? outboundIpv6PrefixInterface.trim() : null,
        ipv6_sticky: outboundIpv6Sticky,
        ipv6_sticky_ttl_secs: outboundIpv6StickyTtl,
        ipv6_refresh_secs: outboundIpv6RefreshSecs && outboundIpv6RefreshSecs > 0 ? outboundIpv6RefreshSecs : null,
      };

      const paddingPatch: Partial<ServerPaddingConfig> = {
        cover: paddingCover,
        min_bytes: paddingMinBytes,
        max_bytes: paddingMaxBytes,
        cover_jitter_min_ms: paddingCoverJitterMinMs,
        cover_jitter_max_ms: paddingCoverJitterMaxMs,
        throttle_detect_enabled: paddingThrottleDetect,
      };

      const fallbackPatch: Partial<ServerHttpFallbackConfig> = {
        backend: fallbackBackend.trim() ? fallbackBackend.trim() : null,
        backend_proto: fallbackBackendProto || null,
        proxy_protocol: fallbackProxyProtocol || null,
        request_timeout_secs: fallbackTimeoutSecs,
        apply_to_h1: fallbackApplyH1,
        apply_to_h3: fallbackApplyH3,
        add_x_forwarded_for: fallbackXFwdFor,
        add_x_forwarded_proto: fallbackXFwdProto,
        add_x_forwarded_host: fallbackXFwdHost,
      };

      let sniPatch: ServerSniFallbackConfig | null = null;
      const parsedMatchSni = sniMatchSni
        .split(/[,\n]/)
        .map((s) => s.trim())
        .filter((s) => s.length > 0);

      const parsedBackends = sniBackends
        .filter((b) => b.backend.trim().length > 0)
        .map((b) => {
          const bMatchSni = b.match_sni
            .split(/[,\n]/)
            .map((s) => s.trim())
            .filter((s) => s.length > 0);
          return {
            backend: b.backend.trim(),
            proxy_protocol: b.proxy_protocol || null,
            match_sni: bMatchSni.length > 0 ? bMatchSni : null,
          };
        });

      if (parsedMatchSni.length > 0 || parsedBackends.length > 0) {
        sniPatch = {
          match_sni: parsedMatchSni.length > 0 ? parsedMatchSni : null,
          allow_no_sni: sniAllowNoSni,
          max_client_hello_bytes: sniMaxClientHelloBytes > 0 ? sniMaxClientHelloBytes : null,
          backends: parsedBackends.length > 0 ? parsedBackends : null,
        };
      }

      const res = await patchServerConfig(instance, {
        server: serverPatch,
        session_resumption: resumePatch,
        outbound: outboundPatch,
        padding: paddingPatch,
        http_fallback: fallbackPatch,
        sni_fallback: sniPatch,
        tuning_profile: tuningProfile.trim() ? tuningProfile.trim() : null,
        endpoints: editableEndpoints.map((ep) => ({
          path: ep.path,
          padded: ep.padded,
        })),
      });

      formDirty = false;
      if (res.requires_restart) {
        toast('Server settings saved. Restart outline-ss-rust to apply socket/TLS changes.');
      } else {
        toast('Server settings saved.');
      }
      await configPoll.refresh();
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      toast(msg, 'error');
    } finally {
      mutating = false;
    }
  }
</script>

<section class="view active">
  <div class="page-head">
    <div>
      <h1>Server Settings</h1>
      <p>Configure listening ports, TLS certificates, session resumption, and outbound routing.</p>
    </div>
    <div class="toolbar">
      <InstanceSelector base="/ss" bind:selected={instance} bind:refreshSecs={refreshSecs} />
      <button class="btn primary sm" disabled={!instance || mutating || !formDirty} onclick={save}>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
        Save changes
      </button>
    </div>
  </div>

  {#if !instance}
    <div class="empty">Select a server to view and configure its settings.</div>
  {:else}
    <ErrorBanner message={configPoll.error} />

    {#if config}
      {#if formDirty}
        <div class="applybar">
          <span class="pill">MODIFIED</span>
          <span>You have unsaved changes. Remember to click "Save changes" above.</span>
        </div>
      {/if}

      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(360px, 1fr)); gap: var(--sp-4);">
        <!-- Listeners & TLS -->
        <div class="panel" style="padding: var(--sp-4);">
          <h3 style="font-size: 14px; font-weight: 600; margin-top: 0; margin-bottom: var(--sp-3);">
            Listeners & TLS
          </h3>
          <div style="display: flex; flex-direction: column; gap: var(--sp-3);">
            <div class="fieldrow">
              <label for="tcp-listen-input">TCP / TLS Listen Address</label>
              <input
                id="tcp-listen-input"
                type="text"
                placeholder="0.0.0.0:443 or [::]:443"
                bind:value={listen}
                oninput={markDirty}
                class="field-mono"
              />
              <span class="hint">Primary listening socket for WebSocket / XHTTP and raw Shadowsocks connections.</span>
            </div>

            <div class="fieldrow">
              <label for="cert-path-input">TLS Certificate Fullchain Path</label>
              <input
                id="cert-path-input"
                type="text"
                placeholder="/etc/letsencrypt/live/example.com/fullchain.pem"
                bind:value={certPath}
                oninput={markDirty}
                class="field-mono"
              />
              <span class="hint">Path to the PEM-encoded TLS certificate fullchain file.</span>
            </div>

            <div class="fieldrow">
              <label for="key-path-input">TLS Private Key Path</label>
              <input
                id="key-path-input"
                type="text"
                placeholder="/etc/letsencrypt/live/example.com/privkey.pem"
                bind:value={keyPath}
                oninput={markDirty}
                class="field-mono"
              />
              <span class="hint">Path to the PEM-encoded RSA or ECC private key file.</span>
            </div>

            <div class="fieldrow">
              <label for="h3-listen-input">HTTP/3 QUIC Listen Address (Optional)</label>
              <input
                id="h3-listen-input"
                type="text"
                placeholder="0.0.0.0:443 or [::]:443 (leave blank to disable)"
                bind:value={h3Listen}
                oninput={markDirty}
                class="field-mono"
              />
              <span class="hint">UDP socket for HTTP/3 carrier traffic. Usually the same port as TCP.</span>
            </div>

            <div class="fieldrow">
              <label for="h3-mtu-input">HTTP/3 Initial MTU (Optional)</label>
              <input
                id="h3-mtu-input"
                type="number"
                min="1200"
                max="1500"
                placeholder="1252 (leave blank for QUIC default 1200)"
                bind:value={h3InitialMtu}
                oninput={markDirty}
                class="field-mono"
              />
              <span class="hint">Initial UDP packet size for HTTP/3 QUIC handshakes (1200–1450).</span>
            </div>
          </div>
        </div>

        <!-- Session Resumption -->
        <div class="panel" style="padding: var(--sp-4);">
          <h3 style="font-size: 14px; font-weight: 600; margin-top: 0; margin-bottom: var(--sp-3);">
            Session Resumption (0-RTT)
          </h3>
          <div style="display: flex; flex-direction: column; gap: var(--sp-3);">
            <div class="fieldrow">
              <label class="switch">
                <input type="checkbox" bind:checked={resumeEnabled} onchange={markDirty} />
                <span>Enable fast session resumption</span>
              </label>
              <span class="hint">Allows clients to quickly resume interrupted sessions without full crypto handshake.</span>
            </div>

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: var(--sp-2);">
              <div class="fieldrow">
                <label for="ttl-tcp-input">TCP TTL (sec)</label>
                <input
                  id="ttl-tcp-input"
                  type="number"
                  min="10"
                  max="86400"
                  bind:value={orphanTtlTcpSecs}
                  oninput={markDirty}
                  disabled={!resumeEnabled}
                  class="field-mono"
                />
              </div>
              <div class="fieldrow">
                <label for="ttl-udp-input">UDP TTL (sec)</label>
                <input
                  id="ttl-udp-input"
                  type="number"
                  min="10"
                  max="86400"
                  bind:value={orphanTtlUdpSecs}
                  oninput={markDirty}
                  disabled={!resumeEnabled}
                  class="field-mono"
                />
              </div>
            </div>

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: var(--sp-2);">
              <div class="fieldrow">
                <label for="per-user-cap-input">Per-User Cap</label>
                <input
                  id="per-user-cap-input"
                  type="number"
                  min="1"
                  max="64"
                  bind:value={orphanPerUserCap}
                  oninput={markDirty}
                  disabled={!resumeEnabled}
                  class="field-mono"
                />
              </div>
              <div class="fieldrow">
                <label for="global-cap-input">Global Cap</label>
                <input
                  id="global-cap-input"
                  type="number"
                  min="16"
                  max="65536"
                  bind:value={orphanGlobalCap}
                  oninput={markDirty}
                  disabled={!resumeEnabled}
                  class="field-mono"
                />
              </div>
            </div>

            <div class="fieldrow">
              <label for="downlink-buf-input">Downlink Buffer (KiB)</label>
              <input
                id="downlink-buf-input"
                type="number"
                min="0"
                max="1024"
                bind:value={downlinkBufferKib}
                oninput={markDirty}
                disabled={!resumeEnabled}
                class="field-mono"
              />
              <span class="hint">Buffer size to hold downstream packets while a client briefly reconnects.</span>
            </div>
          </div>
        </div>

        <!-- Outbound Routing & Tuning -->
        <div class="panel" style="padding: var(--sp-4);">
          <h3 style="font-size: 14px; font-weight: 600; margin-top: 0; margin-bottom: var(--sp-3);">
            Outbound Traffic & Tuning
          </h3>
          <div style="display: flex; flex-direction: column; gap: var(--sp-3);">
            <div class="fieldrow">
              <label class="switch">
                <input type="checkbox" bind:checked={outboundPreferIpv4} onchange={markDirty} />
                <span>Prefer IPv4 for upstream targets</span>
              </label>
              <span class="hint">When target domain resolves to both IPv4 and IPv6, connect via IPv4 first.</span>
            </div>

            <div class="fieldrow">
              <label class="switch">
                <input type="checkbox" bind:checked={outboundIpv6Sticky} onchange={markDirty} />
                <span>Sticky IPv6 sessions</span>
              </label>
              <span class="hint">Keeps the same source IP for the same client session across connections.</span>
            </div>

            <div class="fieldrow">
              <label for="outbound-prefix-input">IPv6 Prefix Pool (Optional)</label>
              <input
                id="outbound-prefix-input"
                type="text"
                placeholder="2001:db8:1234::/64"
                bind:value={outboundIpv6Prefix}
                oninput={markDirty}
                class="field-mono"
              />
              <span class="hint">Subnet prefix for outbound IPv6 address rotation.</span>
            </div>

            <div class="fieldrow">
              <label for="outbound-iface-input">Bind Outbound Interface (Optional)</label>
              <input
                id="outbound-iface-input"
                type="text"
                placeholder="eth0 or wg0"
                bind:value={outboundIpv6Interface}
                oninput={markDirty}
                class="field-mono"
              />
              <span class="hint">Network interface device to bind all upstream outbound sockets.</span>
            </div>

            <div class="fieldrow">
              <label for="outbound-prefix-iface-input">IPv6 Dynamic Prefix Interface (Optional)</label>
              <input
                id="outbound-prefix-iface-input"
                type="text"
                placeholder="eth0 or ens3"
                bind:value={outboundIpv6PrefixInterface}
                oninput={markDirty}
                class="field-mono"
              />
              <span class="hint">Interface from which to discover the dynamic /64 prefix pool.</span>
            </div>

            <div class="fieldrow">
              <label for="outbound-refresh-secs-input">IPv6 Prefix Refresh Interval (sec)</label>
              <input
                id="outbound-refresh-secs-input"
                type="number"
                min="10"
                placeholder="300 (leave blank for default)"
                bind:value={outboundIpv6RefreshSecs}
                oninput={markDirty}
                class="field-mono"
              />
              <span class="hint">Periodic interval to rediscover dynamic IPv6 prefix from network interface.</span>
            </div>

            <div class="fieldrow">
              <label for="tuning-profile-input">Tuning Profile</label>
              <select id="tuning-profile-input" bind:value={tuningProfile} onchange={markDirty}>
                <option value="large">large (Production default — 64-bit fast crypto, large socket & ring buffers)</option>
                <option value="medium">medium (Balanced memory footprint and buffer sizes)</option>
                <option value="small">small (Low-memory footprint, embedded/constrained environments)</option>
              </select>
            </div>
          </div>
        </div>

        <!-- Carrier Padding & Jitter -->
        <div class="panel" style="padding: var(--sp-4);">
          <h3 style="font-size: 14px; font-weight: 600; margin-top: 0; margin-bottom: var(--sp-3);">
            Carrier Padding & Jitter
          </h3>
          <div style="display: flex; flex-direction: column; gap: var(--sp-3);">
            <div class="fieldrow">
              <label class="switch">
                <input type="checkbox" bind:checked={paddingCover} onchange={markDirty} />
                <span>Cover mode (pad payload up to max bytes)</span>
              </label>
              <span class="hint">If enabled, pads payloads up to max bytes rather than adding random bytes.</span>
            </div>

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: var(--sp-2);">
              <div class="fieldrow">
                <label for="pad-min-input">Min Padding (bytes)</label>
                <input
                  id="pad-min-input"
                  type="number"
                  min="0"
                  max="65535"
                  bind:value={paddingMinBytes}
                  oninput={markDirty}
                  class="field-mono"
                />
              </div>
              <div class="fieldrow">
                <label for="pad-max-input">Max Padding (bytes)</label>
                <input
                  id="pad-max-input"
                  type="number"
                  min="0"
                  max="65535"
                  bind:value={paddingMaxBytes}
                  oninput={markDirty}
                  class="field-mono"
                />
              </div>
            </div>

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: var(--sp-2);">
              <div class="fieldrow">
                <label for="pad-req-jitter-input">Cover Jitter Min (ms)</label>
                <input
                  id="pad-req-jitter-input"
                  type="number"
                  min="0"
                  max="10000"
                  bind:value={paddingCoverJitterMinMs}
                  oninput={markDirty}
                  class="field-mono"
                />
              </div>
              <div class="fieldrow">
                <label for="pad-resp-jitter-input">Cover Jitter Max (ms)</label>
                <input
                  id="pad-resp-jitter-input"
                  type="number"
                  min="0"
                  max="10000"
                  bind:value={paddingCoverJitterMaxMs}
                  oninput={markDirty}
                  class="field-mono"
                />
              </div>
            </div>

            <div class="fieldrow">
              <label class="switch">
                <input type="checkbox" bind:checked={paddingThrottleDetect} onchange={markDirty} />
                <span>Throttle detection</span>
              </label>
              <span class="hint">Dynamically adapts padding behavior when carrier throttling is detected.</span>
            </div>
          </div>
        </div>

        <!-- SNI Camouflage & Fallback -->
        <div class="panel" style="padding: var(--sp-4);">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: var(--sp-3);">
            <div>
              <h3 style="font-size: 14px; font-weight: 600; margin: 0;">
                SNI Camouflage & Fallback
              </h3>
              <p class="desc" style="margin-top: 4px; margin-bottom: 0; font-size: 12px;">
                Peek ClientHello on TCP listener: route legitimate proxy SNIs locally, splice foreign or non-SNI TLS probes to camouflage backends.
              </p>
            </div>
            <button class="btn sm" type="button" onclick={addSniBackend}>
              + Add Backend
            </button>
          </div>

          <div style="display: flex; flex-direction: column; gap: var(--sp-3);">
            <div class="fieldrow">
              <label for="sni-match-input">Local Allowed SNI Whitelist (match_sni)</label>
              <input
                id="sni-match-input"
                type="text"
                placeholder="*.beerloga.su, myproxy.domain.com"
                bind:value={sniMatchSni}
                oninput={markDirty}
                class="field-mono"
              />
              <span class="hint">SNIs handled locally by this proxy listener. Wildcards supported (*.example.com). Separated by commas.</span>
            </div>

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: var(--sp-2);">
              <div class="fieldrow">
                <label class="switch">
                  <input type="checkbox" bind:checked={sniAllowNoSni} onchange={markDirty} />
                  <span>Allow connections without SNI</span>
                </label>
                <span class="hint">If unchecked, connections lacking SNI are forwarded to the fallback backend.</span>
              </div>
              <div class="fieldrow">
                <label for="sni-max-hello-input">Max ClientHello Bytes</label>
                <input
                  id="sni-max-hello-input"
                  type="number"
                  min="256"
                  max="65535"
                  bind:value={sniMaxClientHelloBytes}
                  oninput={markDirty}
                  class="field-mono"
                />
              </div>
            </div>

            <!-- Backends list -->
            <div>
              <span style="font-size: 12px; font-weight: 600; color: var(--text-muted); display: block; margin-bottom: var(--sp-2);">
                Fallback Backends ([[sni_fallback.backends]]):
              </span>
              {#if sniBackends.length === 0}
                <div class="empty" style="padding: var(--sp-2); font-size: 12px;">
                  No fallback backends configured. Click "+ Add Backend" above to add one.
                </div>
              {:else}
                <div style="display: flex; flex-direction: column; gap: var(--sp-2);">
                  {#each sniBackends as b, idx}
                    <div style="display: grid; grid-template-columns: 2fr 1.2fr 2fr auto; gap: var(--sp-2); align-items: end; background: var(--bg-surface-2, rgba(0,0,0,0.1)); padding: var(--sp-2); border-radius: var(--radius-sm, 6px); border: 1px solid var(--border-subtle, rgba(255,255,255,0.05));">
                      <div class="fieldrow" style="margin: 0;">
                        <label for={`sni-b-target-${idx}`} style="font-size: 11px;">Backend Target</label>
                        <input
                          id={`sni-b-target-${idx}`}
                          type="text"
                          placeholder="127.0.0.1:11443"
                          bind:value={b.backend}
                          oninput={markDirty}
                          class="field-mono sm"
                        />
                      </div>
                      <div class="fieldrow" style="margin: 0;">
                        <label for={`sni-b-pp-${idx}`} style="font-size: 11px;">PROXY Protocol</label>
                        <select id={`sni-b-pp-${idx}`} bind:value={b.proxy_protocol} onchange={markDirty} class="sm">
                          <option value="">Disabled</option>
                          <option value="v1">v1 (text)</option>
                          <option value="v2">v2 (binary)</option>
                        </select>
                      </div>
                      <div class="fieldrow" style="margin: 0;">
                        <label for={`sni-b-match-${idx}`} style="font-size: 11px;">Route SNIs (Empty = Catch-all)</label>
                        <input
                          id={`sni-b-match-${idx}`}
                          type="text"
                          placeholder="Empty for catch-all default"
                          bind:value={b.match_sni}
                          oninput={markDirty}
                          class="field-mono sm"
                        />
                      </div>
                      <button
                        type="button"
                        class="btn sm danger"
                        style="height: 32px; padding: 0 8px;"
                        title="Remove backend"
                        onclick={() => removeSniBackend(idx)}
                      >
                        ✕
                      </button>
                    </div>
                  {/each}
                </div>
              {/if}
            </div>
          </div>
        </div>

        <!-- HTTP Camouflage & Fallback -->
        <div class="panel" style="padding: var(--sp-4);">
          <h3 style="font-size: 14px; font-weight: 600; margin-top: 0; margin-bottom: var(--sp-3);">
            HTTP Camouflage & Fallback
          </h3>
          <p class="desc" style="margin-top: 0; margin-bottom: var(--sp-3); font-size: 12px;">
            Reverse proxy unauthenticated HTTP probes to a real website to camouflage proxy listeners.
          </p>
          <div style="display: flex; flex-direction: column; gap: var(--sp-3);">
            <div class="fieldrow">
              <label for="fallback-backend-input">Fallback Backend Target (Optional)</label>
              <input
                id="fallback-backend-input"
                type="text"
                placeholder="http://127.0.0.1:8080"
                bind:value={fallbackBackend}
                oninput={markDirty}
                class="field-mono"
              />
              <span class="hint">Scheme and host:port of camouflage website (e.g. http://127.0.0.1:8080).</span>
            </div>

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: var(--sp-2);">
              <div class="fieldrow">
                <label for="fallback-proto-input">Backend Protocol</label>
                <select id="fallback-proto-input" bind:value={fallbackBackendProto} onchange={markDirty}>
                  <option value="">auto (HTTP/1.1)</option>
                  <option value="h1">HTTP/1.1</option>
                  <option value="h2">HTTP/2</option>
                </select>
              </div>
              <div class="fieldrow">
                <label for="fallback-timeout-input">Timeout (sec)</label>
                <input
                  id="fallback-timeout-input"
                  type="number"
                  min="1"
                  max="300"
                  bind:value={fallbackTimeoutSecs}
                  oninput={markDirty}
                  class="field-mono"
                />
              </div>
            </div>

            <div class="fieldrow">
              <label for="fallback-proxy-proto-input">PROXY Protocol</label>
              <select id="fallback-proxy-proto-input" bind:value={fallbackProxyProtocol} onchange={markDirty}>
                <option value="">Disabled</option>
                <option value="v1">PROXY Protocol v1 (text)</option>
                <option value="v2">PROXY Protocol v2 (binary)</option>
              </select>
              <span class="hint">Pass real client IP to backend via PROXY protocol header. (Note: apply_to_h3 requires v2 or Disabled).</span>
            </div>

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: var(--sp-2);">
              <div class="fieldrow">
                <label class="switch">
                  <input type="checkbox" bind:checked={fallbackApplyH1} onchange={markDirty} />
                  <span>Apply to HTTP/1.1 & H2</span>
                </label>
              </div>
              <div class="fieldrow">
                <label class="switch">
                  <input type="checkbox" bind:checked={fallbackApplyH3} onchange={markDirty} />
                  <span>Apply to HTTP/3</span>
                </label>
              </div>
            </div>

            <div style="display: flex; flex-direction: column; gap: var(--sp-1);">
              <span style="font-size: 12px; font-weight: 500; color: var(--text-muted);">Forwarding Headers:</span>
              <div style="display: flex; gap: var(--sp-3); flex-wrap: wrap;">
                <label class="switch" style="font-size: 12px;">
                  <input type="checkbox" bind:checked={fallbackXFwdFor} onchange={markDirty} />
                  <span>X-Forwarded-For</span>
                </label>
                <label class="switch" style="font-size: 12px;">
                  <input type="checkbox" bind:checked={fallbackXFwdProto} onchange={markDirty} />
                  <span>X-Forwarded-Proto</span>
                </label>
                <label class="switch" style="font-size: 12px;">
                  <input type="checkbox" bind:checked={fallbackXFwdHost} onchange={markDirty} />
                  <span>X-Forwarded-Host</span>
                </label>
              </div>
            </div>
          </div>
        </div>

        <!-- Configured Carrier Endpoints -->
        <div class="panel" style="padding: var(--sp-4);">
          <h3 style="font-size: 14px; font-weight: 600; margin-top: 0; margin-bottom: var(--sp-3);">
            Carrier Endpoints
          </h3>
          <p class="desc" style="margin-top: 0; margin-bottom: var(--sp-3); font-size: 12px;">
            Active transport pathways configured on this server for proxy traffic.
          </p>

          {#if editableEndpoints.length === 0}
            <div class="empty" style="padding: var(--sp-3);">No carrier endpoints configured.</div>
          {:else}
            <table>
              <thead>
                <tr>
                  <th>Path</th>
                  <th>Transport</th>
                  <th>Protocol</th>
                  <th>Padding</th>
                </tr>
              </thead>
              <tbody>
                {#each editableEndpoints as ep}
                  <tr>
                    <td><span class="field-mono" style="font-weight: 600;">{ep.path}</span></td>
                    <td><span class="chip info">{ep.transport}</span></td>
                    <td><span class="chip ok">{ep.protocol}</span></td>
                    <td>
                      <label class="switch" style="cursor: pointer; margin: 0; display: inline-flex; align-items: center; gap: var(--sp-2);">
                        <input
                          type="checkbox"
                          bind:checked={ep.padded}
                          onchange={markDirty}
                        />
                        <span class="chip" class:pos={ep.padded} class:off={!ep.padded}>
                          {ep.padded ? 'Padded' : 'Plain'}
                        </span>
                      </label>
                    </td>
                  </tr>
                {/each}
              </tbody>
            </table>
          {/if}
        </div>
      </div>
    {/if}
  {/if}
</section>
