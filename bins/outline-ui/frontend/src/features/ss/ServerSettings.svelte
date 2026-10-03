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
  let outboundIpv6Sticky = $state(false);
  let outboundIpv6StickyTtl = $state(300);

  // Form states: Tuning profile
  let tuningProfile = $state('default');

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
  const endpoints = $derived<EndpointConfigItem[]>(config?.endpoints ?? []);

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
        outboundIpv6Sticky = config.outbound.ipv6_sticky ?? false;
        outboundIpv6StickyTtl = config.outbound.ipv6_sticky_ttl_secs ?? 300;
      }
      if (config.tuning_profile) {
        tuningProfile = config.tuning_profile;
      }
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
        ipv6_sticky: outboundIpv6Sticky,
        ipv6_sticky_ttl_secs: outboundIpv6StickyTtl,
      };

      const res = await patchServerConfig(instance, {
        server: serverPatch,
        session_resumption: resumePatch,
        outbound: outboundPatch,
        tuning_profile: tuningProfile.trim() ? tuningProfile.trim() : null,
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
              <label for="tuning-profile-input">Tuning Profile</label>
              <select id="tuning-profile-input" bind:value={tuningProfile} onchange={markDirty}>
                <option value="default">default (Standard buffer sizes and timeouts)</option>
                <option value="high-concurrency">high-concurrency (Aggressive socket pooling)</option>
                <option value="low-latency">low-latency (Reduced buffering and fast flushing)</option>
              </select>
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

          {#if endpoints.length === 0}
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
                {#each endpoints as ep}
                  <tr>
                    <td><span class="field-mono" style="font-weight: 600;">{ep.path}</span></td>
                    <td><span class="chip info">{ep.transport}</span></td>
                    <td><span class="chip ok">{ep.protocol}</span></td>
                    <td>
                      {#if ep.padded}
                        <span class="chip pos">Padded</span>
                      {:else}
                        <span class="chip off">Plain</span>
                      {/if}
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
