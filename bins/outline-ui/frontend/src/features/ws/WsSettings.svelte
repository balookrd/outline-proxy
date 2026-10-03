<script lang="ts">
  import { onDestroy } from 'svelte';
  import { getWsConfig, patchWsConfig, apply } from '../../lib/api';
  import { createPoll } from '../../lib/poll.svelte';
  import { toast } from '../../lib/toast.svelte';
  import type {
    WsConfigResponse,
    WsProbeConfig,
    WsSocks5Config,
    WsSocks5User,
    WsTunConfig,
    WsDialConfig,
    WsPaddingConfig,
    WsQuicConfig,
    WsH2Config,
    WsTcpTimeoutsConfig,
    WsConfigPatch,
  } from '../../lib/types';
  import InstanceSelector from '../../components/layout/InstanceSelector.svelte';
  import ErrorBanner from '../../components/layout/ErrorBanner.svelte';

  let instance = $state('');
  let refreshSecs = $state(10);
  const refreshMs = $derived(Math.max(1000, refreshSecs * 1000));

  let mutating = $state(false);
  let applying = $state(false);
  let formDirty = $state(false);
  let restartNotice = $state(false);

  // Probe settings
  let probeIntervalSecs = $state<number>(30);
  let probeTimeoutSecs = $state<number>(5);
  let probeMaxConcurrent = $state<number>(4);
  let probeMaxDials = $state<number | null>(null);
  let probeMinFailures = $state<number>(2);
  let probeAttempts = $state<number>(1);
  let probeSkipWhenActive = $state<boolean>(true);
  let probeLivenessIntervalSecs = $state<number>(10);
  let probeEndpointCheck = $state<boolean>(true);
  let probeEndpointCheckTimeoutMs = $state<number>(1500);
  let probeHttpUrls = $state<string>('');
  let probeTlsTargets = $state<string>('');
  let probeDnsServer = $state<string>('');
  let probeDnsPort = $state<number>(53);
  let probeDnsName = $state<string>('');
  let probeTcpHost = $state<string>('');
  let probeTcpPort = $state<number>(80);
  let probeWsEnabled = $state<boolean>(true);

  // SOCKS5 settings
  let socks5Listen = $state<string>('127.0.0.1:1080');
  interface Socks5UserItem {
    id: string;
    username: string;
    password: string;
    has_password: boolean;
  }
  let socks5Users = $state<Socks5UserItem[]>([]);

  function addSocks5User() {
    socks5Users = [
      ...socks5Users,
      {
        id: `user-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
        username: '',
        password: '',
        has_password: false,
      },
    ];
    markDirty();
  }

  function removeSocks5User(id: string) {
    socks5Users = socks5Users.filter((u) => u.id !== id);
    markDirty();
  }

  // TUN settings
  let tunName = $state<string>('tun0');
  let tunMtu = $state<number>(1500);
  let tunMaxFlows = $state<number>(8192);
  let tunMaxCarrierFlows = $state<number>(1024);
  let tunIdleTimeoutSecs = $state<number>(120);
  let tunMaxConcurrentUpstreamDials = $state<number>(128);
  let tunIpsecBypass = $state<boolean>(false);
  let tunSniffQuic = $state<boolean>(true);
  let tunRouteBySni = $state<boolean>(false);
  let tunGso = $state<boolean>(true);
  let tunGro = $state<boolean>(true);
  let tunUso = $state<boolean>(true);

  // Dial & Obfuscation
  let dialTimeoutSecs = $state<number>(10);
  let fingerprintProfile = $state<string>('off');
  let directFwmark = $state<number | null>(null);
  let preferPublicIpv6Src = $state<boolean>(false);

  // Padding
  let paddingEnabled = $state<boolean>(false);
  let paddingMinBytes = $state<number>(0);
  let paddingMaxBytes = $state<number>(256);
  let paddingCover = $state<boolean>(false);
  let paddingCoverJitterMinMs = $state<number>(250);
  let paddingCoverJitterMaxMs = $state<number>(1500);
  let paddingReactToThrottle = $state<boolean>(false);

  // QUIC
  let quicStreamReceiveWindow = $state<number>(1048576);
  let quicReceiveWindow = $state<number>(2097152);
  let quicKeepaliveSecs = $state<number>(15);
  let quicIdleTimeoutSecs = $state<number>(30);

  // H2
  let h2StreamWindowSize = $state<number>(1048576);
  let h2ConnWindowSize = $state<number>(2097152);
  let h2KeepaliveIntervalSecs = $state<number>(20);
  let h2KeepaliveTimeoutSecs = $state<number>(10);

  // TCP Timeouts
  let tcpPostClientEofDownstreamSecs = $state<number>(5);
  let tcpUpstreamResponseSecs = $state<number>(15);
  let tcpSocksUpstreamIdleSecs = $state<number>(300);
  let tcpDirectIdleSecs = $state<number>(120);

  const configPoll = createPoll<WsConfigResponse | null>(
    () => (instance ? getWsConfig(instance) : Promise.resolve(null)),
    () => refreshMs,
  );

  $effect(() => {
    void instance;
    formDirty = false;
    restartNotice = false;
    configPoll.start();
  });
  onDestroy(() => configPoll.stop());

  const config = $derived(configPoll.data);

  $effect(() => {
    if (config && !formDirty) {
      if (config.probe) {
        probeIntervalSecs = config.probe.interval_secs ?? 30;
        probeTimeoutSecs = config.probe.timeout_secs ?? 5;
        probeMaxConcurrent = config.probe.max_concurrent ?? 4;
        probeMaxDials = config.probe.max_dials ?? null;
        probeMinFailures = config.probe.min_failures ?? 2;
        probeAttempts = config.probe.attempts ?? 1;
        probeSkipWhenActive = config.probe.skip_when_active ?? true;
        probeLivenessIntervalSecs = config.probe.liveness_interval_secs ?? 10;
        probeEndpointCheck = config.probe.endpoint_check ?? true;
        probeEndpointCheckTimeoutMs = config.probe.endpoint_check_timeout_ms ?? 1500;
        probeHttpUrls = (config.probe.http_urls ?? []).join('\n');
        probeTlsTargets = (config.probe.tls_targets ?? []).join('\n');
        probeDnsServer = config.probe.dns_server ?? '';
        probeDnsPort = config.probe.dns_port ?? 53;
        probeDnsName = config.probe.dns_name ?? '';
        probeTcpHost = config.probe.tcp_host ?? '';
        probeTcpPort = config.probe.tcp_port ?? 80;
        probeWsEnabled = config.probe.ws_enabled ?? true;
      }
      if (config.socks5) {
        socks5Listen = config.socks5.listen ?? '127.0.0.1:1080';
        if (config.socks5.users && config.socks5.users.length > 0) {
          socks5Users = config.socks5.users.map((u, i) => ({
            id: `${u.username}-${i}`,
            username: u.username,
            password: '',
            has_password: !!u.has_password,
          }));
        } else if (config.socks5.username) {
          socks5Users = [
            {
              id: 'legacy-user-0',
              username: config.socks5.username,
              password: '',
              has_password: !!config.socks5.has_password,
            },
          ];
        } else {
          socks5Users = [];
        }
      }
      if (config.tun) {
        tunName = config.tun.name ?? 'tun0';
        tunMtu = config.tun.mtu ?? 1500;
        tunMaxFlows = config.tun.max_flows ?? 8192;
        tunMaxCarrierFlows = config.tun.max_carrier_flows ?? 1024;
        tunIdleTimeoutSecs = config.tun.idle_timeout_secs ?? 120;
        tunMaxConcurrentUpstreamDials = config.tun.max_concurrent_upstream_dials ?? 128;
        tunIpsecBypass = config.tun.ipsec_bypass ?? false;
        tunSniffQuic = config.tun.sniff_quic ?? true;
        tunRouteBySni = config.tun.route_by_sni ?? false;
        tunGso = config.tun.gso ?? true;
        tunGro = config.tun.gro ?? tunGso;
        tunUso = config.tun.uso ?? tunGso;
      }
      if (config.dial) {
        dialTimeoutSecs = config.dial.timeout_secs ?? 10;
      }
      if (config.fingerprint_profile) {
        fingerprintProfile = config.fingerprint_profile;
      }
      directFwmark = config.direct_fwmark ?? null;
      preferPublicIpv6Src = config.prefer_public_ipv6_src ?? false;
      if (config.padding) {
        paddingEnabled = config.padding.enabled ?? false;
        paddingMinBytes = config.padding.min_bytes ?? 0;
        paddingMaxBytes = config.padding.max_bytes ?? 256;
        paddingCover = config.padding.cover ?? false;
        paddingCoverJitterMinMs = config.padding.cover_jitter_min_ms ?? 250;
        paddingCoverJitterMaxMs = config.padding.cover_jitter_max_ms ?? 1500;
        paddingReactToThrottle = config.padding.react_to_throttle ?? false;
      }
      if (config.quic) {
        quicStreamReceiveWindow = config.quic.stream_receive_window ?? 1048576;
        quicReceiveWindow = config.quic.receive_window ?? 2097152;
        quicKeepaliveSecs = config.quic.keepalive_secs ?? 15;
        quicIdleTimeoutSecs = config.quic.idle_timeout_secs ?? 30;
      }
      if (config.h2) {
        h2StreamWindowSize = config.h2.initial_stream_window_size ?? 1048576;
        h2ConnWindowSize = config.h2.initial_connection_window_size ?? 2097152;
        h2KeepaliveIntervalSecs = config.h2.keepalive_interval_secs ?? 20;
        h2KeepaliveTimeoutSecs = config.h2.keepalive_timeout_secs ?? 10;
      }
      if (config.tcp_timeouts) {
        tcpPostClientEofDownstreamSecs = config.tcp_timeouts.post_client_eof_downstream_secs ?? 5;
        tcpUpstreamResponseSecs = config.tcp_timeouts.upstream_response_secs ?? 15;
        tcpSocksUpstreamIdleSecs = config.tcp_timeouts.socks_upstream_idle_secs ?? 300;
        tcpDirectIdleSecs = config.tcp_timeouts.direct_idle_secs ?? 120;
      }
    }
  });

  function markDirty() {
    formDirty = true;
  }

  function parseList(raw: string): string[] {
    return raw
      .split(/[\n,]/)
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
  }

  async function save() {
    if (!instance) return;

    if (paddingMinBytes > paddingMaxBytes) {
      toast('Padding min_bytes cannot exceed max_bytes.', 'error');
      return;
    }
    if (paddingCoverJitterMinMs > paddingCoverJitterMaxMs) {
      toast('Cover jitter min_ms cannot exceed max_ms.', 'error');
      return;
    }

    mutating = true;
    try {
      const orig = config ?? {};
      const patch: WsConfigPatch = {};

      // 1. Probe
      const probePatch: WsProbeConfig = {};
      let probeChanged = false;
      if (probeIntervalSecs !== (orig.probe?.interval_secs ?? 30)) {
        probePatch.interval_secs = probeIntervalSecs;
        probeChanged = true;
      }
      if (probeTimeoutSecs !== (orig.probe?.timeout_secs ?? 5)) {
        probePatch.timeout_secs = probeTimeoutSecs;
        probeChanged = true;
      }
      if (probeMaxConcurrent !== (orig.probe?.max_concurrent ?? 4)) {
        probePatch.max_concurrent = probeMaxConcurrent;
        probeChanged = true;
      }
      if (probeMaxDials !== (orig.probe?.max_dials ?? null)) {
        probePatch.max_dials = probeMaxDials;
        probeChanged = true;
      }
      if (probeMinFailures !== (orig.probe?.min_failures ?? 2)) {
        probePatch.min_failures = probeMinFailures;
        probeChanged = true;
      }
      if (probeAttempts !== (orig.probe?.attempts ?? 1)) {
        probePatch.attempts = probeAttempts;
        probeChanged = true;
      }
      if (probeSkipWhenActive !== (orig.probe?.skip_when_active ?? true)) {
        probePatch.skip_when_active = probeSkipWhenActive;
        probeChanged = true;
      }
      if (probeLivenessIntervalSecs !== (orig.probe?.liveness_interval_secs ?? 10)) {
        probePatch.liveness_interval_secs = probeLivenessIntervalSecs;
        probeChanged = true;
      }
      if (probeEndpointCheck !== (orig.probe?.endpoint_check ?? true)) {
        probePatch.endpoint_check = probeEndpointCheck;
        probeChanged = true;
      }
      if (probeEndpointCheckTimeoutMs !== (orig.probe?.endpoint_check_timeout_ms ?? 1500)) {
        probePatch.endpoint_check_timeout_ms = probeEndpointCheckTimeoutMs;
        probeChanged = true;
      }

      const newHttp = parseList(probeHttpUrls);
      const origHttp = orig.probe?.http_urls ?? [];
      if (JSON.stringify(newHttp) !== JSON.stringify(origHttp)) {
        probePatch.http_urls = newHttp;
        probeChanged = true;
      }

      const newTls = parseList(probeTlsTargets);
      const origTls = orig.probe?.tls_targets ?? [];
      if (JSON.stringify(newTls) !== JSON.stringify(origTls)) {
        probePatch.tls_targets = newTls;
        probeChanged = true;
      }

      const newDnsServer = probeDnsServer.trim() || null;
      const origDnsServer = orig.probe?.dns_server ?? null;
      if (newDnsServer !== origDnsServer) {
        probePatch.dns_server = newDnsServer;
        probeChanged = true;
      }

      if (probeDnsPort !== (orig.probe?.dns_port ?? 53)) {
        probePatch.dns_port = probeDnsPort;
        probeChanged = true;
      }

      const newDnsName = probeDnsName.trim() || null;
      const origDnsName = orig.probe?.dns_name ?? null;
      if (newDnsName !== origDnsName) {
        probePatch.dns_name = newDnsName;
        probeChanged = true;
      }

      const newTcpHost = probeTcpHost.trim() || null;
      const origTcpHost = orig.probe?.tcp_host ?? null;
      if (newTcpHost !== origTcpHost) {
        probePatch.tcp_host = newTcpHost;
        probeChanged = true;
      }

      if (probeTcpPort !== (orig.probe?.tcp_port ?? 80)) {
        probePatch.tcp_port = probeTcpPort;
        probeChanged = true;
      }

      if (probeWsEnabled !== (orig.probe?.ws_enabled ?? true)) {
        probePatch.ws_enabled = probeWsEnabled;
        probeChanged = true;
      }

      if (probeChanged) {
        patch.probe = probePatch;
      }

      // 2. SOCKS5
      const socks5Patch: {
        listen?: string | null;
        users?: Array<{ username: string; password?: string | null }>;
      } = {};
      let socks5Changed = false;
      const newS5Listen = socks5Listen.trim() || null;
      const origS5Listen = orig.socks5?.listen ?? null;
      if (newS5Listen !== origS5Listen) {
        socks5Patch.listen = newS5Listen;
        socks5Changed = true;
      }

      for (const u of socks5Users) {
        const uname = u.username.trim();
        if (uname && !u.has_password && !u.password.trim()) {
          toast(`Password is required for user "${uname}".`, 'error');
          mutating = false;
          return;
        }
      }

      const origUsers =
        orig.socks5?.users ??
        (orig.socks5?.username
          ? [{ username: orig.socks5.username, has_password: orig.socks5.has_password }]
          : []);

      const activeUsers = socks5Users.filter((u) => u.username.trim().length > 0);
      let usersChanged = activeUsers.length !== origUsers.length;
      if (!usersChanged) {
        for (let i = 0; i < activeUsers.length; i++) {
          const cur = activeUsers[i];
          const prev = origUsers[i];
          if (cur.username.trim() !== prev.username || cur.password.trim().length > 0) {
            usersChanged = true;
            break;
          }
        }
      }

      if (usersChanged) {
        socks5Patch.users = activeUsers.map((u) => ({
          username: u.username.trim(),
          password: u.password.trim() ? u.password.trim() : (u.has_password ? '********' : null),
        }));
        socks5Changed = true;
      }

      if (socks5Changed) {
        patch.socks5 = socks5Patch;
      }

      // 3. TUN
      const tunPatch: WsTunConfig = {};
      let tunChanged = false;
      const newTunName = tunName.trim() || null;
      const origTunName = orig.tun?.name ?? null;
      if (newTunName !== origTunName) {
        tunPatch.name = newTunName;
        tunChanged = true;
      }
      if (tunMtu !== (orig.tun?.mtu ?? 1500)) {
        tunPatch.mtu = tunMtu;
        tunChanged = true;
      }
      if (tunMaxFlows !== (orig.tun?.max_flows ?? 8192)) {
        tunPatch.max_flows = tunMaxFlows;
        tunChanged = true;
      }
      if (tunMaxCarrierFlows !== (orig.tun?.max_carrier_flows ?? 1024)) {
        tunPatch.max_carrier_flows = tunMaxCarrierFlows;
        tunChanged = true;
      }
      if (tunIdleTimeoutSecs !== (orig.tun?.idle_timeout_secs ?? 120)) {
        tunPatch.idle_timeout_secs = tunIdleTimeoutSecs;
        tunChanged = true;
      }
      if (tunMaxConcurrentUpstreamDials !== (orig.tun?.max_concurrent_upstream_dials ?? 128)) {
        tunPatch.max_concurrent_upstream_dials = tunMaxConcurrentUpstreamDials;
        tunChanged = true;
      }
      if (tunIpsecBypass !== (orig.tun?.ipsec_bypass ?? false)) {
        tunPatch.ipsec_bypass = tunIpsecBypass;
        tunChanged = true;
      }
      if (tunSniffQuic !== (orig.tun?.sniff_quic ?? true)) {
        tunPatch.sniff_quic = tunSniffQuic;
        tunChanged = true;
      }
      if (tunRouteBySni !== (orig.tun?.route_by_sni ?? false)) {
        tunPatch.route_by_sni = tunRouteBySni;
        tunChanged = true;
      }
      if (tunGso !== (orig.tun?.gso ?? true)) {
        tunPatch.gso = tunGso;
        tunChanged = true;
      }
      if (tunGro !== (orig.tun?.gro ?? tunGso)) {
        tunPatch.gro = tunGro;
        tunChanged = true;
      }
      if (tunUso !== (orig.tun?.uso ?? tunGso)) {
        tunPatch.uso = tunUso;
        tunChanged = true;
      }
      if (tunChanged) {
        patch.tun = tunPatch;
      }

      // 4. Dial
      if (orig.dial != null || dialTimeoutSecs !== 10) {
        if (dialTimeoutSecs !== (orig.dial?.timeout_secs ?? 10)) {
          patch.dial = { timeout_secs: dialTimeoutSecs };
        }
      }

      // 5. Padding
      const paddingPatch: WsPaddingConfig = {};
      let paddingChanged = false;
      if (paddingEnabled !== (orig.padding?.enabled ?? false)) {
        paddingPatch.enabled = paddingEnabled;
        paddingChanged = true;
      }
      if (paddingMinBytes !== (orig.padding?.min_bytes ?? 0)) {
        paddingPatch.min_bytes = paddingMinBytes;
        paddingChanged = true;
      }
      if (paddingMaxBytes !== (orig.padding?.max_bytes ?? 256)) {
        paddingPatch.max_bytes = paddingMaxBytes;
        paddingChanged = true;
      }
      if (paddingCover !== (orig.padding?.cover ?? false)) {
        paddingPatch.cover = paddingCover;
        paddingChanged = true;
      }
      if (paddingCoverJitterMinMs !== (orig.padding?.cover_jitter_min_ms ?? 250)) {
        paddingPatch.cover_jitter_min_ms = paddingCoverJitterMinMs;
        paddingChanged = true;
      }
      if (paddingCoverJitterMaxMs !== (orig.padding?.cover_jitter_max_ms ?? 1500)) {
        paddingPatch.cover_jitter_max_ms = paddingCoverJitterMaxMs;
        paddingChanged = true;
      }
      if (paddingReactToThrottle !== (orig.padding?.react_to_throttle ?? false)) {
        paddingPatch.react_to_throttle = paddingReactToThrottle;
        paddingChanged = true;
      }
      if (paddingChanged) {
        patch.padding = paddingPatch;
      }

      // 6. QUIC
      if (orig.quic != null || quicStreamReceiveWindow !== 1048576 || quicReceiveWindow !== 2097152 || quicKeepaliveSecs !== 15 || quicIdleTimeoutSecs !== 30) {
        const quicPatch: WsQuicConfig = {};
        let quicChanged = false;
        if (quicStreamReceiveWindow !== (orig.quic?.stream_receive_window ?? 1048576)) {
          quicPatch.stream_receive_window = quicStreamReceiveWindow;
          quicChanged = true;
        }
        if (quicReceiveWindow !== (orig.quic?.receive_window ?? 2097152)) {
          quicPatch.receive_window = quicReceiveWindow;
          quicChanged = true;
        }
        if (quicKeepaliveSecs !== (orig.quic?.keepalive_secs ?? 15)) {
          quicPatch.keepalive_secs = quicKeepaliveSecs;
          quicChanged = true;
        }
        if (quicIdleTimeoutSecs !== (orig.quic?.idle_timeout_secs ?? 30)) {
          quicPatch.idle_timeout_secs = quicIdleTimeoutSecs;
          quicChanged = true;
        }
        if (quicChanged) {
          patch.quic = quicPatch;
        }
      }

      // 7. H2
      if (orig.h2 != null || h2StreamWindowSize !== 1048576 || h2ConnWindowSize !== 2097152 || h2KeepaliveIntervalSecs !== 20 || h2KeepaliveTimeoutSecs !== 10) {
        const h2Patch: WsH2Config = {};
        let h2Changed = false;
        if (h2StreamWindowSize !== (orig.h2?.initial_stream_window_size ?? 1048576)) {
          h2Patch.initial_stream_window_size = h2StreamWindowSize;
          h2Changed = true;
        }
        if (h2ConnWindowSize !== (orig.h2?.initial_connection_window_size ?? 2097152)) {
          h2Patch.initial_connection_window_size = h2ConnWindowSize;
          h2Changed = true;
        }
        if (h2KeepaliveIntervalSecs !== (orig.h2?.keepalive_interval_secs ?? 20)) {
          h2Patch.keepalive_interval_secs = h2KeepaliveIntervalSecs;
          h2Changed = true;
        }
        if (h2KeepaliveTimeoutSecs !== (orig.h2?.keepalive_timeout_secs ?? 10)) {
          h2Patch.keepalive_timeout_secs = h2KeepaliveTimeoutSecs;
          h2Changed = true;
        }
        if (h2Changed) {
          patch.h2 = h2Patch;
        }
      }

      // 8. TCP Timeouts
      if (orig.tcp_timeouts != null || tcpPostClientEofDownstreamSecs !== 5 || tcpUpstreamResponseSecs !== 15 || tcpSocksUpstreamIdleSecs !== 300 || tcpDirectIdleSecs !== 120) {
        const tcpTimeoutsPatch: WsTcpTimeoutsConfig = {};
        let tcpTimeoutsChanged = false;
        if (tcpPostClientEofDownstreamSecs !== (orig.tcp_timeouts?.post_client_eof_downstream_secs ?? 5)) {
          tcpTimeoutsPatch.post_client_eof_downstream_secs = tcpPostClientEofDownstreamSecs;
          tcpTimeoutsChanged = true;
        }
        if (tcpUpstreamResponseSecs !== (orig.tcp_timeouts?.upstream_response_secs ?? 15)) {
          tcpTimeoutsPatch.upstream_response_secs = tcpUpstreamResponseSecs;
          tcpTimeoutsChanged = true;
        }
        if (tcpSocksUpstreamIdleSecs !== (orig.tcp_timeouts?.socks_upstream_idle_secs ?? 300)) {
          tcpTimeoutsPatch.socks_upstream_idle_secs = tcpSocksUpstreamIdleSecs;
          tcpTimeoutsChanged = true;
        }
        if (tcpDirectIdleSecs !== (orig.tcp_timeouts?.direct_idle_secs ?? 120)) {
          tcpTimeoutsPatch.direct_idle_secs = tcpDirectIdleSecs;
          tcpTimeoutsChanged = true;
        }
        if (tcpTimeoutsChanged) {
          patch.tcp_timeouts = tcpTimeoutsPatch;
        }
      }

      // 9. Root fields
      if (fingerprintProfile !== (orig.fingerprint_profile ?? 'off')) {
        patch.fingerprint_profile = fingerprintProfile;
      }
      if (preferPublicIpv6Src !== (orig.prefer_public_ipv6_src ?? false)) {
        patch.prefer_public_ipv6_src = preferPublicIpv6Src;
      }
      if (directFwmark !== (orig.direct_fwmark ?? null)) {
        patch.direct_fwmark = directFwmark;
      }

      if (Object.keys(patch).length === 0) {
        formDirty = false;
        toast('No modifications detected.');
        return;
      }

      const res = await patchWsConfig(instance, patch);
      formDirty = false;
      restartNotice = res.restart_required;

      if (res.restart_required) {
        toast('Settings saved. Restart outline-ws-rust service to bind new sockets or TUN device.');
      } else {
        toast('Settings saved. Click "Apply now" to reload routing and uplinks live.');
      }

      await configPoll.refresh();
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      toast(msg, 'error');
    } finally {
      mutating = false;
    }
  }

  async function triggerApply() {
    if (!instance) return;
    applying = true;
    try {
      await apply(instance);
      toast(`Dynamic configuration applied on ${instance}`);
      restartNotice = false;
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      toast(`Apply failed: ${msg}`, 'error');
    } finally {
      applying = false;
    }
  }
</script>

<section class="view active">
  <div class="page-head">
    <div>
      <h1>Client Settings</h1>
      <p>Configure quality probes, local SOCKS5 & TUN ingress, carrier obfuscation, and transport windows.</p>
    </div>
    <div class="toolbar">
      <InstanceSelector base="/ws" bind:selected={instance} bind:refreshSecs={refreshSecs} />
      <button
        class="btn secondary sm"
        disabled={!instance || applying || mutating}
        onclick={triggerApply}
        title="Hot-reloads uplinks, groups and routing rules on this client node without dropping active sessions"
      >
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
        {applying ? 'Applying...' : 'Apply now'}
      </button>
      <button class="btn primary sm" disabled={!instance || mutating || !formDirty} onclick={save}>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
        {mutating ? 'Saving...' : 'Save changes'}
      </button>
    </div>
  </div>

  {#if !instance}
    <div class="empty">Select a client instance to view and adjust its configuration.</div>
  {:else}
    <ErrorBanner message={configPoll.error} />

    {#if config}
      {#if formDirty}
        <div class="applybar">
          <span class="pill">MODIFIED</span>
          <span>You have unsaved changes. Remember to click "Save changes" above, then "Apply now" to reload routing.</span>
        </div>
      {/if}

      {#if restartNotice}
        <div class="applybar" style="border-color: color-mix(in srgb, var(--info) 40%, var(--border)); background: color-mix(in srgb, var(--info) 10%, var(--surface));">
          <span class="pill" style="color: var(--info);">RESTART REQUIRED</span>
          <span>Changes to SOCKS5 listen socket, TUN interface parameters, or dial/transport windows require restarting <code>outline-ws-rust</code>.</span>
        </div>
      {/if}

      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(360px, 1fr)); gap: var(--sp-4);">
        <!-- 1. Quality & Liveness Probes -->
        <div class="panel" style="padding: var(--sp-4);">
          <h3 style="font-size: 14px; font-weight: 600; margin-top: 0; margin-bottom: var(--sp-2);">
            Health & Quality Probes
          </h3>
          <p class="desc" style="margin-top: 0; margin-bottom: var(--sp-3); font-size: 12px; color: var(--fg-muted);">
            Latency measurement (EWMA RTT), liveness checks, and degradation detection across uplinks.
          </p>

          <div style="display: flex; flex-direction: column; gap: var(--sp-3);">
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: var(--sp-2);">
              <div class="fieldrow">
                <label for="probe-interval">Probe Interval (s)</label>
                <input
                  id="probe-interval"
                  type="number"
                  min="1"
                  bind:value={probeIntervalSecs}
                  oninput={markDirty}
                  class="field-mono"
                />
                <span class="hint">Background measurement period.</span>
              </div>
              <div class="fieldrow">
                <label for="probe-liveness">Liveness Interval (s)</label>
                <input
                  id="probe-liveness"
                  type="number"
                  min="1"
                  bind:value={probeLivenessIntervalSecs}
                  oninput={markDirty}
                  class="field-mono"
                />
                <span class="hint">Health check for active uplinks.</span>
              </div>
            </div>

            <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: var(--sp-2);">
              <div class="fieldrow">
                <label for="probe-timeout">Timeout (s)</label>
                <input
                  id="probe-timeout"
                  type="number"
                  min="1"
                  bind:value={probeTimeoutSecs}
                  oninput={markDirty}
                  class="field-mono"
                />
              </div>
              <div class="fieldrow">
                <label for="probe-min-failures">Failures</label>
                <input
                  id="probe-min-failures"
                  type="number"
                  min="1"
                  bind:value={probeMinFailures}
                  oninput={markDirty}
                  class="field-mono"
                />
                <span class="hint">Failure threshold.</span>
              </div>
              <div class="fieldrow">
                <label for="probe-attempts">Attempts</label>
                <input
                  id="probe-attempts"
                  type="number"
                  min="1"
                  bind:value={probeAttempts}
                  oninput={markDirty}
                  class="field-mono"
                />
              </div>
            </div>

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: var(--sp-2);">
              <div class="fieldrow">
                <label for="probe-max-concurrent">Max Concurrent</label>
                <input
                  id="probe-max-concurrent"
                  type="number"
                  min="1"
                  bind:value={probeMaxConcurrent}
                  oninput={markDirty}
                  class="field-mono"
                />
              </div>
              <div class="fieldrow">
                <label for="probe-endpoint-timeout">Handshake Timeout (ms)</label>
                <input
                  id="probe-endpoint-timeout"
                  type="number"
                  min="50"
                  bind:value={probeEndpointCheckTimeoutMs}
                  oninput={markDirty}
                  class="field-mono"
                />
              </div>
            </div>

            <div class="fieldrow">
              <label class="switch">
                <input type="checkbox" bind:checked={probeSkipWhenActive} onchange={markDirty} />
                <span>Skip probe when active</span>
              </label>
              <span class="hint">Bypasses background probe if user traffic is actively flowing through uplink.</span>
            </div>

            <div class="fieldrow">
              <label class="switch">
                <input type="checkbox" bind:checked={probeEndpointCheck} onchange={markDirty} />
                <span>Pre-check endpoint TCP handshake</span>
              </label>
            </div>

            <div class="fieldrow">
              <label class="switch">
                <input type="checkbox" bind:checked={probeWsEnabled} onchange={markDirty} />
                <span>Enable WebSocket probes</span>
              </label>
            </div>

            <div class="fieldrow">
              <label for="probe-http-urls">HTTP Probe URLs</label>
              <textarea
                id="probe-http-urls"
                rows="3"
                placeholder="http://cp.cloudflare.com/generate_204"
                bind:value={probeHttpUrls}
                oninput={markDirty}
                class="field-mono"
              ></textarea>
              <span class="hint">Plain HTTP URLs rotated per probe cycle (one per line, http:// only).</span>
            </div>

            <div class="fieldrow">
              <label for="probe-tls-targets">TLS Probe Targets ([outline.probe.tls])</label>
              <textarea
                id="probe-tls-targets"
                rows="5"
                placeholder="www.instagram.com&#10;www.youtube.com&#10;www.googletagmanager.com&#10;www.googlevideo.com&#10;api.telegram.org"
                bind:value={probeTlsTargets}
                oninput={markDirty}
                class="field-mono"
              ></textarea>
              <span class="hint">Host/SNI endpoints tested via pure TLS handshake (one per line, port 443 default).</span>
            </div>

            <div style="display: grid; grid-template-columns: 2fr 1fr; gap: var(--sp-2);">
              <div class="fieldrow">
                <label for="probe-dns-server">DNS Probe Server</label>
                <input
                  id="probe-dns-server"
                  type="text"
                  placeholder="1.1.1.1"
                  bind:value={probeDnsServer}
                  oninput={markDirty}
                  class="field-mono"
                />
              </div>
              <div class="fieldrow">
                <label for="probe-dns-port">Port</label>
                <input
                  id="probe-dns-port"
                  type="number"
                  min="1"
                  max="65535"
                  bind:value={probeDnsPort}
                  oninput={markDirty}
                  class="field-mono"
                />
              </div>
            </div>

            <div class="fieldrow">
              <label for="probe-dns-name">DNS Test Query Domain</label>
              <input
                id="probe-dns-name"
                type="text"
                placeholder="example.com"
                bind:value={probeDnsName}
                oninput={markDirty}
                class="field-mono"
              />
            </div>
          </div>
        </div>

        <!-- 2. Local Ingress & Interface (SOCKS5 / TUN) -->
        <div class="panel" style="padding: var(--sp-4);">
          <h3 style="font-size: 14px; font-weight: 600; margin-top: 0; margin-bottom: var(--sp-2);">
            Ingress & Network Interfaces
          </h3>
          <p class="desc" style="margin-top: 0; margin-bottom: var(--sp-3); font-size: 12px; color: var(--fg-muted);">
            SOCKS5 listening proxy socket and virtual TUN network adapter on this device.
          </p>

          <div style="display: flex; flex-direction: column; gap: var(--sp-3);">
            <div class="fieldrow">
              <label for="socks5-listen">SOCKS5 Listen Address</label>
              <input
                id="socks5-listen"
                type="text"
                placeholder="127.0.0.1:1080"
                bind:value={socks5Listen}
                oninput={markDirty}
                class="field-mono"
              />
              <span class="hint">Local client connection binding address.</span>
            </div>

            <div class="fieldrow">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: var(--sp-1);">
                <span style="font-weight: 500; font-size: 13px;">SOCKS5 Users ([[socks5.users]])</span>
                <button
                  type="button"
                  class="btn btn-secondary btn-sm"
                  onclick={addSocks5User}
                  style="padding: 2px 8px; font-size: 11px;"
                >
                  + Add User
                </button>
              </div>
              <span class="hint" style="margin-bottom: var(--sp-2); display: block;">
                Authenticated proxy users (RFC 1929). If empty, SOCKS5 accepts unauthenticated connections.
              </span>

              {#if socks5Users.length === 0}
                <div style="padding: var(--sp-2); font-size: 12px; color: var(--fg-muted); background: var(--bg-soft); border-radius: var(--rad-sm); border: 1px dashed var(--border-soft);">
                  No users configured (anonymous access allowed).
                </div>
              {:else}
                <div style="display: flex; flex-direction: column; gap: var(--sp-2);">
                  {#each socks5Users as user (user.id)}
                    <div style="display: grid; grid-template-columns: 1fr 1fr auto; gap: var(--sp-2); align-items: center;">
                      <div>
                        <input
                          type="text"
                          placeholder="Username"
                          bind:value={user.username}
                          oninput={markDirty}
                          class="field-mono"
                          style="font-size: 12px;"
                        />
                      </div>
                      <div>
                        <input
                          type="password"
                          placeholder={user.has_password ? '•••••••• (configured)' : 'Password'}
                          bind:value={user.password}
                          oninput={markDirty}
                          class="field-mono"
                          style="font-size: 12px;"
                        />
                      </div>
                      <button
                        type="button"
                        class="btn btn-ghost btn-sm"
                        style="color: var(--danger, #f43f5e); padding: 4px 8px;"
                        onclick={() => removeSocks5User(user.id)}
                        title="Remove user"
                      >
                        ✕
                      </button>
                    </div>
                  {/each}
                </div>
              {/if}
            </div>

            <div style="border-top: 1px solid var(--border-soft); margin: var(--sp-1) 0;"></div>

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: var(--sp-2);">
              <div class="fieldrow">
                <label for="tun-name">TUN Device Name</label>
                <input
                  id="tun-name"
                  type="text"
                  placeholder="tun0"
                  bind:value={tunName}
                  oninput={markDirty}
                  class="field-mono"
                />
              </div>
              <div class="fieldrow">
                <label for="tun-mtu">MTU</label>
                <input
                  id="tun-mtu"
                  type="number"
                  min="576"
                  max="65535"
                  bind:value={tunMtu}
                  oninput={markDirty}
                  class="field-mono"
                />
              </div>
            </div>

            <div style="display: grid; grid-template-columns: 1fr 1fr 1fr 1fr; gap: var(--sp-2);">
              <div class="fieldrow">
                <label for="tun-max-flows">Max Flows</label>
                <input
                  id="tun-max-flows"
                  type="number"
                  min="64"
                  bind:value={tunMaxFlows}
                  oninput={markDirty}
                  class="field-mono"
                />
              </div>
              <div class="fieldrow">
                <label for="tun-carrier-flows">Carrier Flows</label>
                <input
                  id="tun-carrier-flows"
                  type="number"
                  min="16"
                  bind:value={tunMaxCarrierFlows}
                  oninput={markDirty}
                  class="field-mono"
                />
              </div>
              <div class="fieldrow">
                <label for="tun-idle-timeout">Idle TTL (s)</label>
                <input
                  id="tun-idle-timeout"
                  type="number"
                  min="1"
                  bind:value={tunIdleTimeoutSecs}
                  oninput={markDirty}
                  class="field-mono"
                />
              </div>
              <div class="fieldrow">
                <label for="tun-max-dials">Max Dials</label>
                <input
                  id="tun-max-dials"
                  type="number"
                  min="1"
                  bind:value={tunMaxConcurrentUpstreamDials}
                  oninput={markDirty}
                  class="field-mono"
                />
              </div>
            </div>

            <div class="fieldrow">
              <label class="switch">
                <input type="checkbox" bind:checked={tunRouteBySni} onchange={markDirty} />
                <span>Route by SNI (Domain routing)</span>
              </label>
            </div>

            <div class="fieldrow">
              <label class="switch">
                <input type="checkbox" bind:checked={tunSniffQuic} onchange={markDirty} />
                <span>Sniff QUIC SNI from Initial packets</span>
              </label>
            </div>

            <div class="fieldrow">
              <label class="switch">
                <input type="checkbox" bind:checked={tunIpsecBypass} onchange={markDirty} />
                <span>IPsec tunnel bypass</span>
              </label>
            </div>

            <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: var(--sp-2);">
              <div class="fieldrow">
                <label class="switch">
                  <input type="checkbox" bind:checked={tunGso} onchange={markDirty} />
                  <span>GSO</span>
                </label>
              </div>
              <div class="fieldrow">
                <label class="switch">
                  <input type="checkbox" bind:checked={tunGro} onchange={markDirty} />
                  <span>GRO</span>
                </label>
              </div>
              <div class="fieldrow">
                <label class="switch">
                  <input type="checkbox" bind:checked={tunUso} onchange={markDirty} />
                  <span>USO</span>
                </label>
              </div>
            </div>
          </div>
        </div>

        <!-- 3. Carrier & Obfuscation Policies -->
        <div class="panel" style="padding: var(--sp-4);">
          <h3 style="font-size: 14px; font-weight: 600; margin-top: 0; margin-bottom: var(--sp-2);">
            Dial & Obfuscation Policies
          </h3>
          <p class="desc" style="margin-top: 0; margin-bottom: var(--sp-3); font-size: 12px; color: var(--fg-muted);">
            Dial timeouts, TLS client fingerprint diversification, and padding against DPI traffic analysis.
          </p>

          <div style="display: flex; flex-direction: column; gap: var(--sp-3);">
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: var(--sp-2);">
              <div class="fieldrow">
                <label for="dial-timeout">Dial Timeout (s)</label>
                <input
                  id="dial-timeout"
                  type="number"
                  min="1"
                  bind:value={dialTimeoutSecs}
                  oninput={markDirty}
                  class="field-mono"
                />
              </div>
              <div class="fieldrow">
                <label for="fingerprint-profile">TLS Fingerprint Profile</label>
                <select id="fingerprint-profile" bind:value={fingerprintProfile} onchange={markDirty}>
                  <option value="off">off (vanilla rustls)</option>
                  <option value="stable">stable (browser)</option>
                  <option value="random">random (per dial)</option>
                </select>
              </div>
            </div>

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: var(--sp-2);">
              <div class="fieldrow">
                <label for="direct-fwmark">Direct Fwmark</label>
                <input
                  id="direct-fwmark"
                  type="number"
                  placeholder="e.g. 18"
                  bind:value={directFwmark}
                  oninput={markDirty}
                  class="field-mono"
                />
                <span class="hint">SO_MARK for direct bypass.</span>
              </div>
              <div class="fieldrow">
                <label class="switch" style="margin-top: 24px;">
                  <input type="checkbox" bind:checked={preferPublicIpv6Src} onchange={markDirty} />
                  <span>Prefer public IPv6</span>
                </label>
              </div>
            </div>

            <div style="border-top: 1px solid var(--border-soft); margin: var(--sp-1) 0;"></div>

            <div class="fieldrow">
              <label class="switch">
                <input type="checkbox" bind:checked={paddingEnabled} onchange={markDirty} />
                <span>Enable wire padding obfuscation</span>
              </label>
              <span class="hint">Pads transport chunks with variable sizes to disguise flow fingerprints.</span>
            </div>

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: var(--sp-2);">
              <div class="fieldrow">
                <label for="padding-min">Min Padding (bytes)</label>
                <input
                  id="padding-min"
                  type="number"
                  min="0"
                  max="65535"
                  bind:value={paddingMinBytes}
                  oninput={markDirty}
                  class="field-mono"
                />
              </div>
              <div class="fieldrow">
                <label for="padding-max">Max Padding (bytes)</label>
                <input
                  id="padding-max"
                  type="number"
                  min="0"
                  max="65535"
                  bind:value={paddingMaxBytes}
                  oninput={markDirty}
                  class="field-mono"
                />
              </div>
            </div>

            <div class="fieldrow">
              <label class="switch">
                <input
                  type="checkbox"
                  bind:checked={paddingCover}
                  onchange={markDirty}
                />
                <span>Generate background cover traffic</span>
              </label>
            </div>

            <div class="fieldrow">
              <label class="switch">
                <input
                  type="checkbox"
                  bind:checked={paddingReactToThrottle}
                  onchange={markDirty}
                />
                <span>React dynamically to provider throttling</span>
              </label>
            </div>

            {#if paddingCover}
              <div style="display: grid; grid-template-columns: 1fr 1fr; gap: var(--sp-2);">
                <div class="fieldrow">
                  <label for="cover-min">Cover Jitter Min (ms)</label>
                  <input
                    id="cover-min"
                    type="number"
                    min="0"
                    bind:value={paddingCoverJitterMinMs}
                    oninput={markDirty}
                    class="field-mono"
                  />
                </div>
                <div class="fieldrow">
                  <label for="cover-max">Cover Jitter Max (ms)</label>
                  <input
                    id="cover-max"
                    type="number"
                    min="0"
                    bind:value={paddingCoverJitterMaxMs}
                    oninput={markDirty}
                    class="field-mono"
                  />
                </div>
              </div>
            {/if}
          </div>
        </div>

        <!-- 4. Advanced Transport & Timeouts -->
        <div class="panel" style="padding: var(--sp-4);">
          <h3 style="font-size: 14px; font-weight: 600; margin-top: 0; margin-bottom: var(--sp-2);">
            Transport Windows & Timeouts
          </h3>
          <p class="desc" style="margin-top: 0; margin-bottom: var(--sp-3); font-size: 12px; color: var(--fg-muted);">
            Stream receive windows and keepalive timeouts for HTTP/3 (QUIC), HTTP/2, and native TCP carrier streams.
          </p>

          <div style="display: flex; flex-direction: column; gap: var(--sp-3);">
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: var(--sp-2);">
              <div class="fieldrow">
                <label for="quic-stream-win">QUIC Stream Window (B)</label>
                <input
                  id="quic-stream-win"
                  type="number"
                  min="65536"
                  bind:value={quicStreamReceiveWindow}
                  oninput={markDirty}
                  class="field-mono"
                />
              </div>
              <div class="fieldrow">
                <label for="quic-conn-win">QUIC Conn Window (B)</label>
                <input
                  id="quic-conn-win"
                  type="number"
                  min="65536"
                  bind:value={quicReceiveWindow}
                  oninput={markDirty}
                  class="field-mono"
                />
              </div>
            </div>

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: var(--sp-2);">
              <div class="fieldrow">
                <label for="quic-keepalive">QUIC Keepalive (s)</label>
                <input
                  id="quic-keepalive"
                  type="number"
                  min="1"
                  bind:value={quicKeepaliveSecs}
                  oninput={markDirty}
                  class="field-mono"
                />
              </div>
              <div class="fieldrow">
                <label for="quic-idle">QUIC Idle Timeout (s)</label>
                <input
                  id="quic-idle"
                  type="number"
                  min="1"
                  bind:value={quicIdleTimeoutSecs}
                  oninput={markDirty}
                  class="field-mono"
                />
              </div>
            </div>

            <div style="border-top: 1px solid var(--border-soft); margin: var(--sp-1) 0;"></div>

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: var(--sp-2);">
              <div class="fieldrow">
                <label for="h2-stream-win">H2 Stream Window (B)</label>
                <input
                  id="h2-stream-win"
                  type="number"
                  min="65536"
                  bind:value={h2StreamWindowSize}
                  oninput={markDirty}
                  class="field-mono"
                />
              </div>
              <div class="fieldrow">
                <label for="h2-conn-win">H2 Conn Window (B)</label>
                <input
                  id="h2-conn-win"
                  type="number"
                  min="65536"
                  bind:value={h2ConnWindowSize}
                  oninput={markDirty}
                  class="field-mono"
                />
              </div>
            </div>

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: var(--sp-2);">
              <div class="fieldrow">
                <label for="h2-keepalive">H2 Keepalive (s)</label>
                <input
                  id="h2-keepalive"
                  type="number"
                  min="1"
                  bind:value={h2KeepaliveIntervalSecs}
                  oninput={markDirty}
                  class="field-mono"
                />
              </div>
              <div class="fieldrow">
                <label for="h2-timeout">H2 Ping Timeout (s)</label>
                <input
                  id="h2-timeout"
                  type="number"
                  min="1"
                  bind:value={h2KeepaliveTimeoutSecs}
                  oninput={markDirty}
                  class="field-mono"
                />
              </div>
            </div>

            <div style="border-top: 1px solid var(--border-soft); margin: var(--sp-1) 0;"></div>

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: var(--sp-2);">
              <div class="fieldrow">
                <label for="tcp-socks-idle">SOCKS Idle (s)</label>
                <input
                  id="tcp-socks-idle"
                  type="number"
                  min="1"
                  bind:value={tcpSocksUpstreamIdleSecs}
                  oninput={markDirty}
                  class="field-mono"
                />
              </div>
              <div class="fieldrow">
                <label for="tcp-direct-idle">Direct Idle (s)</label>
                <input
                  id="tcp-direct-idle"
                  type="number"
                  min="1"
                  bind:value={tcpDirectIdleSecs}
                  oninput={markDirty}
                  class="field-mono"
                />
              </div>
            </div>

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: var(--sp-2);">
              <div class="fieldrow">
                <label for="tcp-upstream-resp">Upstream Resp (s)</label>
                <input
                  id="tcp-upstream-resp"
                  type="number"
                  min="1"
                  bind:value={tcpUpstreamResponseSecs}
                  oninput={markDirty}
                  class="field-mono"
                />
              </div>
              <div class="fieldrow">
                <label for="tcp-eof-downstream">Post-Client EOF (s)</label>
                <input
                  id="tcp-eof-downstream"
                  type="number"
                  min="1"
                  bind:value={tcpPostClientEofDownstreamSecs}
                  oninput={markDirty}
                  class="field-mono"
                />
              </div>
            </div>
          </div>
        </div>
      </div>
    {/if}
  {/if}
</section>
