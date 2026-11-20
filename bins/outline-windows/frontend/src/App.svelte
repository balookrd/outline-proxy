<script lang="ts">
  import { onMount } from 'svelte';
  import Header from './components/Header.svelte';
  import ServersList from './components/ServersList.svelte';
  import SettingsModal from './components/SettingsModal.svelte';
  import LogViewerModal from './components/LogViewerModal.svelte';
  import {
    getStatus,
    connect,
    disconnect,
    getProfiles,
    addProfile,
    removeProfile,
    selectProfile,
    renameProfile,
    getLogs,
    getSettings,
    updateSettings,
    updateSubscription,
    onStatusChanged,
    onLogMessage,
    onProfilesUpdated,
    onSettingsUpdated,
    onNavigate,
  } from './lib/api';
  import type {
    ServerProfile,
    ProcessState,
    ConnectionStatusResponse,
    AppSettings,
  } from './lib/types';
  import {
    isProcessRunning,
    isProcessStarting,
    isProcessStopping,
  } from './lib/types';

  // Appearance Theme ('dark' | 'light')
  let theme = $state<'dark' | 'light'>(
    (typeof localStorage !== 'undefined' && (localStorage.getItem('outline_theme') as 'dark' | 'light')) || 'dark',
  );

  function toggleTheme() {
    theme = theme === 'dark' ? 'light' : 'dark';
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem('outline_theme', theme);
    }
  }

  // Application Data States
  let status = $state<ConnectionStatusResponse | null>(null);
  let profiles = $state<ServerProfile[]>([]);
  let settings = $state<AppSettings>({
    proxyMode: 'socks5',
    tcpOnly: false,
    socksPort: 1080,
    autostart: false,
    startMinimized: false,
  });
  let logs = $state<string[]>([]);

  // Modals Visibility
  let showServers = $state(false);
  let showSettings = $state(false);
  let showLogs = $state(false);

  // Connection Interaction State
  let actionLoading = $state(false);
  let sessionDuration = $state('00:00:00');
  let sessionStartTimestamp = $state<number | null>(null);
  let trafficUpBytes = $state(0);
  let trafficDownBytes = $state(0);

  // Derived Values
  let currentState = $derived<ProcessState>(status?.state || { status: 'stopped' });
  let isRunning = $derived(isProcessRunning(currentState));
  let isStarting = $derived(isProcessStarting(currentState));
  let isStopping = $derived(isProcessStopping(currentState));
  let isBusy = $derived(isStarting || isStopping || actionLoading);

  let activeProfile = $derived.by<ServerProfile | null>(() => {
    const activeId = status?.activeProfileId || status?.active_profile_id;
    if (activeId) {
      const found = profiles.find((p) => p.id === activeId);
      if (found) return found;
    }
    return profiles[0] || null;
  });

  let activeProfileName = $derived.by<string>(() => {
    if (activeProfile) return activeProfile.name || 'Сервер без имени';
    return status?.activeProfileName || status?.active_profile_name || 'Нет серверов';
  });

  let activeProfileBadge = $derived.by<string>(() => {
    if (!activeProfile) return 'SOCKS5';
    if (activeProfile.transport === 'subscription' || activeProfile.configUrl || activeProfile.config_url) {
      return 'Подписка';
    }
    const t = (activeProfile.transport || '').toLowerCase();
    if (t.includes('vless')) return 'VLESS';
    if (t.includes('ss')) return 'Shadowsocks';
    return activeProfile.transport.toUpperCase();
  });

  // Dynamic Carrier / Protocol computation matching macOS parity (e.g. ss/ws/h2, vless/xhttp/h3, ws/h3, xhttp/h2, ss/tcp)
  const carrierInfo = $derived.by(() => {
    if (!isRunning || !activeProfile) {
      return { tcp: '—', udp: '—' };
    }

    const isTcpOnly = settings.tcpOnly || activeProfile.tcpOnly;
    const fullConfig = ((activeProfile.cachedToml || '') + (activeProfile.link || '')).toLowerCase();

    // Determine primary protocol family: vless or ss
    let family = 'vless';
    const vlessIdx = fullConfig.indexOf('vless://');
    const ssIdx = fullConfig.indexOf('ss://');
    if (vlessIdx !== -1 && (ssIdx === -1 || vlessIdx < ssIdx)) {
      family = 'vless';
    } else if (ssIdx !== -1 && (vlessIdx === -1 || ssIdx < vlessIdx)) {
      family = 'ss';
    } else if ((activeProfile.transport || '').toLowerCase().includes('ss') || (activeProfile.transport || '').toLowerCase().includes('shadowsocks')) {
      family = 'ss';
    } else {
      family = 'vless';
    }

    // Determine carrier HTTP version: h3, h2, h1
    let version = isTcpOnly ? 'h2' : 'h3';
    if (fullConfig.includes('alpn=h3') || fullConfig.includes('xhttp_h3') || fullConfig.includes('ws_h3')) {
      version = isTcpOnly ? 'h2' : 'h3';
    } else if (fullConfig.includes('alpn=h2') || fullConfig.includes('http/2') || fullConfig.includes('xhttp_h2') || fullConfig.includes('ws_h2')) {
      version = 'h2';
    } else if (
      fullConfig.includes('http/1.1') ||
      fullConfig.includes('ws_h1') ||
      fullConfig.includes('xhttp_h1') ||
      fullConfig.includes('alpn=http%2f1.1') ||
      fullConfig.includes('alpn=http/1.1')
    ) {
      version = 'h1';
    }

    // Determine submode carrier: xhttp, ws, or match family (ignoring substring 'ws' in 'outline-ws-rust')
    let subMode = family;
    const xhttpMatches = [
      fullConfig.indexOf('type=xhttp'),
      fullConfig.indexOf('xhttp_h'),
      fullConfig.indexOf('transport = "xhttp'),
      fullConfig.indexOf("transport = 'xhttp"),
    ].filter((p) => p !== -1);

    const wsMatches = [
      fullConfig.indexOf('type=ws'),
      fullConfig.indexOf('ws_h'),
      fullConfig.indexOf('protocol=ws'),
      fullConfig.indexOf('transport = "ws'),
      fullConfig.indexOf("transport = 'ws"),
    ].filter((p) => p !== -1);

    const firstXhttp = xhttpMatches.length > 0 ? Math.min(...xhttpMatches) : -1;
    const firstWs = wsMatches.length > 0 ? Math.min(...wsMatches) : -1;

    if (firstXhttp !== -1 && (firstWs === -1 || firstXhttp < firstWs)) {
      subMode = 'xhttp';
    } else if (firstWs !== -1 && (firstXhttp === -1 || firstWs < firstXhttp)) {
      subMode = 'ws';
    }

    // Inspect live logs for active dialed connection mode (e.g. mode="ws_h2" or mode="xhttp_h3")
    for (let i = logs.length - 1; i >= Math.max(0, logs.length - 60); i--) {
      const line = logs[i];
      if (line.includes('conn_life') || line.includes('connection opened') || line.includes('mode="')) {
        const modeMatch = line.match(/mode="([^"]+)"/);
        if (modeMatch) {
          const rawMode = modeMatch[1].toLowerCase();
          const parts = rawMode.split('_');
          if (parts.length === 2) {
            subMode = parts[0];
            version = isTcpOnly ? 'h2' : parts[1];
          }
          if (line.includes('ss://') || line.includes('shadowsocks') || line.includes(':pss') || line.includes('pss')) {
            family = 'ss';
          } else if (line.includes('vless://') || line.includes('pvless') || line.includes('pxhttp')) {
            family = 'vless';
          }
          break;
        }
      }
    }

    let tcpString = '';
    let udpString = '';

    const famUpper = family.toUpperCase();
    const subUpper = subMode.toUpperCase();
    const verUpper = version.toUpperCase();

    if (subMode !== family) {
      // e.g. VLESS/XHTTP/H3 or SS/WS/H2
      tcpString = `${famUpper}/${subUpper}/${verUpper}`;
      udpString = isTcpOnly ? '—' : `${famUpper}/${subUpper}/${verUpper}`;
    } else if (family === 'ss') {
      tcpString = 'SS/TCP';
      udpString = isTcpOnly ? '—' : 'SS/UDP';
    } else {
      tcpString = `VLESS/${verUpper}`;
      udpString = isTcpOnly ? '—' : `VLESS/${verUpper}`;
    }

    return { tcp: tcpString, udp: udpString };
  });

  // Traffic and Duration Live Timer
  $effect(() => {
    let timer: any = null;

    if (isRunning) {
      if (sessionStartTimestamp === null) {
        const uptime = status?.uptimeSecs || status?.uptime_secs || 0;
        sessionStartTimestamp = Date.now() - uptime * 1000;
        trafficUpBytes = 0;
        trafficDownBytes = 0;
      }

      timer = setInterval(() => {
        if (!sessionStartTimestamp) return;
        const diffSecs = Math.floor((Date.now() - sessionStartTimestamp) / 1000);
        const hrs = String(Math.floor(diffSecs / 3600)).padStart(2, '0');
        const mins = String(Math.floor((diffSecs % 3600) / 60)).padStart(2, '0');
        const secs = String(diffSecs % 60).padStart(2, '0');
        sessionDuration = `${hrs}:${mins}:${secs}`;
        // Live polling of system network traffic
        refreshStatus();
      }, 1000);
    } else {
      sessionStartTimestamp = null;
      sessionDuration = '00:00:00';
      trafficUpBytes = 0;
      trafficDownBytes = 0;
    }

    return () => {
      if (timer) clearInterval(timer);
    };
  });

  function formatBytes(bytes: number): string {
    if (bytes <= 0) return '0 Б';
    const k = 1024;
    const sizes = ['Б', 'КБ', 'МБ', 'ГБ'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
  }

  // Data Loading Helpers
  async function refreshStatus() {
    try {
      status = await getStatus();
      if (status) {
        const tx = status.txBytes ?? status.tx_bytes ?? 0;
        const rx = status.rxBytes ?? status.rx_bytes ?? 0;
        if (isRunning) {
          trafficUpBytes = tx;
          trafficDownBytes = rx;
        }
      }
    } catch (e) {
      console.warn('Failed to get status:', e);
    }
  }

  async function refreshProfiles() {
    try {
      profiles = await getProfiles();
    } catch (e) {
      console.warn('Failed to get profiles:', e);
    }
  }

  async function refreshSettings() {
    try {
      settings = await getSettings();
    } catch (e) {
      console.warn('Failed to get settings:', e);
    }
  }

  async function refreshLogs() {
    try {
      logs = await getLogs();
    } catch (e) {
      console.warn('Failed to get logs:', e);
    }
  }

  // Toggle Connection Action
  async function handleToggleConnection() {
    if (isBusy) return;
    actionLoading = true;
    try {
      if (isRunning) {
        await disconnect();
      } else {
        await connect(activeProfile?.id);
      }
      await refreshStatus();
    } catch (err: any) {
      alert(`Ошибка подключения: ${typeof err === 'string' ? err : err?.message || 'Неизвестная ошибка'}`);
    } finally {
      actionLoading = false;
    }
  }

  // Direct Mode Change (SOCKS5 / TUN)
  async function handleModeSelect(mode: 'socks5' | 'tun') {
    if (settings.proxyMode === mode) return;
    try {
      const updated = { ...settings, proxyMode: mode };
      settings = updated;
      await updateSettings(updated);
      await refreshStatus();
    } catch (err: any) {
      console.error('Failed to update proxy mode:', err);
    }
  }

  // Profile actions
  async function handleSelectProfile(id: string) {
    try {
      await selectProfile(id);
      await refreshProfiles();
      await refreshStatus();
    } catch (err: any) {
      console.error('Failed to select profile:', err);
      throw err;
    }
  }

  async function handleAddProfile(link: string) {
    try {
      await addProfile(link);
      await refreshProfiles();
      await refreshStatus();
    } catch (err: any) {
      console.error('Failed to add profile:', err);
      throw err;
    }
  }

  async function handleRemoveProfile(id: string) {
    try {
      await removeProfile(id);
      await refreshProfiles();
      await refreshStatus();
    } catch (err: any) {
      console.error('Failed to remove profile:', err);
      throw err;
    }
  }

  async function handleRenameProfile(id: string, name: string) {
    try {
      await renameProfile(id, name);
      await refreshProfiles();
      await refreshStatus();
    } catch (err: any) {
      console.error('Failed to rename profile:', err);
      throw err;
    }
  }

  async function handleUpdateSubscription(id: string) {
    try {
      await updateSubscription(id);
      await refreshProfiles();
      await refreshStatus();
    } catch (err: any) {
      console.error('Failed to update subscription:', err);
      throw err;
    }
  }

  async function handleSaveSettings(newSettings: AppSettings) {
    try {
      await updateSettings(newSettings);
      settings = newSettings;
      await refreshStatus();
    } catch (err: any) {
      console.error('Failed to save settings:', err);
      throw err;
    }
  }

  function handleClearLogs() {
    logs = [];
  }

  // Setup Lifecycle
  onMount(() => {
    refreshStatus();
    refreshProfiles();
    refreshSettings();
    refreshLogs();

    const unlistens: Array<() => void> = [];

    // Real-time Listeners
    onStatusChanged((newState) => {
      if (status) {
        status = { ...status, state: newState };
      } else {
        refreshStatus();
      }
    }).then((un) => unlistens.push(un));

    onLogMessage((line) => {
      logs = [...logs.slice(-999), line];
    }).then((un) => unlistens.push(un));

    onProfilesUpdated(() => {
      refreshProfiles();
      refreshStatus();
    }).then((un) => unlistens.push(un));

    onSettingsUpdated(() => {
      refreshSettings();
      refreshStatus();
    }).then((un) => unlistens.push(un));

    onNavigate((view) => {
      if (view === 'settings') showSettings = true;
      if (view === 'logs') showLogs = true;
    }).then((un) => unlistens.push(un));

    return () => {
      unlistens.forEach((un) => un());
    };
  });
</script>

<main
  class="relative flex flex-col h-screen w-full transition-colors duration-200 select-none overflow-hidden p-4 justify-between
    {theme === 'dark' ? 'bg-[#0E1118] text-white' : 'bg-[#F8FAFC] text-[#0F172A]'}"
>
  <!-- 1. Header Banner -->
  <Header {theme} onToggleTheme={toggleTheme} />

  <!-- 2. Status Card (with World Map & Status Ring) -->
  <section
    class="relative rounded-[28px] border overflow-hidden transition-all duration-200 p-3.5 flex flex-col gap-2.5 shadow-sm cursor-pointer
      {theme === 'dark'
        ? 'bg-[#161C26] border-white/10 hover:border-white/20'
        : 'bg-[#EDF2F7] border-[#CBD5E1] hover:border-slate-400'}"
    onclick={() => showServers = true}
    role="button"
    tabindex="0"
    onkeydown={(e) => {
      if (e.key === 'Enter' || e.key === ' ') showServers = true;
    }}
  >
    <!-- Background World Map (Dotted with opacity & theme-matched mask) -->
    <div
      class="absolute inset-0 pointer-events-none"
      style="
        -webkit-mask-image: url('/ic_worldmap.png');
        mask-image: url('/ic_worldmap.png');
        -webkit-mask-repeat: no-repeat;
        mask-repeat: no-repeat;
        -webkit-mask-position: center;
        mask-position: center;
        -webkit-mask-size: contain;
        mask-size: contain;
        background-color: {theme === 'dark' ? '#FFFFFF' : '#0F172A'};
        opacity: {theme === 'dark' ? 0.22 : 0.14};
      "
    ></div>

    <!-- Top Row: Ring Emblem + Server Details + Chevron -->
    <div class="relative z-10 flex items-center justify-between gap-3">
      <!-- Status Ring Emblem (82x82) -->
      <div class="relative w-[82px] h-[82px] flex-shrink-0 flex items-center justify-center">
        <!-- Brand Ring Image with pulse on connected -->
        <img
          src={theme === 'dark' ? '/brand_ring_dark.png' : '/brand_ring_light.png'}
          alt="Ring"
          class="w-full h-full object-contain transition-transform duration-500
            {isRunning ? 'scale-105' : 'opacity-90'}"
        />
        <!-- Inner Status Dot -->
        <div class="absolute inset-0 flex items-center justify-center">
          <div
            class="w-3.5 h-3.5 rounded-full transition-all duration-300
              {isRunning
                ? 'bg-[#059669] shadow-md shadow-emerald-500/50 animate-pulse'
                : (isBusy ? 'bg-[#D9B706]' : 'bg-[#64748B]')}"
          ></div>
        </div>
      </div>

      <!-- Info Column -->
      <div class="flex-1 min-w-0 flex flex-col justify-center">
        <!-- Status Label with Dot (macOS title case: • Отключено / • Подключено) -->
        <div class="flex items-center gap-1.5">
          <span
            class="w-2 h-2 rounded-full
              {isRunning ? 'bg-[#059669] animate-pulse' : (isBusy ? 'bg-[#D9B706]' : 'bg-[#64748B]')}"
          ></span>
          <span class="text-xs font-semibold
            {isRunning ? 'text-[#059669]' : (isBusy ? 'text-[#D9B706]' : 'text-[#64748B]')}">
            {#if isRunning}
              Подключено
            {:else if isStarting}
              Подключение...
            {:else if isStopping}
              Отключение...
            {:else}
              Отключено
            {/if}
          </span>
        </div>

        <!-- Server Title (Huge bold font matching macOS) -->
        <h2 class="text-xl font-bold truncate mt-0.5 tracking-tight {theme === 'dark' ? 'text-white' : 'text-[#0F172A]'}">
          {activeProfileName}
        </h2>

        <!-- Subtitle with Type and Active Badge -->
        <div class="flex items-center gap-2 mt-1">
          <span class="text-xs {theme === 'dark' ? 'text-[#94A3B8]' : 'text-[#475569]'}">
            {activeProfileBadge}
          </span>
          <span class="px-2 py-0.5 rounded-full text-[11px] font-semibold
            {theme === 'dark' ? 'bg-[#1E293B] text-[#93C5FD]' : 'bg-[#DBE6FE] text-[#1E3A8A]'}">
            Активна
          </span>
        </div>

        <!-- Refresh subtitle matching macOS -->
        <div class="text-[11px] text-[#64748B] mt-1">
          Обновлено недавно · каждые 12 ч
        </div>
      </div>

      <!-- Chevron Button -->
      <div class="text-[#64748B] hover:text-[#0F172A] dark:hover:text-white transition-colors pl-1">
        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M9 5l7 7-7 7" />
        </svg>
      </div>
    </div>

    <!-- Stats Strip (Duration, Traffic, Protocol) - strictly when running (macOS parity) -->
    {#if isRunning}
      <div class="relative z-10 pt-2.5 border-t grid grid-cols-[1fr_1.05fr_1.45fr] gap-1 text-left
        {theme === 'dark' ? 'border-white/10' : 'border-[#CBD5E1]'}">
        <!-- 1. Duration Column -->
        <div class="flex flex-col">
          <div class="flex items-center gap-1 text-[9px] font-bold tracking-wider uppercase {theme === 'dark' ? 'text-[#94A3B8]' : 'text-[#64748B]'}">
            <svg class="w-2.5 h-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            Длительность
          </div>
          <span class="text-xs font-mono font-bold mt-0.5 leading-tight {theme === 'dark' ? 'text-white' : 'text-[#0F172A]'}">
            {sessionDuration}
          </span>
          <span class="text-[9px] text-[#64748B] leading-none mt-0.5 pb-0.5">чч:мм:сс</span>
        </div>

        <!-- 2. Traffic Column -->
        <div class="flex flex-col border-x px-2 {theme === 'dark' ? 'border-white/10' : 'border-[#CBD5E1]'}">
          <div class="flex items-center gap-1 text-[9px] font-bold tracking-wider uppercase {theme === 'dark' ? 'text-[#94A3B8]' : 'text-[#64748B]'}">
            <svg class="w-2.5 h-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" />
            </svg>
            Трафик
          </div>
          <div class="flex items-center gap-1 mt-0.5 text-[10px] font-mono">
            <span class="text-[#059669] dark:text-[#22C55E] font-bold">↑</span>
            <span class="{theme === 'dark' ? 'text-[#CBD5E1]' : 'text-[#0F172A]'}">{formatBytes(trafficUpBytes)}</span>
          </div>
          <div class="flex items-center gap-1 text-[10px] font-mono">
            <span class="text-[#1E5EE8] dark:text-[#60A5FA] font-bold">↓</span>
            <span class="{theme === 'dark' ? 'text-[#CBD5E1]' : 'text-[#0F172A]'}">{formatBytes(trafficDownBytes)}</span>
          </div>
        </div>

        <!-- 3. Protocol Column -->
        <div class="flex flex-col pl-1 min-w-0">
          <div class="flex items-center gap-1 text-[9px] font-bold tracking-wider uppercase {theme === 'dark' ? 'text-[#94A3B8]' : 'text-[#64748B]'}">
            <svg class="w-2.5 h-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            Протокол
          </div>
          <div class="flex items-center gap-1 mt-0.5 text-[10.5px] min-w-0">
            <span class="text-[9px] font-semibold px-1 rounded bg-neutral-700/50 text-neutral-300 shrink-0">TCP</span>
            <span class="text-[9.5px] font-mono truncate {theme === 'dark' ? 'text-[#CBD5E1]' : 'text-[#0F172A]'}" title={carrierInfo.tcp}>
              {carrierInfo.tcp}
            </span>
          </div>
          <div class="flex items-center gap-1 text-[10.5px] min-w-0">
            <span class="text-[9px] font-semibold px-1 rounded bg-neutral-700/50 text-neutral-300 shrink-0">UDP</span>
            <span class="text-[9.5px] font-mono truncate {theme === 'dark' ? 'text-[#CBD5E1]' : 'text-[#0F172A]'}" title={carrierInfo.udp}>
              {carrierInfo.udp}
            </span>
          </div>
        </div>
      </div>
    {/if}
  </section>

  <!-- 3. Operational Mode Selector Card -->
  <section
    class="rounded-[18px] border p-3 flex flex-col items-center gap-2 transition-colors
      {theme === 'dark' ? 'bg-[#161C26] border-white/10' : 'bg-[#EDF2F7] border-[#CBD5E1]'}"
  >
    <div class="flex items-center gap-1.5 text-xs font-semibold {theme === 'dark' ? 'text-white' : 'text-[#0F172A]'}">
      <span>🌐</span>
      <span>Режим перехвата трафика:</span>
    </div>

    <!-- Toggle Buttons Row -->
    <div class="w-full max-w-[280px] grid grid-cols-2 gap-2 p-1">
      <button
        type="button"
        onclick={() => handleModeSelect('socks5')}
        class="h-9 px-3 rounded-2xl text-xs font-semibold transition-all cursor-pointer text-center
          {settings.proxyMode === 'socks5'
            ? (theme === 'dark' ? 'bg-[#2563EB] text-white shadow-sm' : 'bg-[#1E5EE8] text-white shadow-sm')
            : (theme === 'dark' ? 'bg-[#20293A] border border-white/10 text-white/75 hover:text-white' : 'bg-white border border-[#CBD5E1] text-[#475569] hover:text-[#0F172A]')}"
      >
        SOCKS5 (Прокси)
      </button>
      <button
        type="button"
        onclick={() => handleModeSelect('tun')}
        class="h-9 px-3 rounded-2xl text-xs font-semibold transition-all cursor-pointer text-center
          {settings.proxyMode === 'tun'
            ? (theme === 'dark' ? 'bg-[#2563EB] text-white shadow-sm' : 'bg-[#1E5EE8] text-white shadow-sm')
            : (theme === 'dark' ? 'bg-[#20293A] border border-white/10 text-white/75 hover:text-white' : 'bg-white border border-[#CBD5E1] text-[#475569] hover:text-[#0F172A]')}"
      >
        TUN (VPN)
      </button>
    </div>

    <p class="text-[11px] text-center max-w-[310px] leading-snug {theme === 'dark' ? 'text-[#94A3B8]' : 'text-[#475569]'}">
      {#if settings.proxyMode === 'socks5'}
        Системный SOCKS5-прокси 127.0.0.1:{settings.socksPort} для браузеров и приложений.
      {:else}
        L3 TUN VPN: туннель в 1 клик без пароля (DNS, игры, все приложения)
      {/if}
    </p>
  </section>

  <!-- 4. Action Row (Add Server & Big Connect Pill Button) -->
  <section class="grid grid-cols-2 gap-3 w-full">
    <!-- Add Server Button -->
    <button
      type="button"
      onclick={() => showServers = true}
      class="h-12 rounded-full border flex items-center justify-center gap-2 font-semibold text-[13.5px] transition-all cursor-pointer active:scale-98
        {theme === 'dark'
          ? 'bg-[#161C26] hover:bg-[#20293A] border-white/12 text-white shadow-sm'
          : 'bg-white hover:bg-neutral-50 border-[#CBD5E1] text-[#0F172A] shadow-sm'}"
    >
      <svg class="w-4 h-4 fill-current {theme === 'dark' ? 'text-white' : 'text-[#0F172A]'}" viewBox="0 0 20 20">
        <path fill-rule="evenodd" d="M10 3a1 1 0 011 1v5h5a1 1 0 110 2h-5v5a1 1 0 11-2 0v-5H4a1 1 0 110-2h5V4a1 1 0 011-1z" clip-rule="evenodd" />
      </svg>
      <span>Добавить сервер</span>
    </button>

    <!-- Big Connect/Disconnect Action Button -->
    <button
      type="button"
      onclick={handleToggleConnection}
      disabled={isBusy}
      class="h-12 rounded-full flex items-center justify-center gap-2 font-bold text-[14px] transition-all cursor-pointer shadow-md active:scale-98 disabled:opacity-50
        {isRunning
          ? 'bg-[#DC2626] hover:bg-[#B91C1C] text-white shadow-red-500/25'
          : (theme === 'dark'
              ? 'bg-[#C7D7FD] hover:bg-[#B3C8FC] text-[#0F172A]'
              : 'bg-[#1E5EE8] hover:bg-[#164EC2] text-white shadow-[#1E5EE8]/25')}"
    >
      {#if isBusy}
        <svg class="w-4 h-4 animate-spin text-current" fill="none" viewBox="0 0 24 24">
          <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
          <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"></path>
        </svg>
        <span>{isStarting ? 'Запуск...' : 'Остановка...'}</span>
      {:else if isRunning}
        <svg class="w-4 h-4 fill-current" viewBox="0 0 20 20">
          <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8 7a1 1 0 00-1 1v4a1 1 0 001 1h4a1 1 0 001-1V8a1 1 0 00-1-1H8z" clip-rule="evenodd" />
        </svg>
        <span>Отключить</span>
      {:else}
        <svg class="w-4 h-4 fill-current" viewBox="0 0 20 20">
          <path fill-rule="evenodd" d="M10 2a1 1 0 011 1v7a1 1 0 11-2 0V3a1 1 0 011-1zm4.95 2.05a1 1 0 010 1.414A6.974 6.974 0 0017 10a7 7 0 11-14 0c0-1.933.784-3.683 2.05-4.95a1 1 0 111.414 1.414A4.974 4.974 0 005 10a5 5 0 1010 0 4.974 4.974 0 00-1.464-3.536 1 1 0 010-1.414z" clip-rule="evenodd" />
        </svg>
        <span>Подключить</span>
      {/if}
    </button>
  </section>

  <!-- 5. Quick Links (matching 2 bubbles on macOS) -->
  <section
    class="rounded-[24px] border p-4 flex items-center justify-around transition-colors
      {theme === 'dark' ? 'bg-[#161C26] border-white/10' : 'bg-[#EDF2F7] border-[#CBD5E1]'}"
  >
    <!-- 1. Logs button -->
    <button
      type="button"
      onclick={() => showLogs = true}
      class="flex flex-col items-center gap-2 group cursor-pointer"
    >
      <div
        class="w-[52px] h-[52px] rounded-full flex items-center justify-center transition-all duration-150 group-hover:scale-105
          {theme === 'dark'
            ? 'bg-[#20293A] text-[#60A5FA] group-hover:bg-[#28354D]'
            : 'bg-[#DBE6FE] text-[#1E5EE8] group-hover:bg-[#C7D7FD]'}"
      >
        <svg class="w-6 h-6 fill-none stroke-current" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
        </svg>
      </div>
      <span class="text-xs font-semibold {theme === 'dark' ? 'text-white' : 'text-[#0F172A]'}">
        Журнал (логи)
      </span>
    </button>

    <!-- 2. Settings button -->
    <button
      type="button"
      onclick={() => showSettings = true}
      class="flex flex-col items-center gap-2 group cursor-pointer"
    >
      <div
        class="w-[52px] h-[52px] rounded-full flex items-center justify-center transition-all duration-150 group-hover:scale-105
          {theme === 'dark'
            ? 'bg-[#20293A] text-[#60A5FA] group-hover:bg-[#28354D]'
            : 'bg-[#DBE6FE] text-[#1E5EE8] group-hover:bg-[#C7D7FD]'}"
      >
        <svg class="w-6 h-6 fill-current" viewBox="0 0 20 20">
          <path fill-rule="evenodd" d="M11.49 3.17c-.38-1.56-2.6-1.56-2.98 0a1.532 1.532 0 01-2.286.948c-1.372-.836-2.942.734-2.106 2.106.54.886.061 2.042-.947 2.287-1.561.379-1.561 2.6 0 2.978a1.532 1.532 0 01.947 2.287c-.836 1.372.734 2.942 2.106 2.106a1.532 1.532 0 012.287.947c.379 1.561 2.6 1.561 2.978 0a1.533 1.533 0 012.287-.947c1.372.836 2.942-.734 2.106-2.106a1.533 1.533 0 01.947-2.287c1.561-.379 1.561-2.6 0-2.978a1.532 1.532 0 01-.947-2.287c.836-1.372-.734-2.942-2.106-2.106a1.532 1.532 0 01-2.287-.947zM10 13a3 3 0 100-6 3 3 0 000 6z" clip-rule="evenodd" />
        </svg>
      </div>
      <span class="text-xs font-semibold {theme === 'dark' ? 'text-white' : 'text-[#0F172A]'}">
        Настройки
      </span>
    </button>
  </section>

  <!-- 6. Version Footer -->
  <footer class="text-center text-[11px] text-[#64748B] hover:text-[#0F172A] dark:hover:text-white transition-colors cursor-pointer py-0.5">
    nightly · vnightly (638262e3)
  </footer>

  <!-- Modal Components -->
  <ServersList
    isOpen={showServers}
    {theme}
    {profiles}
    activeProfileId={status?.activeProfileId || status?.active_profile_id || null}
    onClose={() => showServers = false}
    onSelectProfile={handleSelectProfile}
    onAddProfile={handleAddProfile}
    onRemoveProfile={handleRemoveProfile}
    onUpdateSubscription={handleUpdateSubscription}
    onRenameProfile={handleRenameProfile}
  />

  <SettingsModal
    isOpen={showSettings}
    {theme}
    {settings}
    onClose={() => showSettings = false}
    onSaveSettings={handleSaveSettings}
  />

  <LogViewerModal
    isOpen={showLogs}
    {theme}
    {logs}
    onClose={() => showLogs = false}
    onClearLogs={handleClearLogs}
  />
</main>
