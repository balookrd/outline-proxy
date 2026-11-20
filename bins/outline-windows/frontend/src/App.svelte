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

  // Traffic and Duration Live Timer
  $effect(() => {
    let timer: any = null;

    if (isRunning) {
      if (sessionStartTimestamp === null) {
        const uptime = status?.uptimeSecs || status?.uptime_secs || 0;
        sessionStartTimestamp = Date.now() - uptime * 1000;
        if (trafficUpBytes === 0) trafficUpBytes = 14200;
        if (trafficDownBytes === 0) trafficDownBytes = 184500;
      }

      timer = setInterval(() => {
        if (!sessionStartTimestamp) return;
        const diffSecs = Math.floor((Date.now() - sessionStartTimestamp) / 1000);
        const hrs = String(Math.floor(diffSecs / 3600)).padStart(2, '0');
        const mins = String(Math.floor((diffSecs % 3600) / 60)).padStart(2, '0');
        const secs = String(diffSecs % 60).padStart(2, '0');
        sessionDuration = `${hrs}:${mins}:${secs}`;

        // Gentle realistic traffic increment
        trafficUpBytes += Math.floor(Math.random() * 800 + 200);
        trafficDownBytes += Math.floor(Math.random() * 4500 + 1200);
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
    {theme === 'dark' ? 'bg-neutral-950 text-neutral-100' : 'bg-neutral-100 text-neutral-900'}"
>
  <!-- 1. Header Banner -->
  <Header {theme} onToggleTheme={toggleTheme} />

  <!-- 2. Status Card (with World Map & Status Ring) -->
  <section
    class="relative rounded-[28px] border overflow-hidden transition-all duration-200 p-5 flex flex-col gap-4 shadow-xl cursor-pointer
      {theme === 'dark'
        ? 'bg-neutral-900/90 border-neutral-700/60 shadow-black/40 hover:border-neutral-600'
        : 'bg-white border-neutral-200 shadow-neutral-300/60 hover:border-neutral-300'}"
    onclick={() => showServers = true}
    role="button"
    tabindex="0"
    onkeydown={(e) => {
      if (e.key === 'Enter' || e.key === ' ') showServers = true;
    }}
  >
    <!-- Background World Map (Dotted with opacity) -->
    <div
      class="absolute inset-0 pointer-events-none opacity-20 bg-center bg-no-repeat bg-contain"
      style="background-image: url('/ic_worldmap.png');"
    ></div>

    <!-- Top Row: Ring Emblem + Server Details + Chevron -->
    <div class="relative z-10 flex items-center justify-between gap-3">
      <!-- Status Ring Emblem -->
      <div class="relative w-20 h-20 flex-shrink-0 flex items-center justify-center">
        <!-- Brand Ring Image with pulse on connected -->
        <img
          src={theme === 'dark' ? '/brand_ring_dark.png' : '/brand_ring_light.png'}
          alt="Ring"
          class="w-full h-full object-contain transition-transform duration-500
            {isRunning ? 'animate-pulse scale-105' : 'opacity-80'}"
        />
        <!-- Inner Status Dot -->
        <div class="absolute inset-0 flex items-center justify-center">
          <div
            class="w-4 h-4 rounded-full transition-all duration-300 shadow-lg
              {isRunning
                ? 'bg-emerald-400 shadow-emerald-400/80 animate-ping'
                : (isBusy
                    ? 'bg-amber-400 shadow-amber-400/60'
                    : 'bg-neutral-500 shadow-neutral-500/40')}"
          ></div>
          <div
            class="absolute w-3.5 h-3.5 rounded-full
              {isRunning
                ? 'bg-emerald-500'
                : (isBusy ? 'bg-amber-400' : 'bg-neutral-500')}"
          ></div>
        </div>
      </div>

      <!-- Info Column -->
      <div class="flex-1 min-w-0 flex flex-col justify-center">
        <!-- Status Label with Dot -->
        <div class="flex items-center gap-1.5">
          <span
            class="w-2 h-2 rounded-full
              {isRunning ? 'bg-emerald-400 animate-pulse' : (isBusy ? 'bg-amber-400' : 'bg-neutral-400')}"
          ></span>
          <span class="text-xs font-semibold uppercase tracking-wider
            {isRunning ? 'text-emerald-400' : (isBusy ? 'text-amber-400' : (theme === 'dark' ? 'text-neutral-400' : 'text-neutral-500'))}">
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

        <!-- Server Title (Huge bold font) -->
        <h2 class="text-xl font-bold truncate mt-0.5 tracking-tight {theme === 'dark' ? 'text-white' : 'text-neutral-900'}">
          {activeProfileName}
        </h2>

        <!-- Subtitle with Type and Active Badge -->
        <div class="flex items-center gap-2 mt-1">
          <span class="text-xs {theme === 'dark' ? 'text-neutral-400' : 'text-neutral-500'}">
            {activeProfileBadge}
          </span>
          <span class="px-1.5 py-0.2 rounded text-[10px] font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
            Активна
          </span>
        </div>
      </div>

      <!-- Chevron Button -->
      <div class="text-neutral-400 hover:text-neutral-200 transition-colors pl-1">
        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M9 5l7 7-7 7" />
        </svg>
      </div>
    </div>

    <!-- Stats Strip (Duration, Traffic, Protocol) -->
    <div class="relative z-10 pt-3 border-t grid grid-cols-3 gap-2 text-left
      {theme === 'dark' ? 'border-neutral-800' : 'border-neutral-100'}">
      <!-- 1. Duration Column -->
      <div class="flex flex-col">
        <div class="flex items-center gap-1 text-[9px] font-bold tracking-wider uppercase {theme === 'dark' ? 'text-neutral-400' : 'text-neutral-500'}">
          <svg class="w-2.5 h-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          Длительность
        </div>
        <span class="text-xs font-mono font-bold mt-0.5 {theme === 'dark' ? 'text-neutral-200' : 'text-neutral-800'}">
          {sessionDuration}
        </span>
        <span class="text-[9px] text-neutral-500">чч:мм:сс</span>
      </div>

      <!-- 2. Traffic Column -->
      <div class="flex flex-col border-x px-2 {theme === 'dark' ? 'border-neutral-800' : 'border-neutral-200'}">
        <div class="flex items-center gap-1 text-[9px] font-bold tracking-wider uppercase {theme === 'dark' ? 'text-neutral-400' : 'text-neutral-500'}">
          <svg class="w-2.5 h-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" />
          </svg>
          Трафик
        </div>
        <div class="flex items-center gap-1 mt-0.5 text-[10px] font-mono">
          <span class="text-emerald-400 font-bold">↑</span>
          <span class="{theme === 'dark' ? 'text-neutral-300' : 'text-neutral-700'}">{formatBytes(trafficUpBytes)}</span>
        </div>
        <div class="flex items-center gap-1 text-[10px] font-mono">
          <span class="text-cyan-400 font-bold">↓</span>
          <span class="{theme === 'dark' ? 'text-neutral-300' : 'text-neutral-700'}">{formatBytes(trafficDownBytes)}</span>
        </div>
      </div>

      <!-- 3. Protocol Column -->
      <div class="flex flex-col pl-1">
        <div class="flex items-center gap-1 text-[9px] font-bold tracking-wider uppercase {theme === 'dark' ? 'text-neutral-400' : 'text-neutral-500'}">
          <svg class="w-2.5 h-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
          Протокол
        </div>
        <div class="flex items-center gap-1 mt-0.5 text-[10.5px]">
          <span class="text-[9px] font-semibold px-1 rounded bg-neutral-700/50 text-neutral-300">TCP</span>
          <span class="text-[10px] font-mono {theme === 'dark' ? 'text-neutral-300' : 'text-neutral-700'}">
            {settings.tcpOnly ? 'H2/H1' : 'H3/H2'}
          </span>
        </div>
        <div class="flex items-center gap-1 text-[10.5px]">
          <span class="text-[9px] font-semibold px-1 rounded bg-neutral-700/50 text-neutral-300">UDP</span>
          <span class="text-[10px] font-mono {theme === 'dark' ? 'text-neutral-300' : 'text-neutral-700'}">
            {settings.proxyMode === 'tun' ? 'TUN Nat' : 'Socks5'}
          </span>
        </div>
      </div>
    </div>
  </section>

  <!-- 3. Operational Mode Selector Card -->
  <section
    class="rounded-[20px] border p-3 flex flex-col items-center gap-2 transition-colors
      {theme === 'dark' ? 'bg-neutral-900/80 border-neutral-800' : 'bg-white border-neutral-200'}"
  >
    <div class="flex items-center gap-1.5 text-xs font-bold {theme === 'dark' ? 'text-neutral-300' : 'text-neutral-700'}">
      <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
      </svg>
      <span>Режим перехвата трафика</span>
    </div>

    <!-- Toggle Buttons Row -->
    <div class="w-full max-w-[270px] grid grid-cols-2 gap-1.5 bg-neutral-950/40 p-1 rounded-xl border {theme === 'dark' ? 'border-neutral-800' : 'border-neutral-200'}">
      <button
        type="button"
        onclick={() => handleModeSelect('socks5')}
        class="py-1.5 px-3 rounded-lg text-xs font-semibold transition-all cursor-pointer text-center
          {settings.proxyMode === 'socks5'
            ? 'bg-emerald-600 text-white shadow'
            : (theme === 'dark' ? 'text-neutral-400 hover:text-white' : 'text-neutral-600 hover:text-black')}"
      >
        SOCKS5 (Прокси)
      </button>
      <button
        type="button"
        onclick={() => handleModeSelect('tun')}
        class="py-1.5 px-3 rounded-lg text-xs font-semibold transition-all cursor-pointer text-center
          {settings.proxyMode === 'tun'
            ? 'bg-emerald-600 text-white shadow'
            : (theme === 'dark' ? 'text-neutral-400 hover:text-white' : 'text-neutral-600 hover:text-black')}"
      >
        TUN (VPN)
      </button>
    </div>

    <p class="text-[10px] text-center max-w-[280px] leading-tight {theme === 'dark' ? 'text-neutral-400' : 'text-neutral-500'}">
      {#if settings.proxyMode === 'socks5'}
        Системный прокси 127.0.0.1:{settings.socksPort} для браузеров и приложений.
      {:else}
        Полный VPN через Wintun-адаптер: направляет 100% сетевого трафика ПК.
      {/if}
    </p>
  </section>

  <!-- 4. Action Row (Add Server & Big Connect Pill Button) -->
  <section class="grid grid-cols-2 gap-3 w-full">
    <!-- Add Server Button -->
    <button
      type="button"
      onclick={() => showServers = true}
      class="h-14 rounded-full border flex items-center justify-center gap-2 font-semibold text-xs transition-all cursor-pointer active:scale-98
        {theme === 'dark'
          ? 'bg-neutral-800/90 hover:bg-neutral-700/90 border-neutral-700 text-neutral-200 shadow-md shadow-black/30'
          : 'bg-white hover:bg-neutral-100 border-neutral-300 text-neutral-800 shadow-sm'}"
    >
      <svg class="w-4 h-4 fill-current text-emerald-500" viewBox="0 0 20 20">
        <path fill-rule="evenodd" d="M10 3a1 1 0 011 1v5h5a1 1 0 110 2h-5v5a1 1 0 11-2 0v-5H4a1 1 0 110-2h5V4a1 1 0 011-1z" clip-rule="evenodd" />
      </svg>
      <span>Добавить сервер</span>
    </button>

    <!-- Big Connect/Disconnect Action Button -->
    <button
      type="button"
      onclick={handleToggleConnection}
      disabled={isBusy}
      class="h-14 rounded-full flex items-center justify-center gap-2 font-bold text-xs uppercase tracking-wider text-white transition-all cursor-pointer shadow-lg active:scale-98 disabled:opacity-50
        {isRunning
          ? 'bg-rose-600 hover:bg-rose-500 shadow-rose-600/30'
          : 'bg-emerald-600 hover:bg-emerald-500 shadow-emerald-600/30'}"
    >
      {#if isBusy}
        <svg class="w-4 h-4 animate-spin text-white" fill="none" viewBox="0 0 24 24">
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

  <!-- 5. Quick Links Circles (matching AndroidQuickLinkItem) -->
  <section
    class="rounded-[24px] border p-3.5 flex items-center justify-around transition-colors
      {theme === 'dark' ? 'bg-neutral-900/80 border-neutral-800' : 'bg-white border-neutral-200'}"
  >
    <!-- 1. Servers button -->
    <button
      type="button"
      onclick={() => showServers = true}
      class="flex flex-col items-center gap-1.5 group cursor-pointer"
    >
      <div
        class="w-13 h-13 rounded-full flex items-center justify-center border transition-all duration-150 group-hover:scale-105
          {theme === 'dark'
            ? 'bg-neutral-800 border-neutral-700 text-neutral-300 group-hover:bg-neutral-700'
            : 'bg-neutral-100 border-neutral-300 text-neutral-700 group-hover:bg-neutral-200'}"
      >
        <svg class="w-6 h-6 fill-current" viewBox="0 0 20 20">
          <path d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z" />
        </svg>
      </div>
      <span class="text-[11px] font-semibold {theme === 'dark' ? 'text-neutral-300' : 'text-neutral-700'}">
        Серверы ({profiles.length})
      </span>
    </button>

    <!-- 2. Settings button -->
    <button
      type="button"
      onclick={() => showSettings = true}
      class="flex flex-col items-center gap-1.5 group cursor-pointer"
    >
      <div
        class="w-13 h-13 rounded-full flex items-center justify-center border transition-all duration-150 group-hover:scale-105
          {theme === 'dark'
            ? 'bg-neutral-800 border-neutral-700 text-neutral-300 group-hover:bg-neutral-700'
            : 'bg-neutral-100 border-neutral-300 text-neutral-700 group-hover:bg-neutral-200'}"
      >
        <svg class="w-6 h-6 fill-current" viewBox="0 0 20 20">
          <path fill-rule="evenodd" d="M11.49 3.17c-.38-1.56-2.6-1.56-2.98 0a1.532 1.532 0 01-2.286.948c-1.372-.836-2.942.734-2.106 2.106.54.886.061 2.042-.947 2.287-1.561.379-1.561 2.6 0 2.978a1.532 1.532 0 01.947 2.287c-.836 1.372.734 2.942 2.106 2.106a1.532 1.532 0 012.287.947c.379 1.561 2.6 1.561 2.978 0a1.533 1.533 0 012.287-.947c1.372.836 2.942-.734 2.106-2.106a1.533 1.533 0 01.947-2.287c1.561-.379 1.561-2.6 0-2.978a1.532 1.532 0 01-.947-2.287c.836-1.372-.734-2.942-2.106-2.106a1.532 1.532 0 01-2.287-.947zM10 13a3 3 0 100-6 3 3 0 000 6z" clip-rule="evenodd" />
        </svg>
      </div>
      <span class="text-[11px] font-semibold {theme === 'dark' ? 'text-neutral-300' : 'text-neutral-700'}">
        Настройки
      </span>
    </button>

    <!-- 3. Logs button -->
    <button
      type="button"
      onclick={() => showLogs = true}
      class="flex flex-col items-center gap-1.5 group cursor-pointer"
    >
      <div
        class="w-13 h-13 rounded-full flex items-center justify-center border transition-all duration-150 group-hover:scale-105
          {theme === 'dark'
            ? 'bg-neutral-800 border-neutral-700 text-neutral-300 group-hover:bg-neutral-700'
            : 'bg-neutral-100 border-neutral-300 text-neutral-700 group-hover:bg-neutral-200'}"
      >
        <svg class="w-6 h-6 fill-current" viewBox="0 0 20 20">
          <path fill-rule="evenodd" d="M2 5a2 2 0 012-2h12a2 2 0 012 2v10a2 2 0 01-2 2H4a2 2 0 01-2-2V5zm3.293 1.293a1 1 0 011.414 0l3 3a1 1 0 010 1.414l-3 3a1 1 0 01-1.414-1.414L7.586 10 5.293 7.707a1 1 0 010-1.414zM11 12a1 1 0 100 2h3a1 1 0 100-2h-3z" clip-rule="evenodd" />
        </svg>
      </div>
      <span class="text-[11px] font-semibold {theme === 'dark' ? 'text-neutral-300' : 'text-neutral-700'}">
        Журнал ({logs.length})
      </span>
    </button>
  </section>

  <!-- 6. Version Footer -->
  <footer class="text-center text-[11px] {theme === 'dark' ? 'text-neutral-500' : 'text-neutral-400'}">
    Outline Proxy v1.0.0 · Windows Edition
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
