<script lang="ts">
  import type { AppSettings } from '../lib/types';

  interface Props {
    isOpen: boolean;
    theme: 'dark' | 'light';
    settings: AppSettings;
    onClose: () => void;
    onSaveSettings: (settings: AppSettings) => Promise<void>;
  }

  let {
    isOpen = false,
    theme = 'dark',
    settings,
    onClose,
    onSaveSettings,
  }: Props = $props();

  let localMode = $state<'socks5' | 'tun'>('socks5');
  let localTcpOnly = $state(false);
  let localSocksPort = $state(1080);
  let localAutostart = $state(false);
  let localStartMinimized = $state(false);
  let isSaving = $state(false);
  let saveSuccess = $state(false);
  let errorMessage = $state<string | null>(null);

  // Synchronize local draft with current settings when modal opens
  $effect(() => {
    if (isOpen && settings) {
      localMode = settings.proxyMode || 'socks5';
      localTcpOnly = !!settings.tcpOnly;
      localSocksPort = settings.socksPort || 1080;
      localAutostart = !!settings.autostart;
      localStartMinimized = !!settings.startMinimized;
      saveSuccess = false;
      errorMessage = null;
    }
  });

  async function handleSave() {
    isSaving = true;
    errorMessage = null;
    saveSuccess = false;
    try {
      const port = Number(localSocksPort);
      if (isNaN(port) || port < 1 || port > 65535) {
        throw new Error('Укажите корректный порт (1–65535)');
      }
      await onSaveSettings({
        proxyMode: localMode,
        tcpOnly: localTcpOnly,
        socksPort: port,
        autostart: localAutostart,
        startMinimized: localStartMinimized,
      });
      saveSuccess = true;
      setTimeout(() => {
        saveSuccess = false;
        onClose();
      }, 500);
    } catch (err: any) {
      errorMessage = typeof err === 'string' ? err : err?.message || 'Не удалось сохранить настройки';
    } finally {
      isSaving = false;
    }
  }
</script>

{#if isOpen}
  <!-- Backdrop -->
  <div
    class="fixed inset-0 z-50 flex items-center justify-center p-3 backdrop-blur-sm transition-all duration-200 select-none
      {theme === 'dark' ? 'bg-black/60' : 'bg-neutral-900/40'}"
    role="dialog"
    aria-modal="true"
  >
    <!-- Modal Card -->
    <div
      class="w-full max-w-[370px] max-h-[92vh] flex flex-col rounded-[26px] border shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150
        {theme === 'dark'
          ? 'bg-neutral-900 border-neutral-700/80 text-neutral-100 shadow-black/80'
          : 'bg-white border-neutral-300 text-neutral-900 shadow-neutral-500/30'}"
    >
      <!-- Header -->
      <div class="flex items-center justify-between px-5 py-3.5 border-b {theme === 'dark' ? 'border-neutral-800' : 'border-neutral-200'}">
        <div class="flex items-center gap-2">
          <!-- Gear Icon -->
          <div class="w-7 h-7 rounded-full flex items-center justify-center {theme === 'dark' ? 'bg-neutral-800 text-neutral-300' : 'bg-neutral-100 text-neutral-700'}">
            <svg class="w-4 h-4 fill-current" viewBox="0 0 20 20">
              <path fill-rule="evenodd" d="M11.49 3.17c-.38-1.56-2.6-1.56-2.98 0a1.532 1.532 0 01-2.286.948c-1.372-.836-2.942.734-2.106 2.106.54.886.061 2.042-.947 2.287-1.561.379-1.561 2.6 0 2.978a1.532 1.532 0 01.947 2.287c-.836 1.372.734 2.942 2.106 2.106a1.532 1.532 0 012.287.947c.379 1.561 2.6 1.561 2.978 0a1.533 1.533 0 012.287-.947c1.372.836 2.942-.734 2.106-2.106a1.533 1.533 0 01.947-2.287c1.561-.379 1.561-2.6 0-2.978a1.532 1.532 0 01-.947-2.287c.836-1.372-.734-2.942-2.106-2.106a1.532 1.532 0 01-2.287-.947zM10 13a3 3 0 100-6 3 3 0 000 6z" clip-rule="evenodd" />
            </svg>
          </div>
          <h2 class="text-sm font-bold tracking-tight">Настройки приложения</h2>
        </div>
        <button
          type="button"
          onclick={onClose}
          class="w-7 h-7 rounded-full flex items-center justify-center transition-colors cursor-pointer
            {theme === 'dark' ? 'hover:bg-neutral-800 text-neutral-400 hover:text-white' : 'hover:bg-neutral-100 text-neutral-500 hover:text-black'}"
          title="Закрыть"
        >
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>

      <!-- Content Body -->
      <div class="flex-1 overflow-y-auto px-5 py-4 space-y-4">
        <!-- 1. Proxy Mode Block -->
        <div class="space-y-2">
          <div class="flex items-center justify-between">
            <span class="text-xs font-bold {theme === 'dark' ? 'text-neutral-200' : 'text-neutral-800'}">
              Режим перехвата трафика
            </span>
            <span class="text-[10px] font-mono {theme === 'dark' ? 'text-neutral-400' : 'text-neutral-500'}">
              {localMode === 'socks5' ? 'Системный прокси' : 'TUN-адаптер'}
            </span>
          </div>

          <div class="grid grid-cols-2 gap-2">
            <!-- SOCKS5 Button -->
            <button
              type="button"
              onclick={() => localMode = 'socks5'}
              class="p-2.5 rounded-2xl border text-left transition-all cursor-pointer flex flex-col justify-between
                {localMode === 'socks5'
                  ? 'bg-emerald-600/15 border-emerald-500 text-emerald-400 font-bold shadow-sm shadow-emerald-950/20'
                  : (theme === 'dark' ? 'bg-neutral-800/40 border-neutral-700/60 text-neutral-400 hover:bg-neutral-800/70' : 'bg-neutral-50 border-neutral-200 text-neutral-600 hover:bg-neutral-100')}"
            >
              <div class="flex items-center justify-between">
                <span class="text-xs">SOCKS5</span>
                {#if localMode === 'socks5'}
                  <span class="w-2 h-2 rounded-full bg-emerald-400"></span>
                {/if}
              </div>
              <span class="text-[10px] opacity-75 font-normal mt-1">Прокси системы</span>
            </button>

            <!-- TUN Button -->
            <button
              type="button"
              onclick={() => localMode = 'tun'}
              class="p-2.5 rounded-2xl border text-left transition-all cursor-pointer flex flex-col justify-between
                {localMode === 'tun'
                  ? 'bg-emerald-600/15 border-emerald-500 text-emerald-400 font-bold shadow-sm shadow-emerald-950/20'
                  : (theme === 'dark' ? 'bg-neutral-800/40 border-neutral-700/60 text-neutral-400 hover:bg-neutral-800/70' : 'bg-neutral-50 border-neutral-200 text-neutral-600 hover:bg-neutral-100')}"
            >
              <div class="flex items-center justify-between">
                <span class="text-xs">TUN (VPN)</span>
                {#if localMode === 'tun'}
                  <span class="w-2 h-2 rounded-full bg-emerald-400"></span>
                {/if}
              </div>
              <span class="text-[10px] opacity-75 font-normal mt-1">Весь трафик ПК</span>
            </button>
          </div>

          <p class="text-[10px] leading-relaxed {theme === 'dark' ? 'text-neutral-400' : 'text-neutral-500'}">
            {#if localMode === 'socks5'}
              Направляет трафик браузеров через локальный порт 127.0.0.1:{localSocksPort}.
            {:else}
              Создает виртуальный адаптер Wintun и перехватывает 100% сетевого трафика.
            {/if}
          </p>
        </div>

        <!-- 2. TCP Only Switch -->
        <div class="p-3 rounded-2xl border space-y-1.5
          {theme === 'dark' ? 'bg-neutral-800/40 border-neutral-700/60' : 'bg-neutral-50 border-neutral-200'}">
          <label class="flex items-center justify-between cursor-pointer">
            <div>
              <span class="text-xs font-semibold block {theme === 'dark' ? 'text-neutral-200' : 'text-neutral-800'}">
                Только TCP (без H3/QUIC)
              </span>
              <span class="text-[10px] block {theme === 'dark' ? 'text-neutral-400' : 'text-neutral-500'}">
                Использует TCP/H2 при блокировках UDP
              </span>
            </div>
            <input
              type="checkbox"
              bind:checked={localTcpOnly}
              class="w-4 h-4 accent-emerald-500 cursor-pointer rounded"
            />
          </label>
        </div>

        <!-- 3. SOCKS5 Port -->
        <div class="p-3 rounded-2xl border space-y-1.5
          {theme === 'dark' ? 'bg-neutral-800/40 border-neutral-700/60' : 'bg-neutral-50 border-neutral-200'}">
          <div class="flex items-center justify-between">
            <label for="socksPortInput" class="text-xs font-semibold {theme === 'dark' ? 'text-neutral-200' : 'text-neutral-800'}">
              Порт SOCKS5
            </label>
            <input
              id="socksPortInput"
              type="number"
              min="1"
              max="65535"
              bind:value={localSocksPort}
              class="w-20 px-2 py-1 text-xs text-right rounded-lg border font-mono outline-none
                {theme === 'dark'
                  ? 'bg-neutral-900 border-neutral-700 text-white focus:border-emerald-500'
                  : 'bg-white border-neutral-300 text-neutral-900 focus:border-emerald-600'}"
            />
          </div>
          <span class="text-[10px] block {theme === 'dark' ? 'text-neutral-400' : 'text-neutral-500'}">
            Локальный адрес: 127.0.0.1:{localSocksPort}
          </span>
        </div>

        <!-- 4. Windows Startup & Behavior -->
        <div class="p-3 rounded-2xl border space-y-2.5
          {theme === 'dark' ? 'bg-neutral-800/40 border-neutral-700/60' : 'bg-neutral-50 border-neutral-200'}">
          <span class="text-xs font-semibold block {theme === 'dark' ? 'text-neutral-200' : 'text-neutral-800'}">
            Запуск и поведение в Windows
          </span>

          <label class="flex items-center justify-between cursor-pointer">
            <span class="text-xs {theme === 'dark' ? 'text-neutral-300' : 'text-neutral-700'}">
              Запускать при старте системы
            </span>
            <input
              type="checkbox"
              bind:checked={localAutostart}
              class="w-4 h-4 accent-emerald-500 cursor-pointer rounded"
            />
          </label>

          <label class="flex items-center justify-between cursor-pointer">
            <span class="text-xs {theme === 'dark' ? 'text-neutral-300' : 'text-neutral-700'}">
              Запускать свёрнутым в трей
            </span>
            <input
              type="checkbox"
              bind:checked={localStartMinimized}
              class="w-4 h-4 accent-emerald-500 cursor-pointer rounded"
            />
          </label>
        </div>

        {#if errorMessage}
          <p class="text-xs text-rose-400 font-medium">{errorMessage}</p>
        {/if}
        {#if saveSuccess}
          <p class="text-xs text-emerald-400 font-medium">Настройки успешно сохранены!</p>
        {/if}
      </div>

      <!-- Footer Buttons -->
      <div class="px-5 py-3 border-t flex items-center justify-end gap-2 {theme === 'dark' ? 'border-neutral-800 bg-neutral-900/60' : 'border-neutral-200 bg-neutral-50'}">
        <button
          type="button"
          onclick={onClose}
          class="px-3.5 py-1.5 text-xs font-semibold rounded-xl transition-colors cursor-pointer
            {theme === 'dark' ? 'hover:bg-neutral-800 text-neutral-300' : 'hover:bg-neutral-200 text-neutral-700'}"
        >
          Отмена
        </button>
        <button
          type="button"
          onclick={handleSave}
          disabled={isSaving}
          class="px-4 py-1.5 text-xs font-bold rounded-xl bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white transition-all cursor-pointer shadow"
        >
          {#if isSaving}
            Сохранение...
          {:else}
            Сохранить
          {/if}
        </button>
      </div>
    </div>
  </div>
{/if}
