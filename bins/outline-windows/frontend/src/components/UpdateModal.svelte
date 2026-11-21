<script lang="ts">
  import type { UpdateInfo } from '../lib/types';

  interface Props {
    isOpen?: boolean;
    theme?: 'dark' | 'light';
    update?: UpdateInfo | null;
    isInstalling?: boolean;
    progressPercent?: number;
    error?: string | null;
    onInstall: () => void;
    onClose: () => void;
  }

  let {
    isOpen = false,
    theme = 'dark',
    update = null,
    isInstalling = false,
    progressPercent = 0,
    error = null,
    onInstall,
    onClose,
  }: Props = $props();

  function handleKeyDown(e: KeyboardEvent) {
    if (e.key === 'Escape' && isOpen && !isInstalling) {
      onClose();
    }
  }
</script>

<svelte:window onkeydown={handleKeyDown} />

{#if isOpen}
  <!-- Backdrop -->
  <div
    class="fixed inset-0 z-50 flex items-center justify-center p-3 backdrop-blur-sm transition-all duration-200 select-none
      {theme === 'dark' ? 'bg-black/60' : 'bg-neutral-900/40'}"
  >
    <!-- Modal Card -->
    <div
      role="dialog"
      aria-modal="true"
      tabindex="-1"
      class="w-full max-w-[390px] max-h-[92vh] flex flex-col rounded-[24px] border shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150 p-6
        {theme === 'dark'
          ? 'bg-[#161C26] border-white/10 text-white shadow-black/80'
          : 'bg-white border-[#E2E8F0] text-[#0F172A] shadow-neutral-500/30'}"
    >
      <!-- Icon -->
      <div
        class="w-12 h-12 rounded-full flex items-center justify-center mx-auto mb-3.5
          {theme === 'dark' ? 'bg-[#20293A] text-[#60A5FA]' : 'bg-[#DBE6FE] text-[#1E5EE8]'}"
      >
        <svg class="w-6 h-6 fill-none stroke-current" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
        </svg>
      </div>

      <!-- Title & Label -->
      <h3 class="text-base font-bold text-center tracking-tight">
        Доступно обновление
      </h3>
      {#if update?.label}
        <div class="text-xs font-semibold text-center mt-1 {theme === 'dark' ? 'text-[#60A5FA]' : 'text-[#1E5EE8]'}">
          {update.label}
        </div>
      {/if}

      <!-- Description -->
      <p class="text-xs text-center text-[#94A3B8] leading-relaxed mt-1.5 px-1">
        Приложение скачает проверенную сборку с проверкой SHA-256, обновит файлы и перезапустится. Туннель переподключится автоматически.
      </p>

      <!-- Release Notes (if present) -->
      {#if update?.notes && update.notes.trim().length > 0}
        <div
          class="mt-3.5 p-3 rounded-xl border text-xs max-h-36 overflow-y-auto leading-relaxed whitespace-pre-wrap font-sans opacity-85 select-text
            {theme === 'dark' ? 'bg-[#0D121B] border-white/10 text-neutral-300' : 'bg-[#F8FAFC] border-slate-200 text-slate-700'}"
        >
          {update.notes.trim()}
        </div>
      {/if}

      <!-- Installing Progress -->
      {#if isInstalling}
        <div class="mt-4 flex flex-col gap-1.5">
          <div class="flex items-center justify-between text-xs text-[#94A3B8]">
            <span>Загрузка и проверка обновления…</span>
            <span class="font-semibold">{progressPercent}%</span>
          </div>
          <div class="w-full h-2 rounded-full overflow-hidden bg-slate-700/30">
            <div
              class="h-full rounded-full transition-all duration-200 bg-gradient-to-r from-blue-500 to-indigo-500"
              style="width: {progressPercent}%"
            ></div>
          </div>
        </div>
      {/if}

      <!-- Error Message -->
      {#if error}
        <div class="mt-3 p-3 rounded-xl border text-xs bg-red-500/10 border-red-500/30 text-red-400">
          <div class="font-semibold mb-0.5">Ошибка обновления</div>
          <div class="break-words">{error}</div>
        </div>
      {/if}

      <!-- Action Buttons -->
      <div class="mt-5 flex items-center gap-2.5">
        {#if isInstalling}
          <button
            type="button"
            disabled
            class="w-full py-2.5 px-4 rounded-xl text-sm font-semibold flex items-center justify-center gap-2 bg-[#2563EB]/50 text-white/70 cursor-not-allowed"
          >
            <svg class="w-4 h-4 animate-spin text-white" viewBox="0 0 24 24" fill="none">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z"></path>
            </svg>
            <span>Установка…</span>
          </button>
        {:else}
          <button
            type="button"
            onclick={onClose}
            class="flex-1 py-2.5 px-4 rounded-xl text-sm font-semibold border transition-colors cursor-pointer
              {theme === 'dark'
                ? 'border-white/10 text-neutral-300 hover:bg-white/5 active:bg-white/10'
                : 'border-slate-300 text-slate-700 hover:bg-slate-100 active:bg-slate-200'}"
          >
            Отмена
          </button>
          <button
            type="button"
            onclick={onInstall}
            class="flex-1 py-2.5 px-4 rounded-xl text-sm font-semibold bg-[#2563EB] text-white hover:brightness-110 active:scale-[0.98] shadow-md transition-all cursor-pointer flex items-center justify-center gap-1.5"
          >
            {error ? 'Повторить' : 'Обновить'}
          </button>
        {/if}
      </div>
    </div>
  </div>
{/if}
