<script lang="ts">
  import type { ServerProfile } from '../lib/types';

  interface Props {
    isOpen: boolean;
    theme: 'dark' | 'light';
    profiles: ServerProfile[];
    activeProfileId: string | null;
    onClose: () => void;
    onSelectProfile: (id: string) => Promise<void>;
    onAddProfile: (link: string) => Promise<void>;
    onRemoveProfile: (id: string) => Promise<void>;
    onUpdateSubscription: (id: string) => Promise<void>;
    onRenameProfile: (id: string, name: string) => Promise<void>;
  }

  let {
    isOpen = false,
    theme = 'dark',
    profiles = [],
    activeProfileId = null,
    onClose,
    onSelectProfile,
    onAddProfile,
    onRemoveProfile,
    onUpdateSubscription,
    onRenameProfile,
  }: Props = $props();

  let linkInput = $state('');
  let isSubmitting = $state(false);
  let updatingProfileId = $state<string | null>(null);
  let selectingProfileId = $state<string | null>(null);
  let editingProfileId = $state<string | null>(null);
  let editingName = $state('');
  let isRenaming = $state(false);
  let errorMessage = $state<string | null>(null);
  let deleteTarget = $state<{ id: string; name: string } | null>(null);

  function startRename(profile: ServerProfile) {
    editingProfileId = profile.id;
    editingName = profile.name || '';
  }

  function cancelRename() {
    editingProfileId = null;
    editingName = '';
  }

  async function saveRename(id: string) {
    const trimmed = editingName.trim();
    if (!trimmed) {
      errorMessage = 'Название не может быть пустым';
      return;
    }
    isRenaming = true;
    errorMessage = null;
    try {
      await onRenameProfile(id, trimmed);
      editingProfileId = null;
      editingName = '';
    } catch (err: any) {
      errorMessage = typeof err === 'string' ? err : err?.message || 'Не удалось переименовать профиль';
    } finally {
      isRenaming = false;
    }
  }

  async function handleSelect(id: string) {
    selectingProfileId = id;
    errorMessage = null;
    try {
      await onSelectProfile(id);
    } catch (err: any) {
      errorMessage = typeof err === 'string' ? err : err?.message || 'Не удалось выбрать профиль';
    } finally {
      selectingProfileId = null;
    }
  }

  async function handleAdd() {
    const trimmed = linkInput.trim();
    if (!trimmed) {
      errorMessage = 'Введите ссылку или URL подписки';
      return;
    }
    isSubmitting = true;
    errorMessage = null;
    try {
      await onAddProfile(trimmed);
      linkInput = '';
    } catch (err: any) {
      errorMessage = typeof err === 'string' ? err : err?.message || 'Не удалось добавить профиль';
    } finally {
      isSubmitting = false;
    }
  }

  async function handlePaste() {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        linkInput = text.trim();
      }
    } catch {
      // Ignore clipboard permission errors
    }
  }

  async function handleUpdate(profile: ServerProfile) {
    updatingProfileId = profile.id;
    errorMessage = null;
    try {
      await onUpdateSubscription(profile.id);
    } catch (err: any) {
      errorMessage = typeof err === 'string' ? err : err?.message || 'Ошибка обновления подписки';
    } finally {
      updatingProfileId = null;
    }
  }

  function handleRemove(id: string, name: string) {
    deleteTarget = { id, name };
  }

  async function confirmDelete() {
    if (!deleteTarget) return;
    const target = deleteTarget;
    deleteTarget = null;
    try {
      await onRemoveProfile(target.id);
    } catch (err: any) {
      errorMessage = typeof err === 'string' ? err : err?.message || 'Ошибка удаления';
    }
  }

  function cancelDelete() {
    deleteTarget = null;
  }

  function handleKeyDown(e: KeyboardEvent) {
    if (e.key === 'Escape' && isOpen) {
      if (editingProfileId) {
        cancelRename();
      } else if (deleteTarget) {
        deleteTarget = null;
      } else {
        onClose();
      }
    }
  }

  function getTransportBadge(profile: ServerProfile) {
    const isSub = profile.transport === 'subscription' || !!profile.configUrl || !!profile.config_url;
    if (isSub) {
      return { text: 'ПОДПИСКА', bg: 'bg-amber-500/20 text-amber-300 border-amber-500/30' };
    }
    const t = (profile.transport || '').toLowerCase();
    if (t.includes('vless')) {
      return { text: 'VLESS', bg: 'bg-indigo-500/20 text-indigo-300 border-indigo-500/30' };
    }
    if (t.includes('ss')) {
      return { text: 'SHADOWSOCKS', bg: 'bg-sky-500/15 text-sky-400 border-sky-500/25' };
    }
    return { text: (profile.transport || 'ПРОКСИ').toUpperCase(), bg: 'bg-neutral-500/20 text-neutral-300 border-neutral-500/30' };
  }

  function getPingBadge(profile: ServerProfile, isActive: boolean) {
    if (profile.ping != null) {
      if (profile.ping < 100) {
        return {
          text: `${profile.ping} мс`,
          bg: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
          dot: 'bg-emerald-400',
        };
      }
      if (profile.ping < 250) {
        return {
          text: `${profile.ping} мс`,
          bg: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
          dot: 'bg-amber-400',
        };
      }
      return {
        text: `${profile.ping} мс`,
        bg: 'bg-rose-500/20 text-rose-400 border-rose-500/30',
        dot: 'bg-rose-400',
      };
    }
    if (isActive) {
      return {
        text: '<50 мс',
        bg: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/25',
        dot: 'bg-emerald-400 animate-pulse',
      };
    }
    return {
      text: '— мс',
      bg: 'bg-neutral-700/30 text-neutral-400 border-neutral-700/40',
      dot: 'bg-neutral-500',
    };
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
          <!-- Folder Icon matching macOS palette -->
          <div class="w-7 h-7 rounded-full flex items-center justify-center {theme === 'dark' ? 'bg-[#20293A] text-[#60A5FA]' : 'bg-[#DBE6FE] text-[#1E5EE8]'}">
            <svg class="w-4 h-4 fill-current" viewBox="0 0 20 20">
              <path d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z" />
            </svg>
          </div>
          <h2 class="text-sm font-bold tracking-tight">Серверы и подписки</h2>
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
      <div class="flex-1 overflow-y-auto px-4 py-3 space-y-3.5">
        <!-- Error Alert Banner -->
        {#if errorMessage}
          <div class="p-2.5 rounded-xl bg-rose-500/15 border border-rose-500/30 text-rose-300 text-xs flex items-center justify-between animate-in fade-in duration-150">
            <span class="font-medium">{errorMessage}</span>
            <button
              type="button"
              onclick={() => errorMessage = null}
              class="text-rose-400 hover:text-rose-200 font-bold ml-2 cursor-pointer"
            >
              ✕
            </button>
          </div>
        {/if}

        <!-- Add Profile Section -->
        <div class="p-3 rounded-2xl border space-y-2
          {theme === 'dark' ? 'bg-neutral-800/50 border-neutral-700/60' : 'bg-neutral-50 border-neutral-200'}">
          <div class="flex items-center justify-between">
            <span class="text-xs font-semibold {theme === 'dark' ? 'text-neutral-300' : 'text-neutral-700'}">
              + Добавить сервер или подписку
            </span>
            <button
              type="button"
              onclick={handlePaste}
              class="text-[11px] font-medium text-[#1E5EE8] hover:text-[#164EC2] dark:text-[#60A5FA] cursor-pointer flex items-center gap-1"
            >
              Вставить
            </button>
          </div>

          <div class="flex gap-1.5">
            <input
              type="text"
              bind:value={linkInput}
              placeholder="vless://, ss://, outline:// или https://"
              class="flex-1 px-3 py-1.5 text-xs rounded-xl border outline-none font-mono transition-colors
                {theme === 'dark'
                  ? 'bg-neutral-900 border-neutral-700 text-neutral-200 focus:border-[#2563EB]'
                  : 'bg-white border-neutral-300 text-neutral-900 focus:border-[#1E5EE8]'}"
              onkeydown={(e) => {
                if (e.key === 'Enter') handleAdd();
              }}
            />
            <button
              type="button"
              onclick={handleAdd}
              disabled={isSubmitting || !linkInput.trim()}
              class="px-3 py-1.5 text-xs font-bold rounded-xl text-white transition-all cursor-pointer shadow-sm disabled:opacity-40
                {theme === 'dark'
                  ? 'bg-[#2563EB] hover:bg-[#1D4ED8]'
                  : 'bg-[#1E5EE8] hover:bg-[#164EC2] shadow-[#1E5EE8]/20'}"
            >
              {#if isSubmitting}
                ...
              {:else}
                Добавить
              {/if}
            </button>
          </div>

          {#if errorMessage}
            <p class="text-[11px] text-rose-400 font-medium">{errorMessage}</p>
          {/if}
        </div>

        <!-- Profiles List -->
        <div class="space-y-2">
          {#if profiles.length === 0}
            <div class="text-center py-8 space-y-2 {theme === 'dark' ? 'text-neutral-400' : 'text-neutral-500'}">
              <svg class="w-10 h-10 mx-auto opacity-40" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
              </svg>
              <p class="text-xs">Нет добавленных серверов</p>
              <p class="text-[11px] opacity-70">Добавьте ссылку доступа или URL подписки выше</p>
            </div>
          {:else}
            {#each profiles as profile (profile.id)}
              {@const badge = getTransportBadge(profile)}
              {@const isActive = activeProfileId === profile.id}
              {@const isSub = profile.transport === 'subscription' || !!profile.configUrl || !!profile.config_url}
              {@const ping = getPingBadge(profile, isActive)}

              <div
                class="p-3 rounded-2xl border transition-all duration-150 relative space-y-2
                  {isActive
                    ? (theme === 'dark'
                        ? 'bg-[#161C26] border-[#3B82F6]/70 shadow-md shadow-blue-950/40'
                        : 'bg-[#DBE6FE]/35 border-[#1E5EE8] shadow-sm')
                    : (theme === 'dark'
                        ? 'bg-neutral-800/40 border-neutral-700/50 hover:bg-neutral-800/70'
                        : 'bg-white border-neutral-200 hover:bg-neutral-50')}"
              >
                <!-- Top Row: Name and badges -->
                <div class="flex items-start justify-between gap-2">
                  <div class="flex-1 min-w-0">
                    {#if editingProfileId === profile.id}
                      <!-- Inline rename form -->
                      <form
                        onsubmit={(e) => { e.preventDefault(); saveRename(profile.id); }}
                        class="flex items-center gap-1.5 w-full mb-1"
                      >
                        <input
                          type="text"
                          bind:value={editingName}
                          class="flex-1 px-2 py-0.5 text-xs rounded-lg border outline-none font-semibold transition-colors
                            {theme === 'dark'
                              ? 'bg-neutral-900 border-neutral-600 text-white focus:border-[#2563EB]'
                              : 'bg-white border-neutral-300 text-neutral-900 focus:border-[#1E5EE8]'}"
                          onkeydown={(e) => {
                            if (e.key === 'Escape') cancelRename();
                          }}
                        />
                        <button
                          type="submit"
                          disabled={isRenaming || !editingName.trim()}
                          class="w-6 h-6 rounded flex items-center justify-center text-white bg-[#1E5EE8] hover:bg-[#164EC2] dark:bg-[#2563EB] cursor-pointer"
                          title="Сохранить"
                        >
                          <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7" />
                          </svg>
                        </button>
                        <button
                          type="button"
                          onclick={cancelRename}
                          class="w-6 h-6 rounded flex items-center justify-center text-neutral-400 hover:text-white hover:bg-neutral-700 cursor-pointer"
                          title="Отмена"
                        >
                          ✕
                        </button>
                      </form>
                    {:else}
                      <div class="flex items-center gap-1.5 flex-wrap">
                        <span
                          class="text-xs font-bold truncate cursor-pointer hover:underline {theme === 'dark' ? 'text-white' : 'text-neutral-900'}"
                          onclick={() => startRename(profile)}
                          title="Нажмите для переименования"
                          role="button"
                          tabindex="0"
                          onkeydown={(e) => { if (e.key === 'Enter') startRename(profile); }}
                        >
                          {profile.name || 'Без названия'}
                        </span>
                        {#if isActive}
                          <span class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full text-[10px] font-bold
                            {theme === 'dark' ? 'bg-[#1E293B] text-[#93C5FD] border border-[#3B82F6]/40' : 'bg-[#DBE6FE] text-[#1E3A8A] border border-[#93C5FD]'}">
                            <span class="w-1.5 h-1.5 rounded-full {theme === 'dark' ? 'bg-[#60A5FA]' : 'bg-[#1E5EE8]'} animate-pulse"></span>
                            АКТИВЕН
                          </span>
                        {/if}
                      </div>
                    {/if}

                    <div class="flex items-center gap-1.5 mt-1 flex-wrap">
                      <span class="text-[10px] font-semibold px-1.5 py-0.2 rounded border {badge.bg}">
                        {badge.text}
                      </span>
                      <!-- Ping latency indicator -->
                      <span class="inline-flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.2 rounded border {ping.bg}">
                        <span class="w-1.5 h-1.5 rounded-full {ping.dot}"></span>
                        {ping.text}
                      </span>
                      {#if profile.tcpOnly || profile.tcp_only}
                        <span class="text-[10px] px-1 py-0.2 rounded bg-neutral-700/50 text-neutral-300 font-mono">
                          TCP-only
                        </span>
                      {/if}
                    </div>
                  </div>

                  <!-- Actions -->
                  <div class="flex items-center gap-0.5">
                    <!-- Rename Button -->
                    <button
                      type="button"
                      onclick={() => startRename(profile)}
                      class="w-7 h-7 rounded-lg flex items-center justify-center transition-colors cursor-pointer
                        {theme === 'dark' ? 'hover:bg-neutral-700 text-neutral-300' : 'hover:bg-neutral-200 text-neutral-600'}"
                      title="Переименовать"
                    >
                      <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z" />
                      </svg>
                    </button>

                    {#if isSub}
                      <!-- Refresh Subscription Button -->
                      <button
                        type="button"
                        onclick={() => handleUpdate(profile)}
                        disabled={updatingProfileId === profile.id}
                        class="w-7 h-7 rounded-lg flex items-center justify-center transition-colors cursor-pointer
                          {theme === 'dark' ? 'hover:bg-neutral-700 text-neutral-300' : 'hover:bg-neutral-200 text-neutral-600'}"
                        title="Обновить подписку"
                      >
                        <svg
                          class="w-3.5 h-3.5 {updatingProfileId === profile.id ? 'animate-spin text-amber-400' : ''}"
                          fill="none"
                          stroke="currentColor"
                          viewBox="0 0 24 24"
                        >
                          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                        </svg>
                      </button>
                    {/if}

                    <!-- Delete button -->
                    <button
                      type="button"
                      onclick={() => handleRemove(profile.id, profile.name)}
                      class="w-7 h-7 rounded-lg flex items-center justify-center transition-colors cursor-pointer text-rose-400 hover:text-rose-300 hover:bg-rose-500/10"
                      title="Удалить профиль"
                    >
                      <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                      </svg>
                    </button>
                  </div>
                </div>

                <!-- Footer button row -->
                {#if !isActive}
                  <div class="pt-1 flex justify-end">
                    <button
                      type="button"
                      onclick={() => handleSelect(profile.id)}
                      disabled={selectingProfileId === profile.id}
                      class="px-2.5 py-1 text-[11px] font-semibold rounded-lg transition-colors cursor-pointer disabled:opacity-50
                        {theme === 'dark'
                          ? 'bg-neutral-800 hover:bg-[#2563EB] hover:text-white text-neutral-200'
                          : 'bg-neutral-100 hover:bg-[#1E5EE8] hover:text-white text-neutral-800 border border-neutral-200'}"
                    >
                      {selectingProfileId === profile.id ? 'Выбор...' : 'Сделать активным'}
                    </button>
                  </div>
                {/if}
              </div>
            {/each}
          {/if}
        </div>
      </div>

      <!-- Footer -->
      <div class="px-5 py-3 border-t flex justify-end {theme === 'dark' ? 'border-neutral-800 bg-neutral-900/60' : 'border-neutral-200 bg-neutral-50'}">
        <button
          type="button"
          onclick={onClose}
          class="px-4 py-1.5 text-xs font-semibold rounded-xl transition-colors cursor-pointer
            {theme === 'dark' ? 'bg-neutral-800 hover:bg-neutral-700 text-white' : 'bg-neutral-200 hover:bg-neutral-300 text-neutral-900'}"
        >
          Закрыть
        </button>
      </div>

      <!-- Delete confirmation dialog overlay -->
      {#if deleteTarget}
        <div class="absolute inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4 rounded-3xl">
          <div class="w-full max-w-[280px] p-4 rounded-2xl border shadow-2xl flex flex-col gap-3 text-center
            {theme === 'dark' ? 'bg-neutral-900 border-neutral-700 text-white' : 'bg-white border-neutral-200 text-neutral-900'}">
            <div class="text-sm font-bold tracking-tight">Удалить сервер?</div>
            <div class="text-xs {theme === 'dark' ? 'text-neutral-300' : 'text-neutral-600'}">
              Вы действительно хотите удалить «{deleteTarget.name}»?
            </div>
            <div class="flex items-center gap-2 pt-1">
              <button
                type="button"
                onclick={cancelDelete}
                class="flex-1 py-1.5 text-xs font-semibold rounded-xl border transition-colors cursor-pointer
                  {theme === 'dark'
                    ? 'border-neutral-700 bg-neutral-800 hover:bg-neutral-700 text-neutral-300'
                    : 'border-neutral-300 bg-neutral-100 hover:bg-neutral-200 text-neutral-700'}"
              >
                Отмена
              </button>
              <button
                type="button"
                onclick={confirmDelete}
                class="flex-1 py-1.5 text-xs font-semibold rounded-xl bg-rose-600 hover:bg-rose-500 text-white transition-colors cursor-pointer shadow-sm"
              >
                Удалить
              </button>
            </div>
          </div>
        </div>
      {/if}
    </div>
  </div>
{/if}
