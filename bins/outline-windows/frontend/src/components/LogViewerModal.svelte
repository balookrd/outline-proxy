<script lang="ts">
  interface Props {
    isOpen: boolean;
    theme: 'dark' | 'light';
    logs: string[];
    onClose: () => void;
    onClearLogs: () => void;
  }

  let {
    isOpen = false,
    theme = 'dark',
    logs = [],
    onClose,
    onClearLogs,
  }: Props = $props();

  type LogFilter = 'all' | 'error' | 'warn' | 'info';

  let currentFilter = $state<LogFilter>('all');
  let logContainer = $state<HTMLDivElement | null>(null);
  let autoScroll = $state(true);
  let copied = $state(false);

  function matchesFilter(line: string, filter: LogFilter): boolean {
    if (filter === 'all') return true;
    const upper = line.toUpperCase();
    if (filter === 'error') {
      return upper.includes('ERROR') || upper.includes('PANIC') || upper.includes('CRITICAL');
    }
    if (filter === 'warn') {
      return upper.includes('WARN');
    }
    if (filter === 'info') {
      return upper.includes('INFO');
    }
    return false;
  }

  let filteredLogs = $derived.by<string[]>(() => {
    if (currentFilter === 'all') return logs;
    return logs.filter((line) => matchesFilter(line, currentFilter));
  });

  let counts = $derived.by(() => {
    let error = 0;
    let warn = 0;
    let info = 0;
    for (const l of logs) {
      const u = l.toUpperCase();
      if (u.includes('ERROR') || u.includes('PANIC') || u.includes('CRITICAL')) {
        error++;
      } else if (u.includes('WARN')) {
        warn++;
      } else if (u.includes('INFO')) {
        info++;
      }
    }
    return { all: logs.length, error, warn, info };
  });

  // Auto-scroll when new log lines arrive if autoScroll is enabled
  $effect(() => {
    if (isOpen && autoScroll && logContainer) {
      logContainer.scrollTop = logContainer.scrollHeight;
    }
  });

  function handleScroll(e: Event) {
    const target = e.currentTarget as HTMLDivElement;
    const isAtBottom = target.scrollHeight - target.scrollTop - target.clientHeight < 40;
    autoScroll = isAtBottom;
  }

  async function handleCopy() {
    try {
      const allText = filteredLogs.join('\n');
      await navigator.clipboard.writeText(allText);
      copied = true;
      setTimeout(() => {
        copied = false;
      }, 1800);
    } catch {
      // Ignore clipboard write errors
    }
  }

  function getLineClass(line: string) {
    const upper = line.toUpperCase();
    if (upper.includes('ERROR') || upper.includes('PANIC') || upper.includes('CRITICAL')) {
      return 'text-rose-400 font-semibold';
    }
    if (upper.includes('WARN')) {
      return 'text-amber-300';
    }
    if (upper.includes('INFO')) {
      return 'text-emerald-400';
    }
    if (upper.includes('DEBUG') || upper.includes('TRACE')) {
      return 'text-neutral-500';
    }
    return 'text-neutral-300';
  }
</script>

{#if isOpen}
  <!-- Backdrop -->
  <div
    class="fixed inset-0 z-50 flex items-center justify-center p-3 backdrop-blur-sm transition-all duration-200 select-none
      {theme === 'dark' ? 'bg-black/70' : 'bg-neutral-900/50'}"
    role="dialog"
    aria-modal="true"
  >
    <!-- Modal Card -->
    <div
      class="w-full max-w-[380px] h-[92vh] flex flex-col rounded-[26px] border shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150
        {theme === 'dark'
          ? 'bg-neutral-900 border-neutral-700/80 text-neutral-100 shadow-black/90'
          : 'bg-white border-neutral-300 text-neutral-900 shadow-neutral-600/30'}"
    >
      <!-- Header -->
      <div class="flex items-center justify-between px-5 py-3 border-b {theme === 'dark' ? 'border-neutral-800' : 'border-neutral-200'}">
        <div class="flex items-center gap-2">
          <!-- Terminal Icon -->
          <div class="w-7 h-7 rounded-full flex items-center justify-center {theme === 'dark' ? 'bg-neutral-800 text-neutral-300' : 'bg-neutral-100 text-neutral-700'}">
            <svg class="w-4 h-4 fill-current" viewBox="0 0 20 20">
              <path fill-rule="evenodd" d="M2 5a2 2 0 012-2h12a2 2 0 012 2v10a2 2 0 01-2 2H4a2 2 0 01-2-2V5zm3.293 1.293a1 1 0 011.414 0l3 3a1 1 0 010 1.414l-3 3a1 1 0 01-1.414-1.414L7.586 10 5.293 7.707a1 1 0 010-1.414zM11 12a1 1 0 100 2h3a1 1 0 100-2h-3z" clip-rule="evenodd" />
            </svg>
          </div>
          <div>
            <h2 class="text-xs font-bold tracking-tight">Журнал событий</h2>
            <span class="text-[10px] {theme === 'dark' ? 'text-neutral-400' : 'text-neutral-500'}">
              {#if currentFilter === 'all'}
                {logs.length} {logs.length === 1 ? 'строка' : (logs.length >= 2 && logs.length <= 4 ? 'строки' : 'строк')}
              {:else}
                {filteredLogs.length} из {logs.length}
              {/if}
            </span>
          </div>
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

      <!-- Level Filter Tabs -->
      <div class="px-4 py-2 border-b flex items-center gap-1.5 overflow-x-auto {theme === 'dark' ? 'border-neutral-800 bg-neutral-900/60' : 'border-neutral-200 bg-neutral-50/80'}">
        <button
          type="button"
          onclick={() => currentFilter = 'all'}
          class="px-2.5 py-1 rounded-lg text-[11px] font-semibold transition-all cursor-pointer flex items-center gap-1.5
            {currentFilter === 'all'
              ? (theme === 'dark' ? 'bg-neutral-700 text-white shadow-sm' : 'bg-neutral-300 text-neutral-900 font-bold shadow-sm')
              : (theme === 'dark' ? 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-800' : 'text-neutral-600 hover:text-black hover:bg-neutral-200/60')}"
        >
          <span>Все</span>
          <span class="text-[9px] px-1 py-0.2 rounded-full {currentFilter === 'all' ? (theme === 'dark' ? 'bg-neutral-600 text-neutral-200' : 'bg-neutral-400/50 text-neutral-900') : (theme === 'dark' ? 'bg-neutral-800 text-neutral-400' : 'bg-neutral-200 text-neutral-600')}">
            {counts.all}
          </span>
        </button>

        <button
          type="button"
          onclick={() => currentFilter = 'error'}
          class="px-2.5 py-1 rounded-lg text-[11px] font-semibold transition-all cursor-pointer flex items-center gap-1.5
            {currentFilter === 'error'
              ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40 shadow-sm'
              : (theme === 'dark' ? 'text-neutral-400 hover:text-rose-300 hover:bg-neutral-800' : 'text-neutral-600 hover:text-rose-600 hover:bg-neutral-200/60')}"
        >
          <span class="w-1.5 h-1.5 rounded-full bg-rose-500"></span>
          <span>Ошибки</span>
          {#if counts.error > 0}
            <span class="text-[9px] px-1 py-0.2 rounded-full bg-rose-500/30 text-rose-300">
              {counts.error}
            </span>
          {/if}
        </button>

        <button
          type="button"
          onclick={() => currentFilter = 'warn'}
          class="px-2.5 py-1 rounded-lg text-[11px] font-semibold transition-all cursor-pointer flex items-center gap-1.5
            {currentFilter === 'warn'
              ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 shadow-sm'
              : (theme === 'dark' ? 'text-neutral-400 hover:text-amber-300 hover:bg-neutral-800' : 'text-neutral-600 hover:text-amber-600 hover:bg-neutral-200/60')}"
        >
          <span class="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
          <span>Предупреждения</span>
          {#if counts.warn > 0}
            <span class="text-[9px] px-1 py-0.2 rounded-full bg-amber-500/30 text-amber-300">
              {counts.warn}
            </span>
          {/if}
        </button>

        <button
          type="button"
          onclick={() => currentFilter = 'info'}
          class="px-2.5 py-1 rounded-lg text-[11px] font-semibold transition-all cursor-pointer flex items-center gap-1.5
            {currentFilter === 'info'
              ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 shadow-sm'
              : (theme === 'dark' ? 'text-neutral-400 hover:text-emerald-300 hover:bg-neutral-800' : 'text-neutral-600 hover:text-emerald-600 hover:bg-neutral-200/60')}"
        >
          <span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
          <span>Инфо</span>
          {#if counts.info > 0}
            <span class="text-[9px] px-1 py-0.2 rounded-full bg-emerald-500/30 text-emerald-300">
              {counts.info}
            </span>
          {/if}
        </button>
      </div>

      <!-- Terminal Body -->
      <div
        bind:this={logContainer}
        onscroll={handleScroll}
        class="flex-1 bg-neutral-950 p-3 overflow-y-auto font-mono text-[10.5px] leading-relaxed select-text space-y-0.5 border-y border-neutral-800"
      >
        {#if filteredLogs.length === 0}
          <div class="h-full flex items-center justify-center text-neutral-500 italic select-none">
            {#if logs.length === 0}
              Журнал пока пуст...
            {:else}
              Нет записей уровня «{currentFilter === 'error' ? 'Ошибки (ERROR)' : currentFilter === 'warn' ? 'Предупреждения (WARN)' : 'Инфо (INFO)'}»
            {/if}
          </div>
        {:else}
          {#each filteredLogs as line, index}
            <div class="break-all whitespace-pre-wrap {getLineClass(line)}">
              <span class="text-neutral-600 select-none mr-1.5">{index + 1}</span>{line}
            </div>
          {/each}
        {/if}
      </div>

      <!-- Footer Toolbar -->
      <div class="px-4 py-2.5 flex items-center justify-between text-xs {theme === 'dark' ? 'bg-neutral-900/80' : 'bg-neutral-50'}">
        <div class="flex items-center gap-2">
          <!-- Copy All -->
          <button
            type="button"
            onclick={handleCopy}
            class="px-2.5 py-1 text-[11px] font-semibold rounded-lg border transition-colors cursor-pointer flex items-center gap-1
              {copied
                ? 'bg-emerald-500/20 border-emerald-500 text-emerald-400'
                : (theme === 'dark' ? 'bg-neutral-800 border-neutral-700 hover:bg-neutral-700 text-neutral-200' : 'bg-white border-neutral-300 hover:bg-neutral-100 text-neutral-800')}"
          >
            {#if copied}
              <span>Скопировано ✓</span>
            {:else}
              <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
              </svg>
              <span>Копировать</span>
            {/if}
          </button>

          <!-- Clear -->
          <button
            type="button"
            onclick={onClearLogs}
            class="px-2.5 py-1 text-[11px] font-semibold rounded-lg border transition-colors cursor-pointer
              {theme === 'dark'
                ? 'bg-neutral-800 border-neutral-700 hover:bg-neutral-700 text-neutral-300'
                : 'bg-white border-neutral-300 hover:bg-neutral-100 text-neutral-700'}"
          >
            Очистить
          </button>
        </div>

        <button
          type="button"
          onclick={onClose}
          class="px-3.5 py-1 text-[11px] font-bold rounded-lg transition-colors cursor-pointer
            {theme === 'dark' ? 'bg-neutral-800 hover:bg-neutral-700 text-white' : 'bg-neutral-200 hover:bg-neutral-300 text-neutral-900'}"
        >
          Закрыть
        </button>
      </div>
    </div>
  </div>
{/if}
