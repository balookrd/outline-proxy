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

  let logContainer = $state<HTMLDivElement | null>(null);
  let autoScroll = $state(true);
  let copied = $state(false);

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
      const allText = logs.join('\n');
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
              {logs.length} {logs.length === 1 ? 'строка' : (logs.length >= 2 && logs.length <= 4 ? 'строки' : 'строк')}
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

      <!-- Terminal Body -->
      <div
        bind:this={logContainer}
        onscroll={handleScroll}
        class="flex-1 bg-neutral-950 p-3 overflow-y-auto font-mono text-[10.5px] leading-relaxed select-text space-y-0.5 border-y border-neutral-800"
      >
        {#if logs.length === 0}
          <div class="h-full flex items-center justify-center text-neutral-500 italic select-none">
            Журнал пока пуст...
          </div>
        {:else}
          {#each logs as line, index}
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
