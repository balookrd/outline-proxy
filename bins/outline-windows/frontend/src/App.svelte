<script lang="ts">
  let connected = $state(false);
  let statusText = $derived(connected ? 'Connected' : 'Disconnected');
</script>

<main class="flex flex-col h-screen w-full bg-slate-900 text-slate-100 p-6 select-none">
  <header class="flex items-center justify-between pb-4 border-b border-slate-800">
    <div class="flex items-center gap-2">
      <div class="w-3 h-3 rounded-full {connected ? 'bg-emerald-500' : 'bg-rose-500'}"></div>
      <h1 class="text-lg font-semibold tracking-wide">Outline Proxy</h1>
    </div>
    <span class="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-400 font-mono">v1.0.0</span>
  </header>

  <section class="flex-1 flex flex-col items-center justify-center gap-6">
    <button
      class="w-32 h-32 rounded-full border-4 flex flex-col items-center justify-center transition-all duration-200 cursor-pointer shadow-lg
        {connected 
          ? 'border-emerald-500/50 bg-emerald-500/10 hover:bg-emerald-500/20 shadow-emerald-500/20' 
          : 'border-slate-700 bg-slate-800 hover:bg-slate-700/80 shadow-black/40'}"
      onclick={() => connected = !connected}
    >
      <span class="text-sm font-medium uppercase tracking-wider {connected ? 'text-emerald-400' : 'text-slate-400'}">
        {statusText}
      </span>
    </button>

    <p class="text-xs text-slate-400 text-center max-w-xs">
      {connected ? 'Routing traffic through secure upstream proxy.' : 'Click to connect to your proxy profile.'}
    </p>
  </section>

  <footer class="pt-4 border-t border-slate-800 flex justify-between text-xs text-slate-500">
    <span>Windows Client</span>
    <span>Ready</span>
  </footer>
</main>
