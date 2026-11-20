<script lang="ts">
  interface Props {
    theme: 'dark' | 'light';
    onToggleTheme: () => void;
  }

  let { theme = 'dark', onToggleTheme }: Props = $props();
</script>

<header
  class="relative h-[86px] w-full rounded-[22px] border overflow-hidden transition-colors duration-200 select-none
    {theme === 'dark'
      ? 'bg-neutral-900 border-neutral-700/60 shadow-lg shadow-black/30'
      : 'bg-white border-neutral-200 shadow-md shadow-neutral-200/50'}"
>
  <!-- Full Banner Image -->
  <img
    src={theme === 'dark' ? '/brand_logo_dark.png' : '/brand_logo_light.png'}
    alt="Outline Proxy"
    class="w-full h-full object-cover select-none pointer-events-none"
  />

  <!-- Actions: Theme toggle (top-right) -->
  <button
    type="button"
    onclick={onToggleTheme}
    class="absolute top-2.5 right-2.5 z-10 w-8 h-8 rounded-full flex items-center justify-center transition-all duration-150 cursor-pointer border
      {theme === 'dark'
        ? 'bg-neutral-800/80 hover:bg-neutral-700 border-neutral-700 text-amber-400'
        : 'bg-white/90 hover:bg-neutral-100 border-neutral-300 text-blue-700 shadow-sm'}"
    title={theme === 'dark' ? 'Включить светлую тему' : 'Включить тёмную тему'}
  >
    {#if theme === 'dark'}
      <!-- Sun icon -->
      <svg class="w-4 h-4 fill-current" viewBox="0 0 20 20">
        <path fill-rule="evenodd" d="M10 2a1 1 0 011 1v1a1 1 0 11-2 0V3a1 1 0 011-1zm4 8a4 4 0 11-8 0 4 4 0 018 0zm-.464 4.95l.707.707a1 1 0 001.414-1.414l-.707-.707a1 1 0 00-1.414 1.414zm2.12-10.607a1 1 0 010 1.414l-.706.707a1 1 0 11-1.414-1.414l.707-.707a1 1 0 011.414 0zM17 11a1 1 0 100-2h-1a1 1 0 100 2h1zm-7 4a1 1 0 011 1v1a1 1 0 11-2 0v-1a1 1 0 011-1zM5.05 6.464A1 1 0 106.465 5.05l-.708-.707a1 1 0 00-1.414 1.414l.707.707zm1.414 8.486l-.707.707a1 1 0 01-1.414-1.414l.707-.707a1 1 0 011.414 1.414zM4 11a1 1 0 100-2H3a1 1 0 000 2h1z" clip-rule="evenodd" />
      </svg>
    {:else}
      <!-- Moon icon -->
      <svg class="w-4 h-4 fill-current" viewBox="0 0 20 20">
        <path d="M17.293 13.293A8 8 0 016.707 2.707a8.001 8.001 0 1010.586 10.586z" />
      </svg>
    {/if}
  </button>
</header>
