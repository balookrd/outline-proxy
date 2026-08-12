<script lang="ts">
  // Mounted once in App.svelte (like Topbar/Sidebar); reads the shared
  // lib/toast.svelte.ts queue directly instead of taking props — any feature
  // calls `toast(...)` and this renders it wherever it happens to be mounted,
  // same relationship dashboard.html's global showToast()/#toast element had.
  import { toasts } from '../../lib/toast.svelte';
</script>

<div class="toasts">
  {#each toasts as t (t.id)}
    <div class="toast {t.kind}" role={t.kind === 'error' ? 'alert' : 'status'}>
      {#if t.kind === 'error'}
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 8v5M12 16h.01"/></svg>
      {:else}
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6 9 17l-5-5"/></svg>
      {/if}
      <span>{t.text}</span>
    </div>
  {/each}
</div>
