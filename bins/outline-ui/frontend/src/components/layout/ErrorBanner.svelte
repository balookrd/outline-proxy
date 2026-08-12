<script lang="ts">
  // Self-guarding: renders nothing when there is no message, so callers can
  // wire it unconditionally as `<ErrorBanner message={poll.error} />` instead
  // of an extra `{#if}` at every call site. Used so a single dead/unreachable
  // instance surfaces as a banner next to otherwise-stale-but-good data,
  // never as a blank page (see features/ss/Users.svelte).
  let { message }: { message?: string | null } = $props();
</script>

{#if message}
  <div class="error-banner" role="alert">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 8v5M12 16h.01"/></svg>
    <span>{message}</span>
  </div>
{/if}
