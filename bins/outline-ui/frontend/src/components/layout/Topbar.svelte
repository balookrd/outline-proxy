<script lang="ts">
  import { toggleTheme, theme } from '../../lib/theme.svelte';
  import logo from '../../assets/outline-logo.png';

  // The prototype hardcodes an example prod hostname here ("ui.k3s.beerloga.su");
  // the real app shows wherever it is actually being served from (dev proxy,
  // this k3s ingress, or anything else) instead of a fixed string.
  const host = typeof location !== 'undefined' ? location.host : '';

  // Recomputed whenever the explicit mode changes; `systemDark` additionally
  // tracks the OS preference so the icon stays correct for a user who never
  // toggled (theme.mode === null) and flips their system theme.
  let systemDark = $state(
    typeof window !== 'undefined' && window.matchMedia('(prefers-color-scheme: dark)').matches,
  );
  $effect(() => {
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    const onChange = (e: MediaQueryListEvent) => (systemDark = e.matches);
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  });
  const isDark = $derived(theme.mode ? theme.mode === 'dark' : systemDark);
</script>

<div class="topbar">
  <div class="brand">
    <span class="logo" aria-hidden="true">
      <img src={logo} alt="outline" width="22" height="22" />
    </span>
    outline <small>fleet UI</small>
  </div>
  <span class="env-pill">{host}</span>
  <div class="spacer"></div>
  <div class="refresh"><span class="dot good"></span> live · auto-refresh <span class="mono">5s</span></div>
  <button
    class="iconbtn"
    title={isDark ? 'Switch to light theme' : 'Switch to dark theme'}
    aria-label={isDark ? 'Switch to light theme' : 'Switch to dark theme'}
    onclick={toggleTheme}
  >
    {#if isDark}
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>
    {:else}
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/></svg>
    {/if}
  </button>
</div>
