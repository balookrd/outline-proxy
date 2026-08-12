<script lang="ts">
  import { toggleTheme } from '../../lib/theme.svelte';

  // The prototype hardcodes an example prod hostname here ("ui.k3s.beerloga.su");
  // the real app shows wherever it is actually being served from (dev proxy,
  // this k3s ingress, or anything else) instead of a fixed string.
  const host = typeof location !== 'undefined' ? location.host : '';
</script>

<div class="topbar">
  <div class="brand">
    <span class="logo" aria-hidden="true">
      <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M4 12h16M12 4v16"/></svg>
    </span>
    outline <small>fleet UI</small>
  </div>
  <span class="env-pill">{host}</span>
  <div class="spacer"></div>
  <div class="refresh"><span class="dot good"></span> live · auto-refresh <span class="mono">5s</span></div>
  <button class="iconbtn" title="Toggle theme" aria-label="Toggle theme" onclick={toggleTheme}>
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/></svg>
  </button>
</div>
