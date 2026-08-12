<script lang="ts">
  // Small presentational status dot — `.dot` + a tone modifier (app.css,
  // ported from the prototype's `<span class="dot good">` in Topbar/inst-head).
  // Self-contained like ErrorBanner.svelte so call sites don't each re-derive
  // the class string.
  let { tone }: { tone: 'good' | 'warn' | 'bad' | 'off' } = $props();
</script>

<span class="dot {tone}" aria-hidden="true"></span>
