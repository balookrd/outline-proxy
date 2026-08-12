<script lang="ts">
  // Renders the ordered per-leg wire list as mono pills joined by `›`
  // arrows, the active wire outlined — prototype's wireChain() (spec
  // 2026-08-12-outline-ui-svelte-rewrite-prototype.html:469-475), CSS from
  // app.css's `.wire`/`.seg.*`/`.arrow`/`.active-seg` (ported in Task 5).
  //
  // Purely presentational: `segments` are already-resolved carrier-tier codes
  // (see lib/wsTopology.ts's legWireSegments()/Segment), not raw uplink
  // fields — this component only knows how to draw them. `xhttp`/`direct`
  // don't line up 1:1 with their CSS class (`.seg.xh`/`.seg.dim`) or, for
  // `direct`, its display label ("direct" — same one-off the prototype's own
  // wireChain() special-cases for its "dim" token), so the mapping lives here
  // rather than leaking CSS-class spelling into the caller. An unrecognised
  // token defensively falls back to the same dim/"direct" treatment instead
  // of rendering an unstyled pill.
  let { segments, activeIdx }: { segments: string[]; activeIdx: number } = $props();

  const SEG_CLASS: Record<string, string> = { h3: 'h3', h2: 'h2', ws: 'ws', xhttp: 'xh', direct: 'dim' };
  const SEG_LABEL: Record<string, string> = { xhttp: 'xh' };

  function segClass(seg: string): string {
    return SEG_CLASS[seg] ?? 'dim';
  }
  function segLabel(seg: string): string {
    return SEG_LABEL[seg] ?? seg;
  }
</script>

{#if segments.length}
  <span class="wire">
    {#each segments as seg, i (i)}
      {#if i > 0}<span class="arrow">›</span>{/if}
      <span class="seg {segClass(seg)}{i === activeIdx ? ' active-seg' : ''}">{segLabel(seg)}</span>
    {/each}
  </span>
{/if}
