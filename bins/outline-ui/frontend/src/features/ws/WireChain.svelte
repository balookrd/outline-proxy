<script lang="ts">
  // Renders the ordered per-leg wire list: the ACTIVE link as a full-text
  // chip ("vless/xhttp/h3"), every fallback link as a small colour-only
  // square carrying the same detail in its tooltip only — owner-approved
  // mockup (wire-active-full.html, reviewed 2026-08-13). Replaces cabc01c0's
  // single-chip-per-link design (transport-hue text + tunnel-accent edge +
  // de-emphasised carrier text — owner feedback on the design before THAT
  // one, the old 3-badge layout, was "too busy" / "перегружена чипами"; this
  // iteration keeps the one-item-per-link idea but swaps what distinguishes
  // the active link from an outline to full readable text, and drops
  // fallback links to pure colour since they don't need to be read, only
  // scanned). Every link (active or fallback) shares one visual grammar:
  //   - COMBO background — the (transport, tunnel) pair (vless+ws, vless+
  //     xhttp, ss+ws, ss+xhttp — wsTopology.ts's wireComboKey()) drives the
  //     chip/square's tint and border (app.css `.wcombo-*`, custom property
  //     `--wcc`). 'neutral' when the tunnel didn't resolve — never
  //     fabricates one of the 4 real hues for a wire that can't back it up.
  //   - CARRIER left-accent edge — h3/h2/h1 (app.css `.wcarrier-*`, custom
  //     property `--wce`), independent of whether the combo resolved: a bare
  //     "h3"/"h2" mode token can resolve carrier with no tunnel at all (see
  //     lib/wsTopology.ts's parseWireMode()). Carrier never colours text.
  // Active vs fallback is then purely a matter of shape/content:
  //   - Active (`i === activeIdx`): `.wchip-full`, full slash-joined text
  //     (wsTopology.ts's wireFullText()), single flat text colour, no
  //     outline — the text itself is what marks it active.
  //   - Fallback: `.wchip-sq`, no text at all, full detail only in `title`.
  //
  // Purely presentational: `links` are already-resolved
  // {transport, tunnel, carrier} triples (see lib/wsTopology.ts's
  // legWireChain()/parseWireMode()), not raw uplink fields — this component
  // only knows how to draw them and build the per-link hover tooltip.
  import type { WireLink, Tunnel, Carrier } from '../../lib/wsTopology';
  import { wireComboKey, wireFullText } from '../../lib/wsTopology';

  let { links, activeIdx }: { links: WireLink[]; activeIdx: number } = $props();

  const PROXY_NAME: Record<string, string> = { vless: 'VLESS', ss: 'Shadowsocks' };
  const TUNNEL_NAME: Record<Exclude<Tunnel, null>, string> = { ws: 'WebSocket', xhttp: 'XHTTP' };
  const CARRIER_NAME: Record<Exclude<Carrier, null>, string> = { h3: 'HTTP/3', h2: 'HTTP/2', h1: 'HTTP/1.1' };

  // combo/carrier class strings — presentation-only (single consumer, unlike
  // wireComboKey()/wireFullText() themselves) so they stay local rather than
  // joining wsTopology.ts's data-resolution helpers, same division of labour
  // the old chipClass() used.
  function comboClass(link: WireLink): string {
    return `wcombo-${wireComboKey(link)}`;
  }
  function carrierClass(link: WireLink): string {
    return link.carrier ? `wcarrier-${link.carrier}` : '';
  }

  // Full-stack descriptive tooltip, e.g. "VLESS over XHTTP over HTTP/3 ·
  // active" — kept on the active chip (task: "keep the full-stack title= on
  // the active chip too") even though its visible text already spells out
  // the compact slash form; this is the same tooltip shape the
  // pre-redesign single-chip design carried on every link.
  function fullStackTooltip(link: WireLink, active: boolean): string {
    const proxyName = PROXY_NAME[link.transport.toLowerCase()] ?? link.transport;
    if (!link.tunnel && !link.carrier) return proxyName;
    const stack = [proxyName, link.tunnel ? TUNNEL_NAME[link.tunnel] : null, link.carrier ? CARRIER_NAME[link.carrier] : null]
      .filter((part): part is string => Boolean(part))
      .join(' over ');
    return `${stack} · ${active ? 'active' : 'fallback'}`;
  }

  // Compact tooltip for a fallback square — it has no visible text of its
  // own, so the tooltip carries the same slash form the active chip shows as
  // text, e.g. "vless/ws/h2 (fallback)".
  function fallbackTooltip(link: WireLink): string {
    return `${wireFullText(link)} (fallback)`;
  }
</script>

{#if links.length}
  <span class="wire">
    {#each links as link, i (i)}
      {#if i > 0}<span class="arrow">›</span>{/if}
      {#if i === activeIdx}
        <span class="wchip-full {comboClass(link)} {carrierClass(link)}" title={fullStackTooltip(link, true)}>{wireFullText(link)}</span>
      {:else}
        <span class="wchip-sq {comboClass(link)} {carrierClass(link)}" title={fallbackTooltip(link)}></span>
      {/if}
    {/each}
  </span>
{/if}
