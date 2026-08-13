<script lang="ts">
  // Renders the ordered per-leg wire list as "Variant B" pills — a small
  // proxy badge (vl/ss) + tunnel badge (ws/xh) in front of the main carrier
  // pill (h3/h2/h1), joined by `›` arrows, the active link outlined. Layer
  // vocabulary/visual shape from the wire-redesign mockup's Variant B
  // (proxy over tunnel over carrier); CSS from app.css's
  // `.wire`/`.wlink`/`.wtag.*`/`.seg.*`/`.arrow`.
  //
  // Purely presentational: `links` are already-resolved
  // {transport, tunnel, carrier} triples (see lib/wsTopology.ts's
  // legWireChain()/parseWireMode()), not raw uplink fields — this component
  // only knows how to draw them and build the per-link hover tooltip. The
  // proxy badge text itself (`vl`/`ss`) comes from wsTopology.ts's
  // proxyLabel() so the "lowercase, exactly vl/ss" rule lives in one place.
  import type { WireLink, Tunnel, Carrier } from '../../lib/wsTopology';
  import { proxyLabel } from '../../lib/wsTopology';

  let { links, activeIdx }: { links: WireLink[]; activeIdx: number } = $props();

  const PROXY_NAME: Record<string, string> = { vless: 'VLESS', ss: 'Shadowsocks' };
  const TUNNEL_NAME: Record<Exclude<Tunnel, null>, string> = { ws: 'WebSocket', xhttp: 'XHTTP' };
  const TUNNEL_TAG: Record<Exclude<Tunnel, null>, string> = { ws: 'ws', xhttp: 'xh' };
  const CARRIER_NAME: Record<Exclude<Carrier, null>, string> = { h3: 'HTTP/3', h2: 'HTTP/2', h1: 'HTTP/1.1' };

  // Full stack + state, e.g. "VLESS over WebSocket over HTTP/3 · active".
  // Falls back to the bare proxy name (e.g. "Shadowsocks") when neither
  // tunnel nor carrier resolved — a wire with genuinely no mode field.
  function tooltip(link: WireLink, active: boolean): string {
    const proxyName = PROXY_NAME[link.transport.toLowerCase()] ?? link.transport;
    if (!link.tunnel && !link.carrier) return proxyName;
    const stack = [proxyName, link.tunnel ? TUNNEL_NAME[link.tunnel] : null, link.carrier ? CARRIER_NAME[link.carrier] : null]
      .filter((part): part is string => Boolean(part))
      .join(' over ');
    return `${stack} · ${active ? 'active' : 'fallback'}`;
  }
</script>

{#if links.length}
  <span class="wire">
    {#each links as link, i (i)}
      {#if i > 0}<span class="arrow">›</span>{/if}
      <span class="wlink {i === activeIdx ? 'active' : 'inactive'}" title={tooltip(link, i === activeIdx)}>
        <span class="wtag proxy">{proxyLabel(link.transport)}</span>
        {#if link.tunnel}<span class="wtag tunnel">{TUNNEL_TAG[link.tunnel]}</span>{/if}
        {#if link.carrier}<span class="seg {link.carrier}">{link.carrier}</span>{/if}
      </span>
    {/each}
  </span>
{/if}
