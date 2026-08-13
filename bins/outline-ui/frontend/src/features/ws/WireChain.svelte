<script lang="ts">
  // Renders the ordered per-leg wire list as ONE chip per link — "vl xh h3"
  // together in a single pill, not three glued-together badges (owner
  // feedback on the old 3-badge layout on live ui2: "too busy" / the table
  // read as "перегружена чипами"). COMBO coloring:
  //   - transport (proxy) is the PRIMARY hue — the chip's text/tint/border
  //     (app.css `.wchip.vless`/`.wchip.ss`) — "what protocol is running".
  //   - tunnel (ws/xhttp) is a SECONDARY accent on the same chip — a
  //     coloured left edge (`.tun-ws`/`.tun-xhttp`) — not a second badge.
  //   - carrier (h3/h2/h1) stays visible as text but de-emphasised
  //     (`.wc-carrier` — lower opacity/weight): the fallback-degradation
  //     detail, not the headline.
  // Active link keeps the accent outline, same idea the old design used.
  // CSS lives in app.css's `.wire`/`.wchip.*`/`.wc-carrier`/`.arrow`.
  //
  // Purely presentational: `links` are already-resolved
  // {transport, tunnel, carrier} triples (see lib/wsTopology.ts's
  // legWireChain()/parseWireMode()), not raw uplink fields — this component
  // only knows how to draw them and build the per-link hover tooltip. The
  // proxy badge text itself (`vl`/`ss`) comes from wsTopology.ts's
  // proxyLabel() so the "lowercase, exactly vl/ss" rule lives in one place;
  // the transport→colour-class mapping below is presentation-only (single
  // consumer, unlike proxyLabel()) so it stays local rather than joining
  // wsTopology.ts's data-resolution helpers.
  import type { WireLink, Tunnel, Carrier } from '../../lib/wsTopology';
  import { proxyLabel } from '../../lib/wsTopology';

  let { links, activeIdx }: { links: WireLink[]; activeIdx: number } = $props();

  const PROXY_NAME: Record<string, string> = { vless: 'VLESS', ss: 'Shadowsocks' };
  const TUNNEL_NAME: Record<Exclude<Tunnel, null>, string> = { ws: 'WebSocket', xhttp: 'XHTTP' };
  const TUNNEL_TAG: Record<Exclude<Tunnel, null>, string> = { ws: 'ws', xhttp: 'xh' };
  const CARRIER_NAME: Record<Exclude<Carrier, null>, string> = { h3: 'HTTP/3', h2: 'HTTP/2', h1: 'HTTP/1.1' };

  // Full chip class string: base + transport colour + tunnel accent + active
  // state. Anything besides the two known proxies falls back to `.other` (a
  // neutral chip) rather than losing its styling entirely — mirrors
  // proxyLabel()'s own "don't silently vanish" fallback for an unrecognised
  // transport.
  function chipClass(link: WireLink, active: boolean): string {
    const transport = link.transport.toLowerCase();
    const transportClass = transport === 'vless' || transport === 'ss' ? transport : 'other';
    const tunnelClass = link.tunnel ? `tun-${link.tunnel}` : '';
    return ['wchip', transportClass, tunnelClass, active ? 'active' : 'inactive'].filter(Boolean).join(' ');
  }

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
      {#if i > 0}<span class="arrow">›</span>{/if}<span class={chipClass(link, i === activeIdx)} title={tooltip(link, i === activeIdx)}>{proxyLabel(link.transport)}{#if link.tunnel} {TUNNEL_TAG[link.tunnel]}{/if}{#if link.carrier}<span class="wc-carrier"> {link.carrier}</span>{/if}</span>
    {/each}
  </span>
{/if}
