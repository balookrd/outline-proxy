<script lang="ts">
  // One uplink group's table: header (name, config chips, active count,
  // group-level Reselect) + a `--topo-cols` grid of uplink rows. Visual shape
  // from the prototype's `.group`/`.group-head`/`.colhead-row`/`.uprow`
  // (spec 2026-08-12-outline-ui-svelte-rewrite-prototype.html:500-529); the
  // field extraction and gating below reproduce
  // bins/outline-ui/src/ws/dashboard.html's renderInstanceBody() (:1260-1387)
  // — isActive/healthy/admin_disabled/last_error and the activateBtn/softBtn/
  // powerBtn presence rules — via lib/wsTopology.ts.
  //
  // READ-ONLY (Task 9): every action button below is rendered `disabled`.
  // Task 10 wires Activate/Soft/Power/Reselect to the real API calls; this
  // component intentionally does not import activate/reselect/setEnabled.
  import type { Group, Uplink } from '../../lib/types';
  import { formatRtt, formatLossPct } from '../../lib/format';
  import {
    isUplinkActive,
    uplinkRowTone,
    uplinkRowLabel,
    uplinkRole,
    legWireSegments,
    primaryRttMs,
    primaryLossRatio,
    lossTone,
    type RowTone,
  } from '../../lib/wsTopology';
  import WireChain from './WireChain.svelte';

  let { group }: { group: Group } = $props();

  const uplinks = $derived(group.uplinks ?? []);
  const activeCount = $derived(uplinks.filter(isUplinkActive).length);

  // dashboard.html prettyMode()/prettyScope() (:555-567).
  function prettyMode(mode?: string): string {
    const v = (mode ?? '').toLowerCase();
    if (v === 'active_passive') return 'Active / Passive';
    if (v === 'active_active') return 'Active / Active';
    return mode || '—';
  }
  function prettyScope(scope?: string): string {
    const v = (scope ?? '').toLowerCase();
    if (v === 'global') return 'Global';
    if (v === 'per_uplink') return 'Per uplink';
    if (v === 'per_flow') return 'Per flow';
    return scope || '—';
  }

  // Config chips: Mode/Scope always (every group has a concrete value for
  // both), the rest presence-only — mirrors the prototype's short
  // notable-feature-flags list (`cfg: ["cluster", "padding"]`) more than
  // dashboard.html's always-on-or-off chip row, since app.css only carries
  // the prototype's plain `.chip` (no dashboard.html `.cfg-chip` variants).
  interface Chip {
    text: string;
    tone?: string;
  }
  const cfgChips = $derived.by((): Chip[] => {
    const chips: Chip[] = [{ text: prettyMode(group.load_balancing_mode) }, { text: prettyScope(group.routing_scope) }];
    if (group.cluster_resume_enabled) chips.push({ text: 'cluster', tone: 'info' });
    if (group.auto_failback) chips.push({ text: 'auto-failback', tone: 'info' });
    if (group.bypass_when_down) {
      const active = group.bypass_active_tcp || group.bypass_active_udp;
      chips.push({ text: active ? 'bypass: direct' : 'bypass armed', tone: active ? 'warn' : undefined });
    }
    return chips;
  });

  // Status chip tone → app.css `.chip` modifier (good→ok, everything else
  // shares its name with the RowTone already).
  function chipTone(tone: RowTone): string {
    return tone === 'good' ? 'ok' : tone;
  }

  // dashboard.html's softBtn gating (:1351-1357): cluster groups only, and
  // only on an enabled row that isn't already active (rendered
  // present-but-disabled on the already-active row, absent on Down/Disabled).
  function showSoft(u: Uplink, tone: RowTone): boolean {
    return !u.admin_disabled && Boolean(group.cluster_resume_enabled) && (tone === 'good' || tone === 'warn');
  }
</script>

<div class="group">
  <div class="group-head">
    <span class="gname">{group.name}</span>
    <span class="gcount">{uplinks.length} uplink{uplinks.length === 1 ? '' : 's'}</span>
    <span class="cfgchips">
      {#each cfgChips as c}
        <span class="chip {c.tone ?? ''}">{c.text}</span>
      {/each}
    </span>
    <div class="right">
      <span class="chip ok"><span class="d"></span>{activeCount} active</span>
      <button
        class="btn ghost sm"
        disabled
        title="Reselect active uplink (weighted)"
        aria-label={`Reselect the active uplink for ${group.name}`}
      >
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-3-6.7L21 8M21 3v5h-5"/></svg> Reselect
      </button>
    </div>
  </div>

  {#if uplinks.length}
    <div class="colhead-row">
      <div>Uplink</div>
      <div>Role</div>
      <div>Status</div>
      <div>TCP wire chain</div>
      <div>UDP wire chain</div>
      <div>RTT</div>
      <div>Loss · Wt</div>
      <div>Action</div>
    </div>
    {#each uplinks as uplink (uplink.name)}
      {@const tone = uplinkRowTone(uplink)}
      {@const tcp = legWireSegments(uplink, 'tcp')}
      {@const udp = legWireSegments(uplink, 'udp')}
      {@const ratio = primaryLossRatio(uplink)}
      {@const rtt = primaryRttMs(uplink)}
      <div class="uprow">
        <div class="col-label"><span class="up-name">{uplink.name}</span></div>
        <div><span class="chip {isUplinkActive(uplink) ? 'info' : ''}">{uplinkRole(uplink)}</span></div>
        <div>
          <span class="chip {chipTone(tone)}"><span class="d"></span>{uplinkRowLabel(tone)}</span>
          {#if uplink.last_error}
            <span class="chip bad" title={uplink.last_error} aria-label={`Error on ${uplink.name}: ${uplink.last_error}`}>⚠</span>
          {/if}
        </div>
        <div><WireChain segments={tcp.segments} activeIdx={tcp.activeIdx} /></div>
        <div><WireChain segments={udp.segments} activeIdx={udp.activeIdx} /></div>
        <div class="metric">{formatRtt(rtt)}</div>
        <div>
          {#if ratio == null}
            <span class="muted mono">—</span>
          {:else}
            <span class="metric {lossTone(ratio)}">{formatLossPct(ratio * 100)}</span>
          {/if}
          <span class="muted mono">· {typeof uplink.weight === 'number' ? uplink.weight : '—'}</span>
        </div>
        <div class="actioncell">
          {#if !uplink.admin_disabled}
            <button class="iconbtn" disabled title="Activate" aria-label={`Activate ${uplink.name}`}>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m6 4 14 8-14 8Z"/></svg>
            </button>
            {#if showSoft(uplink, tone)}
              <button class="iconbtn" disabled title="Soft switch (cluster resume)" aria-label={`Soft switch to ${uplink.name}`}>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M7 7h11l-3-3M17 17H6l3 3"/></svg>
              </button>
            {/if}
          {/if}
          <button
            class="iconbtn"
            disabled
            title={uplink.admin_disabled ? 'Enable' : 'Disable'}
            aria-label={`${uplink.admin_disabled ? 'Enable' : 'Disable'} ${uplink.name}`}
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3v9M6.4 6.4a8 8 0 1 0 11.2 0"/></svg>
          </button>
        </div>
      </div>
    {/each}
  {:else}
    <div class="empty">No uplinks in this group.</div>
  {/if}
</div>
