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
  // Task 10: action buttons are wired, but only via callback props
  // (onActivate/onEnable/onReselect) — this component still intentionally
  // does not import activate/reselect/setEnabled itself, nor lib/poll.svelte
  // or lib/toast.svelte. Topology.svelte owns the per-instance polls and is
  // the one place that knows which instance a given group belongs to (it's
  // the one iterating `listPoll.data.instances`), so it defines the actual
  // handlers (api call + toast + poll.refresh()) and passes bound closures
  // down; this component stays presentational, same division of labour as
  // features/ss/Users.svelte owning mutation state for UsersTable's rows.
  import type { Group, Uplink } from '../../lib/types';
  import { formatRtt, formatLossPct } from '../../lib/format';
  import {
    isUplinkActive,
    uplinkRowTone,
    uplinkRowLabel,
    uplinkRole,
    legWireChain,
    primaryRttMs,
    primaryLossRatio,
    lossTone,
    activateButtonState,
    softButtonState,
    groupFingerprintIsHomogeneous,
    groupFingerprintChip,
    uplinkFingerprintChip,
    rttTooltip,
    type RowTone,
    type ActivateButtonState,
    type SoftButtonState,
  } from '../../lib/wsTopology';
  import WireChain from './WireChain.svelte';
  import StatusDot from '../../components/layout/StatusDot.svelte';

  let {
    group,
    mutating = false,
    onActivate,
    onEnable,
    onReselect,
  }: {
    group: Group;
    // True while an operation Topology.svelte dispatched for this group's
    // instance is in flight — disables every button below so a slow request
    // can't be raced by a second click (mirrors features/ss/Users.svelte's
    // page-wide `mutating` lock, scoped to the instance instead of the whole
    // app since Topology shows every instance at once).
    mutating?: boolean;
    // soft=false is a hard Activate, soft=true is the soft-switch (⇄) button
    // — both ride POST /activate (dashboard.html activateEntries()), so one
    // callback covers both buttons.
    onActivate: (uplinkName: string, soft: boolean) => void;
    onEnable: (uplinkName: string, enabled: boolean) => void;
    onReselect: () => void;
  } = $props();

  const uplinks = $derived(group.uplinks ?? []);
  const activeCount = $derived(uplinks.filter(isUplinkActive).length);
  // `process_stable`/`random` fingerprint strategies give every uplink in
  // the group the same identity — one chip in the header (cfgChips below)
  // instead of repeating it on every row. `per_host_stable` (heterogeneous)
  // keeps the per-row chip instead — see each uprow's `fp` below.
  const fpHomogeneous = $derived(groupFingerprintIsHomogeneous(uplinks));

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
    title?: string;
  }
  const cfgChips = $derived.by((): Chip[] => {
    // Mode/Scope/auto-failback are all required, always-present fields
    // (topology.rs :63-65, no skip_serializing_if) — shown unconditionally,
    // auto-failback as an explicit on/off state rather than presence-only
    // like the skip_serializing_if fields below (cluster/bypass are absent,
    // not `false`, when off, so "not shown" already means off for those).
    // Tone assignment follows one rule: colour is reserved for a *live*
    // signal, everything else (a static config fact — mode/scope/cluster/
    // fingerprint identity) renders through the bare, already-neutral
    // `.chip` (owner: the header was "перегружена чипами" — too many
    // equally-loud colored pills competing with the actual status/wire
    // signal). Mode/Scope never had a tone to begin with; cluster and the
    // homogeneous fingerprint chip previously carried `tone: 'info'` (blue)
    // for no signal reason and are flattened to neutral here too.
    // auto-failback keeps a hint of colour since it's a live on/off toggle:
    // "on" gets app.css's `.chip.pos` (a faint positive tint, deliberately
    // fainter than the header's one real live count, `.chip.ok` on "N
    // active"); "off" was already muted via `.chip.off`.
    const chips: Chip[] = [
      { text: prettyMode(group.load_balancing_mode) },
      { text: prettyScope(group.routing_scope) },
      { text: `auto-failback: ${group.auto_failback ? 'on' : 'off'}`, tone: group.auto_failback ? 'pos' : 'off' },
    ];
    if (group.cluster_resume_enabled) chips.push({ text: 'cluster' });
    if (group.bypass_when_down) {
      const active = group.bypass_active_tcp || group.bypass_active_udp;
      chips.push({ text: active ? 'bypass: direct' : 'bypass armed', tone: active ? 'warn' : undefined });
    }
    // Homogeneous fingerprint identity (process_stable/random) — the
    // heterogeneous (per_host_stable) case renders per-row chips instead,
    // see the uprow loop below.
    if (fpHomogeneous) {
      const fp = groupFingerprintChip(uplinks);
      if (fp) chips.push({ text: fp.label, title: fp.title });
    }
    return chips;
  });

  // Status chip tone → app.css `.chip` modifier (good→ok, everything else
  // shares its name with the RowTone already).
  function chipTone(tone: RowTone): string {
    return tone === 'good' ? 'ok' : tone;
  }

  // Action-cell button copy for each activateButtonState()/softButtonState()
  // outcome — the long descriptive text lives in `title` (desktop tooltip,
  // mirrors dashboard.html's `data-tip`), `aria-label` stays the short
  // per-uplink form the rest of this app's icon buttons use (e.g.
  // features/ss/UsersTable.svelte's `Delete ${user.id}`).
  function activateCopy(uplink: Uplink, state: ActivateButtonState): { title: string; label: string } {
    if (state === 'active') return { title: 'Already active', label: `${uplink.name} is already active` };
    if (state === 'down') return { title: 'Down — every wire unreachable', label: `${uplink.name} is down` };
    return { title: 'Activate (hard switch)', label: `Activate ${uplink.name}` };
  }
  function softCopy(uplink: Uplink, state: SoftButtonState): { title: string; label: string } {
    if (state === 'active') return { title: 'Already active', label: `${uplink.name} is already active` };
    return { title: 'Soft switch (cluster resume)', label: `Soft switch to ${uplink.name}` };
  }
</script>

<div class="group">
  <div class="group-head">
    <span class="gname">{group.name}</span>
    <span class="gcount">{uplinks.length} uplink{uplinks.length === 1 ? '' : 's'}</span>
    <span class="cfgchips">
      {#each cfgChips as c}
        <span class="chip {c.tone ?? ''}" title={c.title}>{c.text}</span>
      {/each}
    </span>
    <div class="right">
      {#if group.global_active_reason}
        <span class="chip reason" title={group.global_active_reason}>{group.global_active_reason}</span>
      {/if}
      <span class="chip ok"><span class="d"></span>{activeCount} active</span>
      <button
        class="btn ghost sm"
        disabled={mutating}
        title="Reselect active uplink (weighted)"
        aria-label={`Reselect the active uplink for ${group.name}`}
        onclick={onReselect}
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
      {@const tcp = legWireChain(uplink, 'tcp')}
      {@const udp = legWireChain(uplink, 'udp')}
      {@const ratio = primaryLossRatio(uplink)}
      {@const rtt = primaryRttMs(uplink)}
      {@const rttTip = rttTooltip(uplink)}
      {@const fp = fpHomogeneous ? null : uplinkFingerprintChip(uplink)}
      <div class="uprow">
        <!-- Quick visual echo of the Status column: reuses the same
             uplinkRowTone()/StatusDot pairing the instance header uses
             (Topology.svelte) so the dot never drifts out of sync with the
             Status chip text just to the right. -->
        <div class="col-label"><span class="up-name"><StatusDot {tone} />{uplink.name}</span></div>
        <div><span class="chip {isUplinkActive(uplink) ? 'info' : ''}">{uplinkRole(uplink)}</span></div>
        <div>
          <span class="chip {chipTone(tone)}"><span class="d"></span>{uplinkRowLabel(tone)}</span>
          {#if uplink.last_error}
            <span class="chip bad" title={uplink.last_error} aria-label={`Error on ${uplink.name}: ${uplink.last_error}`}>⚠</span>
          {/if}
          {#if fp}
            <span class="chip info" title={fp.title}>{fp.label}</span>
          {/if}
        </div>
        <div title={uplink.active_tcp_reason ?? undefined}><WireChain links={tcp.links} activeIdx={tcp.activeIdx} /></div>
        <div title={uplink.active_udp_reason ?? undefined}><WireChain links={udp.links} activeIdx={udp.activeIdx} /></div>
        <div class="metric" title={rttTip || undefined}>{formatRtt(rtt)}</div>
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
            {@const activateState = activateButtonState(tone)}
            {@const activate = activateCopy(uplink, activateState)}
            <button
              class="iconbtn act-activate"
              disabled={activateState !== 'live' || mutating}
              title={activate.title}
              aria-label={activate.label}
              onclick={() => onActivate(uplink.name, false)}
            >
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m6 4 14 8-14 8Z"/></svg>
            </button>
            {@const softState = softButtonState(tone, Boolean(group.cluster_resume_enabled))}
            {#if softState !== 'hidden'}
              {@const soft = softCopy(uplink, softState)}
              <button
                class="iconbtn act-soft"
                disabled={softState !== 'live' || mutating}
                title={soft.title}
                aria-label={soft.label}
                onclick={() => onActivate(uplink.name, true)}
              >
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M7 7h11l-3-3M17 17H6l3 3"/></svg>
              </button>
            {/if}
          {/if}
          <button
            class="iconbtn act-power"
            disabled={mutating}
            title={uplink.admin_disabled ? 'Enable' : 'Disable'}
            aria-label={`${uplink.admin_disabled ? 'Enable' : 'Disable'} ${uplink.name}`}
            onclick={() => onEnable(uplink.name, uplink.admin_disabled)}
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
