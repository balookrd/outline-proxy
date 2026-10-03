<script lang="ts">
  import { route, section, go } from '../../lib/router.svelte';

  const current = $derived(section(route.path));
  const clusterActive = $derived(route.path.startsWith('/ss/cluster'));
  const settingsActive = $derived(route.path.startsWith('/ss/settings'));
  const usersActive = $derived(current === 'ss' && !clusterActive && !settingsActive);
  const uplinksActive = $derived(route.path.startsWith('/ws/uplinks'));
  const routingActive = $derived(route.path.startsWith('/ws/routing'));
  const groupsActive = $derived(route.path.startsWith('/ws/groups'));
  const wsSettingsActive = $derived(route.path.startsWith('/ws/settings'));
  const topologyActive = $derived(current === 'ws' && !uplinksActive && !routingActive && !groupsActive && !wsSettingsActive);

  function onKey(e: KeyboardEvent, path: string) {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(path); }
  }
</script>

<nav class="sidebar">
  <div class="nav-group">Panels</div>
  <div
    class="navlink"
    class:active={current === 'landing'}
    role="button"
    tabindex="0"
    onclick={() => go('/')}
    onkeydown={(e) => onKey(e, '/')}
  >
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>
    Overview
  </div>

  <div class="nav-group">Server · SS</div>
  <div
    class="navlink"
    class:active={usersActive}
    role="button"
    tabindex="0"
    onclick={() => go('/ss')}
    onkeydown={(e) => onKey(e, '/ss')}
  >
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/></svg>
    Users
  </div>
  <div
    class="navlink"
    class:active={clusterActive}
    role="button"
    tabindex="0"
    onclick={() => go('/ss/cluster')}
    onkeydown={(e) => onKey(e, '/ss/cluster')}
  >
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="6" cy="6" r="3"/><circle cx="18" cy="6" r="3"/><circle cx="12" cy="18" r="3"/><path d="M8.5 7.5l5 7M15.5 7.5l-5 7M9 6h6"/></svg>
    Mesh cluster
  </div>
  <div
    class="navlink"
    class:active={settingsActive}
    role="button"
    tabindex="0"
    onclick={() => go('/ss/settings')}
    onkeydown={(e) => onKey(e, '/ss/settings')}
  >
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
    Settings
  </div>

  <div class="nav-group">Client · WS</div>
  <div
    class="navlink"
    class:active={topologyActive}
    role="button"
    tabindex="0"
    onclick={() => go('/ws')}
    onkeydown={(e) => onKey(e, '/ws')}
  >
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><path d="M12 7v4M12 11l-6 6M12 11l6 6"/></svg>
    Topology
  </div>
  <div
    class="navlink"
    class:active={uplinksActive}
    role="button"
    tabindex="0"
    onclick={() => go('/ws/uplinks')}
    onkeydown={(e) => onKey(e, '/ws/uplinks')}
  >
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 12h16M4 12l4-4M4 12l4 4M20 12l-4-4M20 12l-4 4"/></svg>
    Uplinks
  </div>
  <div
    class="navlink"
    class:active={routingActive}
    role="button"
    tabindex="0"
    onclick={() => go('/ws/routing')}
    onkeydown={(e) => onKey(e, '/ws/routing')}
  >
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12h4l3-8 4 16 3-8h4"/></svg>
    Routing
  </div>
  <div
    class="navlink"
    class:active={groupsActive}
    role="button"
    tabindex="0"
    onclick={() => go('/ws/groups')}
    onkeydown={(e) => onKey(e, '/ws/groups')}
  >
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/><path d="M7 14v3a1 1 0 0 0 1 1h3"/></svg>
    Uplink groups
  </div>
  <div
    class="navlink"
    class:active={wsSettingsActive}
    role="button"
    tabindex="0"
    onclick={() => go('/ws/settings')}
    onkeydown={(e) => onKey(e, '/ws/settings')}
  >
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
    Settings
  </div>

  <div class="foot">outline-ui</div>
</nav>
