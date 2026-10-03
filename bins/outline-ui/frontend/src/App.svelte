<script lang="ts">
  import Topbar from './components/layout/Topbar.svelte';
  import Sidebar from './components/layout/Sidebar.svelte';
  import Toasts from './components/layout/Toasts.svelte';
  import Landing from './features/landing/Landing.svelte';
  import Users from './features/ss/Users.svelte';
  import Cluster from './features/ss/Cluster.svelte';
  import ServerSettings from './features/ss/ServerSettings.svelte';
  import Uplinks from './features/ws/Uplinks.svelte';
  import Routing from './features/ws/Routing.svelte';
  import UplinkGroups from './features/ws/UplinkGroups.svelte';
  import Topology from './features/ws/Topology.svelte';
  import WsSettings from './features/ws/WsSettings.svelte';
  import { route, section } from './lib/router.svelte';

  const view = $derived(section(route.path));
  const isCluster = $derived(route.path.startsWith('/ss/cluster'));
  const isSettings = $derived(route.path.startsWith('/ss/settings'));
  const isUplinks = $derived(route.path.startsWith('/ws/uplinks'));
  const isRouting = $derived(route.path.startsWith('/ws/routing'));
  const isGroups = $derived(route.path.startsWith('/ws/groups'));
  const isWsSettings = $derived(route.path.startsWith('/ws/settings'));
</script>

<div class="app">
  <Topbar />
  <Sidebar />
  <main class="main">
    {#if view === 'landing'}
      <Landing />
    {:else if isCluster}
      <Cluster />
    {:else if isSettings}
      <ServerSettings />
    {:else if view === 'ss'}
      <Users />
    {:else if isRouting}
      <Routing />
    {:else if isGroups}
      <UplinkGroups />
    {:else if isUplinks}
      <Uplinks />
    {:else if isWsSettings}
      <WsSettings />
    {:else}
      <Topology />
    {/if}
  </main>
</div>
<Toasts />
