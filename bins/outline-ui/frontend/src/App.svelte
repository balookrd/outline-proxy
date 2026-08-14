<script lang="ts">
  import Topbar from './components/layout/Topbar.svelte';
  import Sidebar from './components/layout/Sidebar.svelte';
  import Toasts from './components/layout/Toasts.svelte';
  import Landing from './features/landing/Landing.svelte';
  import Users from './features/ss/Users.svelte';
  import Uplinks from './features/ws/Uplinks.svelte';
  import Routing from './features/ws/Routing.svelte';
  import Topology from './features/ws/Topology.svelte';
  import { route, section } from './lib/router.svelte';

  const view = $derived(section(route.path));
  const isUplinks = $derived(route.path.startsWith('/ws/uplinks'));
  const isRouting = $derived(route.path.startsWith('/ws/routing'));
</script>

<div class="app">
  <Topbar />
  <Sidebar />
  <main class="main">
    {#if view === 'landing'}
      <Landing />
    {:else if view === 'ss'}
      <Users />
    {:else if isRouting}
      <Routing />
    {:else if isUplinks}
      <Uplinks />
    {:else}
      <Topology />
    {/if}
  </main>
</div>
<Toasts />
