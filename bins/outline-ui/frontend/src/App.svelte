<script lang="ts">
  import Topbar from './components/layout/Topbar.svelte';
  import Sidebar from './components/layout/Sidebar.svelte';
  import Landing from './features/landing/Landing.svelte';
  import { route, section } from './lib/router.svelte';

  const view = $derived(section(route.path));
  const isUplinks = $derived(route.path.startsWith('/ws/uplinks'));
</script>

<div class="app">
  <Topbar />
  <Sidebar />
  <main class="main">
    {#if view === 'landing'}
      <Landing />
    {:else if view === 'ss'}
      <!-- TEMPORARY: real Users panel arrives in Task 6 (swap this section for <Users />) -->
      <section class="view active">
        <div class="empty">Users panel — arrives in Task 6</div>
      </section>
    {:else if isUplinks}
      <!-- TEMPORARY: real Uplinks CRUD arrives in Task 8 (swap this section for <Uplinks />) -->
      <section class="view active">
        <div class="empty">Uplinks — Task 8</div>
      </section>
    {:else}
      <!-- TEMPORARY: real Topology view arrives in Task 9 (swap this section for <Topology />) -->
      <section class="view active">
        <div class="empty">Topology — Task 9</div>
      </section>
    {/if}
  </main>
</div>
