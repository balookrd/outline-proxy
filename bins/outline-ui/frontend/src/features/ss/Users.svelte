<script lang="ts">
  import { onDestroy } from 'svelte';
  import { listUsers } from '../../lib/api';
  import { createPoll } from '../../lib/poll.svelte';
  import type { User } from '../../lib/types';
  import InstanceSelector from '../../components/layout/InstanceSelector.svelte';
  import ErrorBanner from '../../components/layout/ErrorBanner.svelte';
  import UsersTable from './UsersTable.svelte';

  let instance = $state('');
  let refreshSecs = $state(5);
  let search = $state('');

  const refreshMs = $derived(Math.max(1000, refreshSecs * 1000));

  // No instance selected yet → resolve to an empty list without hitting the
  // network (mirrors the old dashboard.html's loadUsers() guard).
  const usersPoll = createPoll(
    () => (instance ? listUsers(instance) : Promise.resolve<User[]>([])),
    () => refreshMs,
  );

  // Start on mount, and restart (re-fetch now + reset the interval) whenever
  // the selected instance changes, instead of waiting up to refreshMs for the
  // next scheduled tick.
  $effect(() => {
    void instance;
    usersPoll.start();
  });
  onDestroy(() => usersPoll.stop());

  const users = $derived(usersPoll.data ?? []);
</script>

<section class="view active">
  <div class="page-head">
    <div><h1>Users</h1><p>Shadowsocks access keys on the selected server.</p></div>
    <div class="toolbar">
      <InstanceSelector base="/ss" bind:selected={instance} bind:refreshSecs={refreshSecs} />
      <input type="search" placeholder="Search id / method…" bind:value={search} aria-label="Search users" />
      <button class="btn primary" disabled title="Create user — coming in a future task">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg> New user
      </button>
    </div>
  </div>

  {#if !instance}
    <div class="empty">Select a server to load users.</div>
  {:else}
    <ErrorBanner message={usersPoll.error} />
    {#if users.length}
      <div class="panel">
        <UsersTable {users} filter={search}>
          {#snippet rowActions(user: User)}
            <button class="iconbtn" title="Edit — coming in a future task" disabled aria-label={`Edit ${user.id}`}>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>
            </button>
            <button
              class="iconbtn"
              title={`${user.enabled ? 'Block' : 'Unblock'} — coming in a future task`}
              disabled
              aria-label={`${user.enabled ? 'Block' : 'Unblock'} ${user.id}`}
            >
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="m5.6 5.6 12.8 12.8"/></svg>
            </button>
            <button
              class="iconbtn danger"
              title="Delete — coming in a future task"
              disabled
              aria-label={`Delete ${user.id}`}
            >
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14"/></svg>
            </button>
          {/snippet}
        </UsersTable>
      </div>
    {:else if !usersPoll.error}
      <div class="empty">No users yet.</div>
    {/if}
  {/if}
</section>
