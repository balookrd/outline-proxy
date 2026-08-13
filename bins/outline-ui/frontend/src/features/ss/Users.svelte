<script lang="ts">
  import { onDestroy } from 'svelte';
  import { listUsers, createUser, updateUser, deleteUser, blockUser, unblockUser } from '../../lib/api';
  import { createPoll } from '../../lib/poll.svelte';
  import { toast } from '../../lib/toast.svelte';
  import type { User, NewUser, PatchUser } from '../../lib/types';
  import InstanceSelector from '../../components/layout/InstanceSelector.svelte';
  import ErrorBanner from '../../components/layout/ErrorBanner.svelte';
  import UsersTable from './UsersTable.svelte';
  import UserDrawer from './UserDrawer.svelte';

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

  // Drawer (create/edit). `editingUser` is a snapshot taken at the moment
  // "Edit" is clicked, not a live binding into `users` — a background poll
  // refresh while the drawer is open must not overwrite an in-progress edit.
  let drawerOpen = $state(false);
  let editingUser = $state<User | null>(null);

  function openCreateDrawer() {
    editingUser = null;
    drawerOpen = true;
  }
  function openEditDrawer(user: User) {
    editingUser = user;
    drawerOpen = true;
  }
  function closeDrawer() {
    drawerOpen = false;
    editingUser = null;
  }

  function errorMessage(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
  }

  // Mirrors dashboard.html's setBusy() — a page-wide button lock while any
  // mutation is in flight, so a slow request can't be raced by a second
  // click (e.g. double-delete). Narrower than the original (only the
  // buttons below read it, not literally every <button> on the page) but
  // same intent.
  let mutating = $state(false);

  // Passed to UserDrawer as `onsave`. The drawer already validated and built
  // the payload (lib/userForm.ts); this does the actual API call, the
  // success/error toast, and — on success — closes the drawer and refetches
  // the list immediately instead of waiting for the next poll tick.
  async function saveUser(payload: NewUser | PatchUser, editingId: string | null) {
    mutating = true;
    try {
      if (editingId) {
        await updateUser(instance, editingId, payload as PatchUser);
        toast('User updated.');
      } else {
        await createUser(instance, payload as NewUser);
        toast('User created.');
      }
      closeDrawer();
      await usersPoll.refresh();
    } catch (e) {
      toast(errorMessage(e), 'error');
    } finally {
      mutating = false;
    }
  }

  async function toggleBlock(user: User) {
    mutating = true;
    try {
      const updated = user.enabled ? await blockUser(instance, user.id) : await unblockUser(instance, user.id);
      toast(`${updated.id} ${updated.enabled ? 'enabled' : 'blocked'}.`);
      await usersPoll.refresh();
    } catch (e) {
      toast(errorMessage(e), 'error');
    } finally {
      mutating = false;
    }
  }

  async function removeUser(user: User) {
    if (!confirm(`Delete user ${user.id}?`)) return;
    mutating = true;
    try {
      await deleteUser(instance, user.id);
      toast(`${user.id} deleted.`);
      await usersPoll.refresh();
    } catch (e) {
      toast(errorMessage(e), 'error');
    } finally {
      mutating = false;
    }
  }
</script>

<section class="view active">
  <div class="page-head">
    <div><h1>Users</h1><p>Shadowsocks access keys on the selected server.</p></div>
    <div class="toolbar">
      <InstanceSelector base="/ss" bind:selected={instance} bind:refreshSecs={refreshSecs} />
      <input type="search" placeholder="Search id / method…" bind:value={search} aria-label="Search users" />
      <button class="btn sm" disabled={!instance || mutating} onclick={openCreateDrawer}>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg> Add user
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
            <button class="iconbtn act-soft" title="Edit" disabled={mutating} aria-label={`Edit ${user.id}`} onclick={() => openEditDrawer(user)}>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>
            </button>
            <button
              class="iconbtn act-power"
              title={user.enabled ? 'Block' : 'Unblock'}
              disabled={mutating}
              aria-label={`${user.enabled ? 'Block' : 'Unblock'} ${user.id}`}
              onclick={() => toggleBlock(user)}
            >
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="m5.6 5.6 12.8 12.8"/></svg>
            </button>
            <button
              class="iconbtn act-danger"
              title="Delete"
              disabled={mutating}
              aria-label={`Delete ${user.id}`}
              onclick={() => removeUser(user)}
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

<UserDrawer open={drawerOpen} {editingUser} onclose={closeDrawer} onsave={saveUser} />
