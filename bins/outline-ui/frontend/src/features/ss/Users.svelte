<script lang="ts">
  import { onDestroy } from 'svelte';
  import { listUsers, createUser, updateUser, deleteUser, blockUser, unblockUser, getDefaults } from '../../lib/api';
  import { createPoll } from '../../lib/poll.svelte';
  import { toast } from '../../lib/toast.svelte';
  import type { User, NewUser, PatchUser, ServerDefaults } from '../../lib/types';
  import InstanceSelector from '../../components/layout/InstanceSelector.svelte';
  import ErrorBanner from '../../components/layout/ErrorBanner.svelte';
  import UsersTable from './UsersTable.svelte';
  import UserDrawer from './UserDrawer.svelte';
  import { cloneUserFields } from '../../lib/userForm';
  import type { UserFormFields } from '../../lib/userForm';

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
  let seedFields = $state<UserFormFields | null>(null);
  let seedNeedsPassword = $state(false);

  // Stale-response guard for the drawer's open/close lifecycle. Plain `let`,
  // NOT `$state` — it is bookkeeping only, nothing renders from it.
  //
  // Why this exists: openCloneDrawer is async (it awaits getDefaults()
  // before writing seedFields/drawerOpen), and nothing disables the other
  // row buttons while that fetch is in flight. So the operator can click
  // Clone(A), then — before the fetch resolves — click Edit(B): editingUser
  // becomes B and the drawer opens on B synchronously. When Clone(A)'s
  // fetch then resolves, its continuation would (without this guard) still
  // run `seedFields = cloneUserFields(A, defaults)`. UserDrawer's prefill
  // $effect reads seedFields and assumes editingUser/seedFields stay stable
  // for as long as `open` is true; a new seedFields identity re-triggers it
  // while editingUser is still B, so it takes the edit branch and reassigns
  // `fields = fieldsFromUser(B)` — silently discarding whatever the
  // operator just typed — and refocuses the id input mid-edit. The same
  // staleness lets two Clone clicks in flight seed the drawer from the
  // wrong template if the older response lands last.
  //
  // Every function that opens or closes the drawer bumps this counter at
  // entry. openCloneDrawer captures the value it saw at entry and re-checks
  // it after the await: if a newer open/close has since run, this request
  // has been superseded and must bail out untouched.
  let drawerGeneration = 0;

  function openCreateDrawer() {
    drawerGeneration++;
    editingUser = null;
    seedFields = null;
    seedNeedsPassword = false;
    drawerOpen = true;
  }
  function openEditDrawer(user: User) {
    drawerGeneration++;
    editingUser = user;
    seedFields = null;
    seedNeedsPassword = false;
    drawerOpen = true;
  }
  async function openCloneDrawer(user: User) {
    const generation = ++drawerGeneration;
    // Snapshot the template into seed fields (fresh secrets, blank id/aliases);
    // create-mode drawer (editingUser stays null) prefilled from it. The
    // server's defaults fill whatever the template leaves unset — without them
    // a user running on defaults would clone into a blank form with no
    // password (the UI cannot pick a cipher it does not know).
    editingUser = null;
    seedNeedsPassword = Boolean(user.has_password);
    let defaults: ServerDefaults | null = null;
    try {
      defaults = await getDefaults(instance);
    } catch (e) {
      // Only surface the toast if this request is still current — if a
      // newer open/close superseded it, the operator already moved on and a
      // toast about an abandoned clone would just be noise.
      if (generation === drawerGeneration) {
        toast(`Could not load server defaults: ${errorMessage(e)}`, 'error');
      }
    }
    // Bail out without touching seedFields/drawerOpen if a newer open/close
    // ran while this fetch was in flight — see drawerGeneration above.
    if (generation !== drawerGeneration) return;
    seedFields = cloneUserFields(user, defaults);
    drawerOpen = true;
  }
  function closeDrawer() {
    drawerGeneration++;
    drawerOpen = false;
    editingUser = null;
    seedFields = null;
    seedNeedsPassword = false;
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
            <button class="iconbtn act-activate" title="Clone" disabled={mutating} aria-label={`Clone ${user.id}`} onclick={() => openCloneDrawer(user)}>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>
            </button>
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

<UserDrawer open={drawerOpen} {editingUser} {seedFields} {seedNeedsPassword} onclose={closeDrawer} onsave={saveUser} />
