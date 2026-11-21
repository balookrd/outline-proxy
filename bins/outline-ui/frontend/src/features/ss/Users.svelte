<script lang="ts">
  import { onDestroy } from 'svelte';
  import {
    ApiError,
    listUsers, createUser, updateUser, deleteUser, blockUser, unblockUser, getDefaults,
    listClusterUsers, getClusterDefaults, createClusterUser, updateClusterUser,
    deleteClusterUser, blockClusterUser, unblockClusterUser,
    regenerateAccessKeys, regenerateClusterAccessKeys,
  } from '../../lib/api';
  import { createPoll } from '../../lib/poll.svelte';
  import { toast } from '../../lib/toast.svelte';
  import { ssTargetState, getClusterSummary } from '../../lib/ssTarget.svelte';
  import type {
    ClusterUser,
    ClusterUsersResponse,
    NewUser,
    NodeActionResult,
    PatchUser,
    ServerDefaults,
    User,
  } from '../../lib/types';
  import SsTargetSelector from '../../components/layout/SsTargetSelector.svelte';
  import ErrorBanner from '../../components/layout/ErrorBanner.svelte';
  import ConfirmDialog from '../../components/layout/ConfirmDialog.svelte';
  import UsersTable from './UsersTable.svelte';
  import UserDrawer from './UserDrawer.svelte';
  import ClusterStatusStrip from './ClusterStatusStrip.svelte';
  import PerNodeResultPanel from './PerNodeResultPanel.svelte';
  import AccessKeysModal from './AccessKeysModal.svelte';
  import { cloneUserFields } from '../../lib/userForm';
  import type { UserFormFields } from '../../lib/userForm';

  const target = $derived(ssTargetState.target);
  const isCluster = $derived(target?.kind === 'cluster');
  const clusterSummary = $derived(
    target?.kind === 'cluster' ? getClusterSummary(target.name) : null,
  );
  const refreshMs = $derived(Math.max(1000, ssTargetState.refreshSecs * 1000));

  let search = $state('');
  let defaultMethod = $state('');
  let actionResults = $state<NodeActionResult[]>([]);
  let actionResultsTitle = $state('');
  let regenerating = $state(false);

  // Links modal state
  let linksModalOpen = $state(false);
  let linksUserId = $state<string | null>(null);
  let createdShowLinksBanner = $state<string | null>(null);

  // Confirm delete dialog state
  let confirmDeleteUser = $state<User | null>(null);
  let confirmDeleteOpen = $derived(confirmDeleteUser !== null);

  type PollData =
    | { kind: 'single'; users: User[] }
    | { kind: 'cluster'; payload: ClusterUsersResponse }
    | null;

  const usersPoll = createPoll<PollData>(
    async () => {
      if (!target) return null;
      if (target.kind === 'cluster') {
        const payload = await listClusterUsers(target.name);
        return { kind: 'cluster', payload };
      }
      const users = await listUsers(target.name);
      return { kind: 'single', users };
    },
    () => refreshMs,
  );

  $effect(() => {
    const t = target;
    actionResults = [];
    createdShowLinksBanner = null;
    defaultMethod = '';
    if (t) {
      const fetchDefaults =
        t.kind === 'cluster' ? getClusterDefaults(t.name) : getDefaults(t.name);
      fetchDefaults
        .then((d) => {
          if (target?.kind === t.kind && target?.name === t.name) {
            defaultMethod = d.method;
          }
        })
        .catch(() => {});
    }
    usersPoll.start();
  });
  onDestroy(() => usersPoll.stop());

  const users = $derived.by<Array<User | ClusterUser>>(() => {
    if (!usersPoll.data) return [];
    return usersPoll.data.kind === 'cluster'
      ? usersPoll.data.payload.users
      : usersPoll.data.users;
  });

  const clusterPayload = $derived(
    usersPoll.data?.kind === 'cluster' ? usersPoll.data.payload : null,
  );

  const pollError = $derived.by(() => {
    if (usersPoll.error) return usersPoll.error;
    if (clusterPayload?.node_errors?.length) {
      return clusterPayload.node_errors.map((e) => `${e.instance}: ${e.error}`).join('; ');
    }
    return null;
  });

  let drawerOpen = $state(false);
  let editingUser = $state<User | null>(null);
  let seedFields = $state<UserFormFields | null>(null);
  let seedNeedsPassword = $state(false);
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
    if (!target) return;
    const generation = ++drawerGeneration;
    editingUser = null;
    seedNeedsPassword = Boolean(user.has_password);
    let defaults: ServerDefaults | null = null;
    try {
      defaults =
        target.kind === 'cluster'
          ? await getClusterDefaults(target.name)
          : await getDefaults(target.name);
    } catch (e) {
      if (generation === drawerGeneration) {
        toast(`Could not load server defaults: ${errorMessage(e)}`, 'error');
      }
    }
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

  function openLinksModal(uid: string) {
    linksUserId = uid;
    linksModalOpen = true;
  }

  function errorMessage(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
  }

  function extractResults(e: unknown): NodeActionResult[] {
    if (e instanceof ApiError && e.body && typeof e.body === 'object' && 'results' in e.body) {
      const r = (e.body as { results?: unknown }).results;
      if (Array.isArray(r)) return r as NodeActionResult[];
    }
    return [];
  }

  let mutating = $state(false);

  async function autoPruneSubscriptions(quiet = true) {
    if (!target) return;
    try {
      if (target.kind === 'cluster') {
        const res = await regenerateClusterAccessKeys(target.name, { prune: true });
        if (!quiet) {
          actionResultsTitle = `Subscriptions regenerated across ${target.name}`;
          actionResults = res.results;
          toast('Subscriptions regenerated and pruned.');
        }
      } else {
        const rep = await regenerateAccessKeys(target.name, { prune: true });
        if (!quiet) {
          toast(`Subscriptions regenerated (${rep.written?.length ?? 0} written, ${rep.pruned?.length ?? 0} pruned).`);
        }
      }
    } catch (e) {
      const results = extractResults(e);
      if (e instanceof ApiError && e.status === 501) {
        if (!quiet) toast('Access-keys generator is not configured on server.', 'error');
        return;
      }
      if (!quiet) {
        if (results.length) {
          actionResultsTitle = 'Subscription regeneration failed';
          actionResults = results;
        }
        toast(`Subscription regeneration failed: ${errorMessage(e)}`, 'error');
      } else {
        toast(`User saved, but subscription sync failed: ${errorMessage(e)}`, 'error');
      }
    }
  }

  async function manualRegenerate() {
    if (!target) return;
    regenerating = true;
    try {
      await autoPruneSubscriptions(false);
    } finally {
      regenerating = false;
    }
  }

  async function saveUser(payload: NewUser | PatchUser, editingId: string | null) {
    if (!target) return;
    mutating = true;
    actionResults = [];
    try {
      if (target.kind === 'cluster') {
        const res = editingId
          ? await updateClusterUser(target.name, editingId, payload as PatchUser)
          : await createClusterUser(target.name, payload as NewUser);
        actionResultsTitle = editingId
          ? `Updated ${editingId} on ${target.name}`
          : `Created ${payload.id} on ${target.name}`;
        actionResults = res.results;
        toast(editingId ? 'User updated across cluster.' : 'User created across cluster.');
      } else if (editingId) {
        await updateUser(target.name, editingId, payload as PatchUser);
        toast('User updated.');
      } else {
        await createUser(target.name, payload as NewUser);
        toast('User created.');
      }
      const createdId = editingId ? null : String(payload.id ?? '');
      closeDrawer();
      await usersPoll.refresh();
      await autoPruneSubscriptions(true);
      if (createdId) {
        createdShowLinksBanner = createdId;
      }
    } catch (e) {
      const results = extractResults(e);
      if (results.length) {
        actionResultsTitle = editingId ? `Update ${editingId} failed` : 'Cluster create failed';
        actionResults = results;
      }
      toast(errorMessage(e), 'error');
    } finally {
      mutating = false;
    }
  }

  async function toggleBlock(user: User) {
    if (!target) return;
    mutating = true;
    actionResults = [];
    try {
      if (target.kind === 'cluster') {
        const res = user.enabled
          ? await blockClusterUser(target.name, user.id)
          : await unblockClusterUser(target.name, user.id);
        actionResultsTitle = `${user.enabled ? 'Blocked' : 'Unblocked'} ${user.id} on ${target.name}`;
        actionResults = res.results;
        toast(`${user.id} ${user.enabled ? 'blocked' : 'enabled'} across cluster.`);
      } else {
        const updated = user.enabled
          ? await blockUser(target.name, user.id)
          : await unblockUser(target.name, user.id);
        toast(`${updated.id} ${updated.enabled ? 'enabled' : 'blocked'}.`);
      }
      await usersPoll.refresh();
      await autoPruneSubscriptions(true);
    } catch (e) {
      const results = extractResults(e);
      if (results.length) {
        actionResultsTitle = `${user.enabled ? 'Block' : 'Unblock'} ${user.id} partial failure`;
        actionResults = results;
      }
      toast(errorMessage(e), 'error');
    } finally {
      mutating = false;
    }
  }

  async function performDelete(user: User) {
    if (!target) return;
    mutating = true;
    actionResults = [];
    try {
      if (target.kind === 'cluster') {
        const res = await deleteClusterUser(target.name, user.id);
        actionResultsTitle = `Deleted ${user.id} on ${target.name}`;
        actionResults = res.results;
        toast(`${user.id} deleted across cluster.`);
      } else {
        await deleteUser(target.name, user.id);
        toast(`${user.id} deleted.`);
      }
      if (createdShowLinksBanner === user.id) createdShowLinksBanner = null;
      await usersPoll.refresh();
      await autoPruneSubscriptions(true);
    } catch (e) {
      const results = extractResults(e);
      if (results.length) {
        actionResultsTitle = `Delete ${user.id} failed`;
        actionResults = results;
      }
      toast(errorMessage(e), 'error');
    } finally {
      mutating = false;
    }
  }
</script>

<section class="view active">
  <div class="page-head">
    <div>
      <h1>Users</h1>
      <p>
        {isCluster
          ? `Manage users and subscription links synchronously across cluster ${target?.name}.`
          : 'Shadowsocks & VLESS access keys on the selected server.'}
      </p>
    </div>
    <div class="toolbar">
      <SsTargetSelector />
      <input type="search" placeholder="Search id / method…" bind:value={search} aria-label="Search users" />
      {#if !isCluster}
        <button
          type="button"
          class="btn sm"
          disabled={!target || mutating || regenerating}
          onclick={manualRegenerate}
          title="Regenerate subscription artifacts and prune deleted/disabled users"
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-2.64-6.36M21 3v6h-6"/></svg>
          {regenerating ? 'Regenerating…' : 'Regenerate'}
        </button>
      {/if}
      <button class="btn primary sm" disabled={!target || mutating} onclick={openCreateDrawer}>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg> Add user
      </button>
    </div>
  </div>

  {#if !target}
    <div class="empty">Select a cluster or server to load users.</div>
  {:else}
    {#if isCluster && clusterSummary}
      <ClusterStatusStrip
        cluster={clusterSummary}
        reachableNodes={clusterPayload?.reachable_nodes ?? clusterSummary.members.length}
        totalNodes={clusterPayload?.total_nodes ?? clusterSummary.members.length}
        {regenerating}
        onRegenerate={manualRegenerate}
      />
    {/if}

    <ErrorBanner message={pollError} />

    {#if createdShowLinksBanner}
      <div class="info-banner" role="status">
        <span>User <strong class="mono">{createdShowLinksBanner}</strong> created. Open subscription links &amp; QR code?</span>
        <span class="spacer"></span>
        <button type="button" class="btn primary sm" onclick={() => openLinksModal(createdShowLinksBanner!)}>
          Show links
        </button>
        <button type="button" class="btn ghost sm" onclick={() => (createdShowLinksBanner = null)}>Dismiss</button>
      </div>
    {/if}

    <PerNodeResultPanel
      title={actionResultsTitle}
      results={actionResults}
      onDismiss={() => (actionResults = [])}
    />

    {#if users.length}
      <div class="panel">
        <UsersTable {users} filter={search} clusterMode={isCluster}>
          {#snippet rowActions(user: User | ClusterUser)}
            <button
              class="iconbtn act-soft"
              title="Show links & QR"
              disabled={mutating || !user.enabled}
              aria-label={`Links for ${user.id}`}
              onclick={() => openLinksModal(user.id)}
            >
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
            </button>
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
              onclick={() => (confirmDeleteUser = user)}
            >
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14"/></svg>
            </button>
          {/snippet}
        </UsersTable>
      </div>
    {:else if !pollError}
      <div class="empty">No users yet.</div>
    {/if}
  {/if}
</section>

<UserDrawer
  open={drawerOpen}
  {editingUser}
  {seedFields}
  {seedNeedsPassword}
  {defaultMethod}
  clusterName={isCluster ? target?.name ?? null : null}
  clusterMembers={clusterSummary?.members ?? []}
  onclose={closeDrawer}
  onsave={saveUser}
/>

<AccessKeysModal
  bind:open={linksModalOpen}
  {target}
  userId={linksUserId}
  onclose={() => (linksUserId = null)}
/>

<ConfirmDialog
  open={confirmDeleteOpen}
  title={isCluster ? `Delete ${confirmDeleteUser?.id ?? ''} across cluster?` : `Delete ${confirmDeleteUser?.id ?? ''}?`}
  message={isCluster
    ? `This removes user "${confirmDeleteUser?.id ?? ''}" from all nodes of cluster "${target?.name ?? ''}" and prunes their subscription files.`
    : `This removes user "${confirmDeleteUser?.id ?? ''}" and prunes their subscription files.`}
  confirmLabel="Delete"
  danger={true}
  onconfirm={() => {
    const u = confirmDeleteUser;
    confirmDeleteUser = null;
    if (u) void performDelete(u);
  }}
  oncancel={() => (confirmDeleteUser = null)}
/>
