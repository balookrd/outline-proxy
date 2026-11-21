<script lang="ts">
  import type { Snippet } from 'svelte';
  import {
    createTable,
    tableFeatures,
    columnFilteringFeature,
    globalFilteringFeature,
    createFilteredRowModel,
    rowSortingFeature,
    createSortedRowModel,
    createColumnHelper,
    sortFn_basic,
  } from '@tanstack/svelte-table';
  import { initials } from '../../lib/format';
  import type { ClusterUser, User } from '../../lib/types';

  let {
    users,
    filter,
    clusterMode = false,
    rowActions,
  }: {
    users: Array<User | ClusterUser>;
    filter: string;
    clusterMode?: boolean;
    rowActions?: Snippet<[User | ClusterUser]>;
  } = $props();

  const features = tableFeatures({
    columnFilteringFeature,
    globalFilteringFeature,
    filteredRowModel: createFilteredRowModel(),
    rowSortingFeature,
    sortedRowModel: createSortedRowModel(),
  });

  const columnHelper = createColumnHelper<typeof features, User | ClusterUser>();
  const columns = columnHelper.columns([
    columnHelper.accessor((u) => u.id, {
      id: 'id',
      header: 'User',
      enableGlobalFilter: true,
      sortFn: sortFn_basic,
    }),
    columnHelper.accessor((u) => u.method ?? '', {
      id: 'method',
      header: 'Method',
      enableGlobalFilter: true,
      enableSorting: false,
    }),
  ]);

  const table = createTable({
    features,
    columns,
    get data() {
      return users;
    },
    getRowId: (u) => u.id,
  });

  $effect.pre(() => {
    table.setGlobalFilter(filter);
  });

  const rows = $derived(table.getRowModel().rows);

  let expandedSyncUser = $state<string | null>(null);

  function toggleSyncDetails(id: string) {
    expandedSyncUser = expandedSyncUser === id ? null : id;
  }

  function asCluster(u: User | ClusterUser): ClusterUser | null {
    return 'sync_status' in u ? (u as ClusterUser) : null;
  }

  function sortIndicator(dir: false | 'asc' | 'desc'): string {
    return dir === 'asc' ? '↑' : dir === 'desc' ? '↓' : '↕';
  }
  function ariaSort(dir: false | 'asc' | 'desc'): 'ascending' | 'descending' | 'none' {
    return dir === 'asc' ? 'ascending' : dir === 'desc' ? 'descending' : 'none';
  }
  function onSortKey(e: KeyboardEvent, columnId: string) {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      table.getColumn(columnId)?.toggleSorting();
    }
  }
</script>

<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
<div tabindex="0" role="region" aria-label="Users table" class="table-wrapper">
  <table>
    <thead>
      <tr>
        <th
          class="sortable"
          tabindex="0"
          aria-sort={ariaSort(table.getColumn('id')?.getIsSorted() ?? false)}
          onclick={() => table.getColumn('id')?.toggleSorting()}
          onkeydown={(e) => onSortKey(e, 'id')}
        >User {sortIndicator(table.getColumn('id')?.getIsSorted() ?? false)}</th>
        <th>Status</th>
        <th>Method</th>
        <th>Keys</th>
        {#if clusterMode}
          <th>Sync</th>
        {/if}
        <th>Actions</th>
      </tr>
    </thead>
    <tbody>
      {#each rows as row (row.id)}
        {@const u = row.original}
        {@const cu = clusterMode ? asCluster(u) : null}
        <tr>
          <td>
            <div class="id-cell">
              <span class="avatar">{initials(u.id)}</span>
              <span class="mono">{u.id}</span>
            </div>
          </td>
          <td>
            {#if u.enabled}
              <span class="chip ok"><span class="d"></span>active</span>
            {:else}
              <span class="chip bad"><span class="d"></span>blocked</span>
            {/if}
          </td>
          <td><span class="chip info">{u.method ?? 'default'}</span></td>
          <td>
            <div class="key-chips">
              {#if u.has_password}<span class="chip ok">SS</span>{/if}
              {#if u.has_vless_id}<span class="chip info">VLESS</span>{/if}
              {#if !u.has_password && !u.has_vless_id}<span class="chip off">none</span>{/if}
            </div>
          </td>
          {#if clusterMode && cu}
            <td>
              <button
                type="button"
                class="chip sync-btn"
                class:ok={cu.sync_status === 'synced'}
                class:warn={cu.sync_status === 'drift'}
                class:bad={cu.sync_status === 'partial'}
                class:off={cu.sync_status === 'unknown'}
                aria-expanded={expandedSyncUser === u.id}
                onclick={() => toggleSyncDetails(u.id)}
                title="Click to inspect per-node user sync details"
              >
                <span class="d"></span>
                {#if cu.sync_status === 'synced'}
                  Synced ({cu.present_on.length}/{cu.present_on.length})
                {:else if cu.sync_status === 'partial'}
                  Partial ({cu.present_on.length}/{cu.present_on.length + cu.missing_on.length})
                {:else if cu.sync_status === 'drift'}
                  Drift ({cu.diff_fields.join(', ')})
                {:else}
                  Unknown
                {/if}
              </button>
            </td>
          {/if}
          <td>
            {#if rowActions}
              <div class="rowactions">{@render rowActions(u)}</div>
            {/if}
          </td>
        </tr>
        {#if clusterMode && cu && expandedSyncUser === u.id}
          <tr class="sync-detail-row">
            <td colspan="6">
              <div class="sync-detail-box">
                <div>
                  <strong>Present on:</strong>
                  <span class="mono">{cu.present_on.join(', ') || '—'}</span>
                </div>
                {#if cu.missing_on.length}
                  <div>
                    <strong>Missing on:</strong>
                    <span class="mono">{cu.missing_on.join(', ')}</span>
                  </div>
                {/if}
                {#if cu.diff_fields.length}
                  <div>
                    <strong>Divergent fields:</strong>
                    <span class="mono">{cu.diff_fields.join(', ')}</span>
                  </div>
                {/if}
                {#if Object.keys(cu.per_node).length}
                  <div class="sync-per-node">
                    {#each Object.entries(cu.per_node) as [node, nu] (node)}
                      <span class="chip mono">
                        {node}: {nu.enabled ? 'active' : 'blocked'} · {nu.method ?? 'default'}
                        {#if nu.password_fp} · pw:{nu.password_fp.slice(0, 6)}{/if}
                        {#if nu.vless_id_fp} · vl:{nu.vless_id_fp.slice(0, 6)}{/if}
                      </span>
                    {/each}
                  </div>
                {/if}
              </div>
            </td>
          </tr>
        {/if}
      {/each}
      {#if !rows.length}
        <tr>
          <td colspan={clusterMode ? 6 : 5}>
            <div class="empty">{users.length ? 'No users match the current filter.' : 'No users yet.'}</div>
          </td>
        </tr>
      {/if}
    </tbody>
  </table>
</div>
