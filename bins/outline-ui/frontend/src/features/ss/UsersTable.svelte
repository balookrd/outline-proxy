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
  import type { User } from '../../lib/types';

  // Presentational: receives data + the search text from Users.svelte and
  // renders it. Row actions (edit/block/delete) are a snippet prop the parent
  // fills — Task 6 is read-only, so Users.svelte passes inert buttons; Task 7
  // wires the real ones without this component changing.
  let {
    users,
    filter,
    rowActions,
  }: {
    users: User[];
    filter: string;
    rowActions?: Snippet<[User]>;
  } = $props();

  // TanStack Table here (@tanstack/svelte-table 9.1.2 — the current "latest"
  // dist-tag already resolved to the Svelte-5-native rewrite; there was no
  // need to fall back to bare @tanstack/table-core, see task-6-report.md) is
  // used strictly headlessly: it owns sorting + global-filter row-model
  // computation only. Every cell below is hand-rendered from `row.original`
  // instead of going through column.cell/FlexRender, so the design-system
  // markup (chips, avatar, copy button) stays plain Svelte + app.css like the
  // rest of this app.
  const features = tableFeatures({
    // globalFilteringFeature and the filteredRowModel slot both formally
    // require columnFilteringFeature to be registered alongside them (see
    // node_modules/@tanstack/table-core/dist/types/TableFeatures.d.ts,
    // FeatureSlotPrereqs) even though this table has no per-column filter UI.
    columnFilteringFeature,
    globalFilteringFeature,
    filteredRowModel: createFilteredRowModel(),
    rowSortingFeature,
    sortedRowModel: createSortedRowModel(),
  });

  const columnHelper = createColumnHelper<typeof features, User>();
  // columnHelper.columns(...) (rather than a bare array literal) preserves
  // each column's individual TValue via variadic tuple inference — a plain
  // array here fails createTable's `columns` assignability check (parameters
  // of the per-column footer/cell templates end up contravariant-mismatched
  // once TValue is widened to `unknown`).
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
    columnHelper.accessor((u) => u.created ?? '', {
      id: 'created',
      header: 'Created',
      enableGlobalFilter: false,
      sortFn: sortFn_basic,
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

  // The search box lives in the parent's toolbar, not in this component, so
  // `globalFilter` is driven one-way from the `filter` prop instead of being
  // a table-controlled slice — nothing in here ever calls setGlobalFilter
  // itself. `$effect.pre` (not plain `$effect`) for the same reason
  // createTable's own internal option-sync effect uses it: the table needs
  // the new filter value applied before the DOM re-renders, or the old
  // (pre-filter) rows would flash for one frame.
  $effect.pre(() => {
    table.setGlobalFilter(filter);
  });

  const rows = $derived(table.getRowModel().rows);

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

  // Per-row transient "Copied" feedback — no toast system in this read-only
  // task, so a brief label swap on the button itself is enough.
  let copiedId = $state<string | null>(null);
  async function copyAccess(u: User) {
    if (!u.access_url) return;
    try {
      await navigator.clipboard.writeText(u.access_url);
      copiedId = u.id;
      setTimeout(() => {
        if (copiedId === u.id) copiedId = null;
      }, 1500);
    } catch {
      // Clipboard API can be unavailable (insecure context, denied
      // permission). Silent no-op: the button just doesn't flip to "Copied".
    }
  }
</script>

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
      <th>Access</th>
      <th
        class="sortable"
        tabindex="0"
        aria-sort={ariaSort(table.getColumn('created')?.getIsSorted() ?? false)}
        onclick={() => table.getColumn('created')?.toggleSorting()}
        onkeydown={(e) => onSortKey(e, 'created')}
      >Created {sortIndicator(table.getColumn('created')?.getIsSorted() ?? false)}</th>
      <th>Actions</th>
    </tr>
  </thead>
  <tbody>
    {#each rows as row (row.id)}
      {@const u = row.original}
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
          {#if u.access_url}
            <button class="btn ghost sm" title="Copy access URL" onclick={() => copyAccess(u)}>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>
              <span class="mono muted access-url">{copiedId === u.id ? 'Copied' : u.access_url}</span>
            </button>
          {:else}
            <span class="mono muted" title="No access URL configured">&mdash;</span>
          {/if}
        </td>
        <td class="mono muted">{u.created ?? '—'}</td>
        <td>
          {#if rowActions}
            <div class="rowactions">{@render rowActions(u)}</div>
          {/if}
        </td>
      </tr>
    {/each}
    {#if !rows.length}
      <tr><td colspan="6"><div class="empty">{users.length ? 'No users match the current filter.' : 'No users yet.'}</div></td></tr>
    {/if}
  </tbody>
</table>
