import { describe, it, expect } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import Toasts from '../../components/layout/Toasts.svelte';
import Users from './Users.svelte';
import { ssTargetState } from '../../lib/ssTarget.svelte';
import { makeClusterMutationResponse, makeClusterUsersResponse } from '../../test/fixtures';
import { installFetchMock } from '../../test/mockApi';

describe('Users view (SS)', () => {
  it('renders cluster strip, sync badges, search filter, and sorting', async () => {
    installFetchMock();
    const user = userEvent.setup();
    render(Users);

    expect(await screen.findByText('alice')).toBeInTheDocument();
    expect(screen.getByText('2/2 nodes online')).toBeInTheDocument();
    expect(screen.getByText('Synced (2/2)')).toBeInTheDocument();
    expect(screen.getByText('Partial (1/2)')).toBeInTheDocument();
    expect(screen.getByText('Drift (password)')).toBeInTheDocument();

    // Disabled user's links button must be disabled
    expect(screen.getByRole('button', { name: 'Links for charlie' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Links for alice' })).toBeEnabled();

    // Search filter narrows rows
    const searchInput = screen.getByLabelText('Search users');
    await user.type(searchInput, 'bob');
    expect(screen.queryByText('alice')).not.toBeInTheDocument();
    expect(screen.getByText('bob')).toBeInTheDocument();

    await user.clear(searchInput);
    expect(screen.getByText('alice')).toBeInTheDocument();

    // Clicking sortable User header flips sort order
    const userHeader = screen.getByRole('columnheader', { name: /User/ });
    await user.click(userHeader);
    expect(userHeader).toHaveAttribute('aria-sort', 'ascending');
    await user.click(userHeader);
    expect(userHeader).toHaveAttribute('aria-sort', 'descending');
  });

  it('encodes + as %2B when switching to auto-discovered cluster nuxt+nuxt2', async () => {
    const mock = installFetchMock();
    const user = userEvent.setup();
    render(Users);

    const select = await screen.findByLabelText('Target cluster or server');
    await waitFor(() => expect(select).not.toBeDisabled());

    await user.selectOptions(select, 'cluster:nuxt+nuxt2');

    await waitFor(() =>
      expect(mock.callsFor('GET', '/ss/dashboard/api/clusters/nuxt%2Bnuxt2/users').length).toBeGreaterThan(0),
    );
    expect(ssTargetState.target).toEqual({ kind: 'cluster', name: 'nuxt+nuxt2' });
  });

  it('validates UserDrawer and creates a user across the cluster with JSON content-type', async () => {
    const clusterState = makeClusterUsersResponse('cloud');
    const mock = installFetchMock([
      {
        method: 'GET',
        match: '/ss/dashboard/api/clusters/cloud/users',
        handler: () => clusterState,
      },
      {
        method: 'POST',
        match: '/ss/dashboard/api/clusters/cloud/users',
        handler: (call) => {
          const payload = call.body as { id: string; method?: string };
          clusterState.users.push({
            id: payload.id,
            enabled: true,
            method: payload.method ?? null,
            has_password: true,
            has_vless_id: false,
            sync_status: 'synced',
            present_on: ['cloud1', 'cloud2'],
            missing_on: [],
            diff_fields: [],
            per_node: {},
          });
          return makeClusterMutationResponse(['cloud1', 'cloud2']);
        },
      },
    ]);
    const user = userEvent.setup();
    render(Users);
    render(Toasts);

    await screen.findByText('alice');
    await user.click(screen.getByRole('button', { name: 'Add user' }));

    const drawer = screen.getByText(/Applies across cluster/).closest('aside') as HTMLElement;
    expect(drawer).toHaveClass('open');

    // Empty password/UUID fails validation and shows an error toast without calling POST
    await user.type(within(drawer).getByLabelText('User id'), 'dave');
    await user.click(within(drawer).getByRole('button', { name: 'Create' }));
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(mock.callsFor('POST', '/ss/dashboard/api/clusters/cloud/users')).toHaveLength(0);

    // Fill password and submit
    await user.type(within(drawer).getByLabelText('Password'), 'super-secret-pw');
    await user.click(within(drawer).getByRole('button', { name: 'Create' }));

    await waitFor(() =>
      expect(mock.callsFor('POST', '/ss/dashboard/api/clusters/cloud/users')).toHaveLength(1),
    );
    const postCall = mock.callsFor('POST', '/ss/dashboard/api/clusters/cloud/users')[0];
    expect(postCall.headers['content-type']).toBe('application/json');
    expect((postCall.body as { id: string }).id).toBe('dave');

    expect(await screen.findByRole('button', { name: 'Show links' })).toBeInTheDocument();
    const table = await screen.findByRole('table');
    expect(await within(table).findByText('dave')).toBeInTheDocument();
  });

  it('blocks/unblocks users and guards delete behind ConfirmDialog', async () => {
    const mock = installFetchMock();
    const user = userEvent.setup();
    render(Users);

    await screen.findByText('alice');

    // Block alice
    await user.click(screen.getByRole('button', { name: 'Block alice' }));
    await waitFor(() =>
      expect(mock.callsFor('POST', '/ss/dashboard/api/clusters/cloud/users/alice/block')).toHaveLength(1),
    );

    // Unblock charlie
    await user.click(screen.getByRole('button', { name: 'Unblock charlie' }));
    await waitFor(() =>
      expect(mock.callsFor('POST', '/ss/dashboard/api/clusters/cloud/users/charlie/unblock')).toHaveLength(1),
    );

    // Cancel deletion
    await user.click(screen.getByRole('button', { name: 'Delete alice' }));
    expect(await screen.findByRole('heading', { name: 'Delete alice across cluster?' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(mock.callsFor('DELETE', '/ss/dashboard/api/clusters/cloud/users/alice')).toHaveLength(0);

    // Confirm deletion
    await user.click(screen.getByRole('button', { name: 'Delete alice' }));
    const confirmBtns = await screen.findAllByRole('button', { name: 'Delete' });
    await user.click(confirmBtns[confirmBtns.length - 1]);

    await waitFor(() =>
      expect(mock.callsFor('DELETE', '/ss/dashboard/api/clusters/cloud/users/alice')).toHaveLength(1),
    );
  });

  it('shows PerNodeResultPanel on partial cluster rollback failure', async () => {
    installFetchMock([
      {
        method: 'POST',
        match: '/ss/dashboard/api/clusters/cloud/users/alice/block',
        handler: () => ({
          status: 502,
          body: {
            error: 'node cloud2 failed',
            results: [
              { instance: 'cloud1', ok: true, status: 200, rolled_back: true },
              { instance: 'cloud2', ok: false, status: 502, error: 'timeout' },
            ],
          },
        }),
      },
    ]);
    const user = userEvent.setup();
    render(Users);

    await screen.findByText('alice');
    await user.click(screen.getByRole('button', { name: 'Block alice' }));

    const panel = await screen.findByRole('region', { name: 'Block alice partial failure' });
    expect(within(panel).getByText('cloud1')).toBeInTheDocument();
    expect(within(panel).getByText('rolled back')).toBeInTheDocument();
    expect(within(panel).getByText('failed (502)')).toBeInTheDocument();
    expect(within(panel).getByText('timeout')).toBeInTheDocument();
  });

  it('switches to single-node mode and hides ClusterStatusStrip', async () => {
    const mock = installFetchMock();
    const user = userEvent.setup();
    render(Users);

    const select = await screen.findByLabelText('Target cluster or server');
    await waitFor(() => expect(select).not.toBeDisabled());

    await user.selectOptions(select, 'instance:cloud1');

    await waitFor(() =>
      expect(mock.callsFor('GET', '/ss/dashboard/api/users?instance=cloud1').length).toBeGreaterThan(0),
    );
    expect(screen.queryByText('2/2 nodes online')).not.toBeInTheDocument();
    expect(await screen.findByRole('button', { name: 'Regenerate' })).toBeInTheDocument();
  });
});
