import { describe, it, expect } from 'vitest';
import { render, screen, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import Cluster from './Cluster.svelte';
import { ssTargetState } from '../../lib/ssTarget.svelte';
import { makeClusterConfigResponse } from '../../test/fixtures';
import { installFetchMock } from '../../test/mockApi';

describe('Cluster view (SS)', () => {
  it('renders member table, mesh_health warnings, and saves symmetric cluster topology', async () => {
    const mock = installFetchMock([
      {
        method: 'GET',
        match: '/ss/dashboard/api/clusters/cloud/config',
        handler: () =>
          makeClusterConfigResponse('cloud', {
            mesh_health: {
              all_reachable: true,
              psk_match: false,
              shards_unique: true,
              peers_symmetric: true,
              restart_pending_nodes: ['cloud2'],
            },
          }),
      },
    ]);
    const user = userEvent.setup();
    render(Cluster);

    expect(await screen.findByText('PSK: Mismatch / Missing')).toBeInTheDocument();
    expect(screen.getByText('Shards: Unique')).toBeInTheDocument();
    expect(screen.getByText('Peers: Symmetric')).toBeInTheDocument();
    expect(screen.getByText('Restart pending: cloud2')).toBeInTheDocument();
    expect(screen.getByLabelText('Shard ID on cloud1')).toHaveValue(1);
    expect(screen.getByLabelText('Shard ID on cloud2')).toHaveValue(2);

    const budgetInput = screen.getByLabelText('Relay budget (ms)');
    await user.clear(budgetInput);
    await user.type(budgetInput, '5500');

    const saveBtn = screen.getByRole('button', { name: 'Save symmetric topology' });
    await user.click(saveBtn);

    await waitFor(() =>
      expect(mock.callsFor('PATCH', '/ss/dashboard/api/clusters/cloud/config')).toHaveLength(1),
    );
    const patchCall = mock.callsFor('PATCH', '/ss/dashboard/api/clusters/cloud/config')[0];
    expect(patchCall.headers['content-type']).toBe('application/json');
    expect((patchCall.body as { per_node: Record<string, { cluster: { mesh_relay_budget_ms: number } }> }).per_node.cloud1.cluster.mesh_relay_budget_ms).toBe(5500);
  });

  it('guards target switching with ConfirmDialog when form has unsaved edits', async () => {
    installFetchMock();
    const user = userEvent.setup();
    render(Cluster);

    const budgetInput = await screen.findByLabelText('Relay budget (ms)');
    await user.clear(budgetInput);
    await user.type(budgetInput, '6000');

    const selector = screen.getByLabelText('Target cluster or server');
    await user.selectOptions(selector, 'instance:cloud1');

    expect(await screen.findByRole('heading', { name: 'Discard unsaved cluster changes?' })).toBeInTheDocument();
    expect(ssTargetState.target).toEqual({ kind: 'cluster', name: 'cloud' });

    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(ssTargetState.target).toEqual({ kind: 'cluster', name: 'cloud' });

    // Confirm discarding changes switches target to standalone node
    await user.selectOptions(selector, 'instance:cloud1');
    await screen.findByRole('heading', { name: 'Discard unsaved cluster changes?' });
    await user.click(screen.getByRole('button', { name: 'Discard' }));

    await waitFor(() => expect(ssTargetState.target).toEqual({ kind: 'instance', name: 'cloud1' }));
  });

  it('loads single-node [cluster] configuration when switching to a standalone instance', async () => {
    const mock = installFetchMock();
    const user = userEvent.setup();
    render(Cluster);

    const selector = await screen.findByLabelText('Target cluster or server');
    await waitFor(() => expect(selector).not.toBeDisabled());
    await user.selectOptions(selector, 'instance:cloud1');

    await waitFor(() =>
      expect(mock.callsFor('GET', '/ss/dashboard/api/config?instance=cloud1').length).toBeGreaterThan(0),
    );
    expect(await screen.findByText('Active Mesh')).toBeInTheDocument();
    expect(screen.getByLabelText('Local Shard ID (0..15)')).toHaveValue(1);
    expect(screen.getByLabelText('Mesh Listen Address')).toHaveValue('[::]:9443');
  });
});
