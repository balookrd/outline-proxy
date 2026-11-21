import { describe, it, expect } from 'vitest';
import { render, screen, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import Topology from './Topology.svelte';
import { makeTopologyResponse } from '../../test/fixtures';
import { installFetchMock } from '../../test/mockApi';

describe('Topology view (WS)', () => {
  it('renders all WS instances, groups, uplinks, wire chains, and handles unreachable instance errors', async () => {
    installFetchMock([
      {
        method: 'GET',
        match: (c) => c.pathname === '/ws/dashboard/api/topology' && c.searchParams.get('instance') === 'router104',
        handler: () => makeTopologyResponse('router104', false),
      },
    ]);
    render(Topology);

    expect(await screen.findByText('beelink102-primary')).toBeInTheDocument();
    expect(screen.getByText('beelink102-backup')).toBeInTheDocument();
    expect(screen.getByText('24ms')).toBeInTheDocument();
    expect(screen.getByText('1 active')).toBeInTheDocument();
    expect(screen.getByText('connection refused')).toBeInTheDocument();
  });

  it('sends activate, reselect, and set_enabled POST mutations with JSON content-type', async () => {
    const mock = installFetchMock();
    const user = userEvent.setup();
    render(Topology);

    await screen.findByText('beelink102-backup');

    // Activate backup uplink on beelink102
    const activateBtns = screen.getAllByRole('button', { name: 'Activate beelink102-backup' });
    await user.click(activateBtns[0]);
    await waitFor(() => expect(mock.callsFor('POST', '/ws/dashboard/api/activate')).toHaveLength(1));
    const actCall = mock.callsFor('POST', '/ws/dashboard/api/activate')[0];
    expect(actCall.headers['content-type']).toBe('application/json');
    expect(actCall.body).toEqual({
      targets: [{ instance: 'beelink102', group: 'main', uplink: 'beelink102-backup' }],
      soft: false,
    });

    // Reselect main group on beelink102
    const reselectBtns = screen.getAllByRole('button', { name: 'Reselect the active uplink for main' });
    await user.click(reselectBtns[0]);
    await waitFor(() => expect(mock.callsFor('POST', '/ws/dashboard/api/reselect')).toHaveLength(1));
    expect(mock.callsFor('POST', '/ws/dashboard/api/reselect')[0].body).toEqual({
      instance: 'beelink102',
      group: 'main',
      soft: true,
    });

    // Disable backup uplink on beelink102
    const disableBtns = screen.getAllByRole('button', { name: 'Disable beelink102-backup' });
    await user.click(disableBtns[0]);
    await waitFor(() => expect(mock.callsFor('POST', '/ws/dashboard/api/set_enabled')).toHaveLength(1));
    expect(mock.callsFor('POST', '/ws/dashboard/api/set_enabled')[0].body).toEqual({
      instance: 'beelink102',
      group: 'main',
      uplink: 'beelink102-backup',
      enabled: false,
    });
  });
});
