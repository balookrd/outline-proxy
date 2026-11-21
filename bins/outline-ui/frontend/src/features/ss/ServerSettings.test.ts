import { describe, it, expect } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import Toasts from '../../components/layout/Toasts.svelte';
import ServerSettings from './ServerSettings.svelte';
import { makeClusterConfigResponse, makeClusterMutationResponse, makeServerConfig } from '../../test/fixtures';
import { installFetchMock } from '../../test/mockApi';

describe('ServerSettings view (SS)', () => {
  it('renders all 5 tabs, supports click + keyboard tab switching, and shows DriftBadge', async () => {
    const cfg = makeClusterConfigResponse('cloud');
    cfg.drift = ['endpoints'];
    cfg.nodes[1].config = makeServerConfig({
      endpoints: [
        { path: '/ws-alt', kind: 'ws_ss', protocol: 'shadowsocks', transport: 'websocket', padded: false },
      ],
    });
    installFetchMock([
      {
        method: 'GET',
        match: '/ss/dashboard/api/clusters/cloud/config',
        handler: () => cfg,
      },
    ]);
    const user = userEvent.setup();
    render(ServerSettings);

    const tablist = await screen.findByRole('tablist', { name: 'Server configuration sections' });
    const tabs = within(tablist).getAllByRole('tab');
    expect(tabs.map((t) => t.textContent?.trim())).toEqual([
      'Carriers & Endpoints',
      'Network & TLS',
      'Resumption & Camouflage',
      'Subscriptions',
      'Tuning & System',
    ]);

    // DriftBadge appears on endpoints
    const driftBtn = await screen.findByRole('button', { name: 'Drift' });
    await user.click(driftBtn);
    expect(screen.getByText('Values across nodes (endpoints)')).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: 'Use for all' })).toHaveLength(2);

    // Click tab 2 and keyboard navigation across tabs
    await user.click(tabs[1]);
    expect(tabs[1]).toHaveAttribute('aria-selected', 'true');
    tabs[1].focus();
    await user.keyboard('{ArrowRight}');
    expect(tabs[2]).toHaveAttribute('aria-selected', 'true');
    await user.keyboard('{End}');
    expect(tabs[4]).toHaveAttribute('aria-selected', 'true');
    await user.keyboard('{Home}');
    expect(tabs[0]).toHaveAttribute('aria-selected', 'true');
  });

  it('activates sticky save-bar on edit, saves PATCH, and displays restart notice', async () => {
    const mock = installFetchMock([
      {
        method: 'PATCH',
        match: '/ss/dashboard/api/clusters/cloud/config',
        handler: () =>
          makeClusterMutationResponse(['cloud1', 'cloud2'], {
            results: [
              { instance: 'cloud1', ok: true, status: 200, requires_restart: true },
              { instance: 'cloud2', ok: true, status: 200, requires_restart: true },
            ],
          }),
      },
    ]);
    const user = userEvent.setup();
    render(ServerSettings);

    await screen.findByRole('tab', { name: 'Network & TLS' });
    await user.click(screen.getByRole('tab', { name: 'Network & TLS' }));

    const listenInput = screen.getByLabelText('Listen address (per-node)');
    await user.clear(listenInput);
    await user.type(listenInput, '0.0.0.0:8443');

    const saveBar = await screen.findByRole('region', { name: 'Unsaved settings bar' });
    const saveBtn = within(saveBar).getByRole('button', { name: /Save to cluster/ });
    await user.click(saveBtn);

    await waitFor(() =>
      expect(mock.callsFor('PATCH', '/ss/dashboard/api/clusters/cloud/config')).toHaveLength(1),
    );
    const patchCall = mock.callsFor('PATCH', '/ss/dashboard/api/clusters/cloud/config')[0];
    expect(patchCall.headers['content-type']).toBe('application/json');
    expect(
      (patchCall.body as { per_node: Record<string, { server: { listen: string } }> }).per_node.cloud1.server.listen,
    ).toBe('0.0.0.0:8443');

    expect(await screen.findByText('RESTART PENDING')).toBeInTheDocument();
    expect(screen.getByText(/cloud1, cloud2/)).toBeInTheDocument();
  });

  it('blocks saving and shows validation error when listen address is invalid', async () => {
    const mock = installFetchMock();
    const user = userEvent.setup();
    render(ServerSettings);
    render(Toasts);

    await screen.findByRole('tab', { name: 'Network & TLS' });
    await user.click(screen.getByRole('tab', { name: 'Network & TLS' }));

    const listenInput = screen.getByLabelText('Listen address (per-node)');
    await user.clear(listenInput);
    await user.type(listenInput, 'not-a-socket-addr');
    await user.tab();

    expect(listenInput).toHaveAttribute('aria-invalid', 'true');

    const saveBar = await screen.findByRole('region', { name: 'Unsaved settings bar' });
    await user.click(within(saveBar).getByRole('button', { name: /Save to cluster/ }));

    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(mock.callsFor('PATCH', '/ss/dashboard/api/clusters/cloud/config')).toHaveLength(0);
  });
});
