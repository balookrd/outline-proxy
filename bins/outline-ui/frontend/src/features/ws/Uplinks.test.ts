import { describe, it, expect } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import Uplinks from './Uplinks.svelte';
import { makeUplinksResponse } from '../../test/fixtures';
import { installFetchMock } from '../../test/mockApi';

describe('Uplinks view (WS)', () => {
  it('loads uplinks grouped by group, creates and edits via UplinkDrawer, and runs Apply', async () => {
    const state = makeUplinksResponse();
    const mock = installFetchMock([
      {
        method: 'GET',
        match: '/ws/dashboard/api/uplinks',
        handler: () => state,
      },
      {
        method: 'POST',
        match: '/ws/dashboard/api/uplinks',
        handler: (call) => {
          const env = call.body as { instance: string; body: { group: string; uplink: { name: string; link?: string } } };
          state.uplinks.push({
            group: env.body.group,
            name: env.body.uplink.name,
            index: state.uplinks.length,
            config: { link: env.body.uplink.link },
          });
          return { ok: true };
        },
      },
    ]);
    const user = userEvent.setup();
    render(Uplinks);

    expect(await screen.findByText('cloud1-edge')).toBeInTheDocument();
    expect(screen.getByText('cloud2-edge')).toBeInTheDocument();
    expect(screen.getByText('2 uplinks')).toBeInTheDocument();

    // Create uplink via UplinkDrawer using a share link
    await user.click(screen.getByRole('button', { name: 'Add uplink' }));
    const drawer = screen.getByText('Add uplink to "main"').closest('aside') as HTMLElement;
    expect(drawer).toHaveClass('open');

    await user.type(within(drawer).getByLabelText('Name'), 'edge-share');
    await user.click(within(drawer).getByLabelText('Use a share link'));
    await user.type(within(drawer).getByLabelText('Share link'), 'vless://11111111-1111-4111-8111-111111111111@edge.fleet.example:443');
    await user.click(within(drawer).getByRole('button', { name: 'Create' }));

    await waitFor(() =>
      expect(mock.callsFor('POST', '/ws/dashboard/api/uplinks')).toHaveLength(1),
    );
    const postCall = mock.callsFor('POST', '/ws/dashboard/api/uplinks')[0];
    expect(postCall.headers['content-type']).toBe('application/json');
    expect((postCall.body as { instance: string }).instance).toBe('beelink102');

    expect(await screen.findByText('edge-share')).toBeInTheDocument();

    // Edit an existing uplink
    await user.click(screen.getByRole('button', { name: 'Edit cloud1-edge' }));
    const editDrawer = screen.getByText('Edit "cloud1-edge" in "main"').closest('aside') as HTMLElement;
    expect(editDrawer).toHaveClass('open');
    await user.click(within(editDrawer).getByRole('button', { name: 'Update' }));

    await waitFor(() =>
      expect(mock.callsFor('PATCH', '/ws/dashboard/api/uplinks')).toHaveLength(1),
    );

    // Apply now banner appears on dirty instance and invokes POST /apply
    const applyBtn = await screen.findByRole('button', { name: 'Apply now' });
    await user.click(applyBtn);

    await waitFor(() =>
      expect(mock.callsFor('POST', '/ws/dashboard/api/apply')).toHaveLength(1),
    );
    expect(mock.callsFor('POST', '/ws/dashboard/api/apply')[0].body).toEqual({
      instance: 'beelink102',
    });
  });
});
