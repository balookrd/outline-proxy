import { describe, it, expect, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import UplinkGroups from './UplinkGroups.svelte';
import { makeGroupsResponse } from '../../test/fixtures';
import { installFetchMock } from '../../test/mockApi';

describe('UplinkGroups view (WS)', () => {
  it('disables Delete when group has uplinks, creates a group via GroupDrawer, and deletes an empty group', async () => {
    const state = makeGroupsResponse();
    const mock = installFetchMock([
      {
        method: 'GET',
        match: '/ws/dashboard/api/groups',
        handler: () => state,
      },
      {
        method: 'POST',
        match: '/ws/dashboard/api/groups',
        handler: (call) => {
          const env = call.body as { body: { group: { name: string; mode?: string; routing_scope?: string } } };
          state.groups.push({
            name: env.body.group.name,
            uplink_count: 0,
            config: env.body.group,
          });
          return { name: env.body.group.name, action: 'create', apply_required: true };
        },
      },
      {
        method: 'DELETE',
        match: '/ws/dashboard/api/groups',
        handler: (call) => {
          const env = call.body as { body: { name: string } };
          state.groups = state.groups.filter((g) => g.name !== env.body.name);
          return { name: env.body.name, action: 'delete', apply_required: true };
        },
      },
    ]);
    const user = userEvent.setup();
    render(UplinkGroups);

    expect(await screen.findByText('main')).toBeInTheDocument();
    expect(screen.getByText('empty-backup')).toBeInTheDocument();

    // Group with uplinks cannot be deleted; empty group can
    expect(screen.getByRole('button', { name: 'Delete group main' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Delete group empty-backup' })).toBeEnabled();

    // Create a new group via GroupDrawer -> triggers empty group hint in pending applybar
    await user.click(screen.getByRole('button', { name: 'Add group' }));
    const drawer = screen.getByText('Add uplink group').closest('aside') as HTMLElement;
    expect(drawer).toHaveClass('open');

    await user.type(within(drawer).getByLabelText('Name'), 'edge-new');
    await user.click(within(drawer).getByRole('button', { name: 'Create' }));

    await waitFor(() =>
      expect(mock.callsFor('POST', '/ws/dashboard/api/groups')).toHaveLength(1),
    );
    expect(await screen.findByText(/Empty:.*empty-backup.*edge-new/)).toBeInTheDocument();

    // Delete empty-backup after confirming window.confirm
    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(true);
    await user.click(screen.getByRole('button', { name: 'Delete group empty-backup' }));

    expect(confirmSpy).toHaveBeenCalledWith('Delete uplink group "empty-backup"?');
    await waitFor(() =>
      expect(mock.callsFor('DELETE', '/ws/dashboard/api/groups')).toHaveLength(1),
    );
    const delCall = mock.callsFor('DELETE', '/ws/dashboard/api/groups')[0];
    expect(delCall.headers['content-type']).toBe('application/json');
    expect(delCall.body).toEqual({ instance: 'beelink102', body: { name: 'empty-backup' } });
    await waitFor(() => expect(screen.queryByText('empty-backup')).not.toBeInTheDocument());
  });
});
