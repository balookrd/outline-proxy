import { describe, it, expect, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import Routing from './Routing.svelte';
import { makeRoutesResponse } from '../../test/fixtures';
import { installFetchMock } from '../../test/mockApi';

describe('Routing view (WS)', () => {
  it('protects default route order/deletion and preserves drawer revision snapshot across poll refreshes', async () => {
    let serverRevision = 'rev-1';
    const mock = installFetchMock([
      {
        method: 'GET',
        match: '/ws/dashboard/api/routes',
        handler: () => makeRoutesResponse(serverRevision),
      },
    ]);
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    render(Routing);

    expect(await screen.findByText('youtube.com')).toBeInTheDocument();

    // Rule #2 is default: Move up and Delete are disabled; rule #1 right above default has Move down disabled
    expect(screen.getByRole('button', { name: 'Move rule #2 up' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Delete rule #2' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Move rule #1 down' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Move rule #0 down' })).toBeEnabled();

    // Open RouteDrawer while revision is rev-1, then advance mock serverRevision and trigger a poll tick
    await user.click(screen.getByRole('button', { name: 'Edit rule #1' }));
    const drawer = screen.getByText('Edit route #1').closest('aside') as HTMLElement;
    expect(drawer).toHaveClass('open');

    serverRevision = 'rev-99';
    await vi.advanceTimersByTimeAsync(5500);
    expect(
      mock.callsFor('GET', '/ws/dashboard/api/routes').length,
    ).toBeGreaterThanOrEqual(2);

    // Saving must still send the snapshot revision captured when the drawer opened (rev-1), not rev-99
    await user.click(within(drawer).getByRole('button', { name: 'Update' }));

    await waitFor(() =>
      expect(mock.callsFor('PATCH', '/ws/dashboard/api/routes')).toHaveLength(1),
    );
    const patchCall = mock.callsFor('PATCH', '/ws/dashboard/api/routes')[0];
    expect(patchCall.headers['content-type']).toBe('application/json');
    expect((patchCall.body as { body: { revision: string; index: number } }).body.revision).toBe('rev-1');
    expect((patchCall.body as { body: { revision: string; index: number } }).body.index).toBe(1);

    expect(await screen.findByRole('button', { name: 'Apply now' })).toBeInTheDocument();
  });
});
