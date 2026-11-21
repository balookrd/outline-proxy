import { describe, it, expect } from 'vitest';
import { render, screen, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import WsSettings from './WsSettings.svelte';
import { makeWsConfigMutationResponse } from '../../test/fixtures';
import { installFetchMock } from '../../test/mockApi';

describe('WsSettings view (WS)', () => {
  it('loads sections, manages [[socks5.users]], saves PATCH, shows restart notice, and runs Apply now', async () => {
    const mock = installFetchMock([
      {
        method: 'PATCH',
        match: '/ws/dashboard/api/config',
        handler: () => makeWsConfigMutationResponse({ restart_required: true, apply_required: true }),
      },
    ]);
    const user = userEvent.setup();
    render(WsSettings);

    expect(await screen.findByLabelText('SOCKS5 Listen Address')).toHaveValue('127.0.0.1:1080');
    expect(screen.getByLabelText('Probe Interval (s)')).toHaveValue(30);
    expect(screen.getByLabelText('TUN Device Name')).toHaveValue('tun0');

    // Add a SOCKS5 user and remove the existing one
    await user.click(screen.getByRole('button', { name: '+ Add User' }));
    const usernameInputs = screen.getAllByPlaceholderText('Username');
    expect(usernameInputs).toHaveLength(2);
    await user.type(usernameInputs[1], 'bob');
    await user.type(screen.getByPlaceholderText('Password'), 'pass-bob');

    const removeButtons = screen.getAllByTitle('Remove user');
    await user.click(removeButtons[0]);
    expect(screen.getAllByPlaceholderText('Username')).toHaveLength(1);

    // Save changes sends PATCH with updated socks5.users
    const saveBtn = screen.getByRole('button', { name: 'Save changes' });
    expect(saveBtn).toBeEnabled();
    await user.click(saveBtn);

    await waitFor(() =>
      expect(mock.callsFor('PATCH', '/ws/dashboard/api/config')).toHaveLength(1),
    );
    const patchCall = mock.callsFor('PATCH', '/ws/dashboard/api/config')[0];
    expect(patchCall.headers['content-type']).toBe('application/json');
    expect(patchCall.url).toBe('/ws/dashboard/api/config?instance=beelink102');
    expect(
      (patchCall.body as { socks5: { users: Array<{ username: string }> } }).socks5.users,
    ).toEqual([{ username: 'bob', password: 'pass-bob' }]);

    expect(await screen.findByText('RESTART REQUIRED')).toBeInTheDocument();

    // Apply now invokes POST /ws/dashboard/api/apply
    await user.click(screen.getByRole('button', { name: 'Apply now' }));
    await waitFor(() =>
      expect(mock.callsFor('POST', '/ws/dashboard/api/apply')).toHaveLength(1),
    );
    expect(mock.callsFor('POST', '/ws/dashboard/api/apply')[0].body).toEqual({
      instance: 'beelink102',
    });
  });
});
