import { describe, it, expect, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import AccessKeysModal from './AccessKeysModal.svelte';
import { makeAccessKeysBundle } from '../../test/fixtures';
import { installFetchMock } from '../../test/mockApi';

describe('AccessKeysModal', () => {
  it('renders all 4 subscription tabs, SVG QR codes, and supports keyboard navigation', async () => {
    installFetchMock();
    const user = userEvent.setup();
    render(AccessKeysModal, {
      props: {
        open: true,
        target: { kind: 'cluster', name: 'cloud' },
        userId: 'alice',
      },
    });

    expect(await screen.findByLabelText('Outline dynamic key URL (ssconf://)')).toHaveValue(
      'ssconf://cloud1.fleet.example/keys/alice.conf',
    );
    expect(screen.getByRole('img', { name: 'Outline subscription QR code' })).toBeInTheDocument();

    const outlineTab = screen.getByRole('tab', { name: 'Outline' });
    const happTab = screen.getByRole('tab', { name: 'Happ / Xray' });
    const appTab = screen.getByRole('tab', { name: 'App Config' });
    const linksTab = screen.getByRole('tab', { name: 'Share Links' });

    // Click tab switch
    await user.click(happTab);
    expect(happTab).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByLabelText('Happ / Xray subscription URL')).toBeVisible();
    expect(screen.getByRole('img', { name: 'Happ Xray subscription QR code' })).toBeInTheDocument();

    // Keyboard ArrowRight / End / Home / ArrowLeft
    happTab.focus();
    await user.keyboard('{ArrowRight}');
    expect(appTab).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByLabelText('outline-client config URL (.toml)')).toBeVisible();

    await user.keyboard('{End}');
    expect(linksTab).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByRole('button', { name: 'Copy all' })).toBeVisible();

    await user.keyboard('{Home}');
    expect(outlineTab).toHaveAttribute('aria-selected', 'true');
    await user.keyboard('{ArrowLeft}');
    expect(linksTab).toHaveAttribute('aria-selected', 'true');
  });

  it('copies subscription URL via navigator.clipboard and updates button label', async () => {
    installFetchMock();
    const writeSpy = vi.spyOn(navigator.clipboard, 'writeText').mockResolvedValue(undefined);
    const user = userEvent.setup();

    render(AccessKeysModal, {
      props: {
        open: true,
        target: { kind: 'cluster', name: 'cloud' },
        userId: 'alice',
      },
    });

    const copyBtn = await screen.findByRole('button', { name: 'Copy URL' });
    await user.click(copyBtn);

    expect(writeSpy).toHaveBeenCalledWith('ssconf://cloud1.fleet.example/keys/alice.conf');
    expect(await screen.findByRole('button', { name: 'Copied' })).toBeInTheDocument();
  });

  it('switches node subscription view in per_node mode', async () => {
    installFetchMock([
      {
        method: 'GET',
        match: '/ss/dashboard/api/clusters/cloud/users/alice/access-keys',
        handler: () => makeAccessKeysBundle('per_node', 'alice'),
      },
    ]);
    const user = userEvent.setup();

    render(AccessKeysModal, {
      props: {
        open: true,
        target: { kind: 'cluster', name: 'cloud' },
        userId: 'alice',
      },
    });

    const nodeSelect = await screen.findByLabelText('Node subscription view');
    expect(screen.getByLabelText('Outline dynamic key URL (ssconf://)')).toHaveValue(
      'ssconf://cloud1.fleet.example/keys/alice.conf',
    );

    await user.selectOptions(nodeSelect, 'cloud2');
    await waitFor(() =>
      expect(screen.getByLabelText('Outline dynamic key URL (ssconf://)')).toHaveValue(
        'ssconf://cloud2.fleet.example/keys/alice.conf',
      ),
    );
  });

  it('renders 501 generator-not-configured hint and 500 error alert', async () => {
    installFetchMock([
      {
        method: 'GET',
        match: '/ss/dashboard/api/clusters/cloud/users/alice/access-keys',
        handler: () => ({ status: 501, body: { error: 'access_keys_generator is not configured' } }),
      },
    ]);

    const { unmount } = render(AccessKeysModal, {
      props: {
        open: true,
        target: { kind: 'cluster', name: 'cloud' },
        userId: 'alice',
      },
    });

    expect(await screen.findByText(/Generator is not configured on this server/)).toBeInTheDocument();
    unmount();

    installFetchMock([
      {
        method: 'GET',
        match: '/ss/dashboard/api/clusters/cloud/users/alice/access-keys',
        handler: () => ({ status: 500, body: { error: 'backend timeout' } }),
      },
    ]);

    render(AccessKeysModal, {
      props: {
        open: true,
        target: { kind: 'cluster', name: 'cloud' },
        userId: 'alice',
      },
    });

    expect(await screen.findByRole('alert')).toHaveTextContent('backend timeout');
  });
});
