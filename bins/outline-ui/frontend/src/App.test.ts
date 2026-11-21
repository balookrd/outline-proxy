import { describe, it, expect } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import App from './App.svelte';
import { route } from './lib/router.svelte';
import { toast } from './lib/toast.svelte';
import { installFetchMock } from './test/mockApi';

describe('App shell', () => {
  it('loads /api/meta and renders version in sidebar footer and mobile topbar', async () => {
    installFetchMock();
    render(App);

    const nav = screen.getByRole('navigation');
    expect(await within(nav).findByText('v26.11.3')).toBeInTheDocument();
    expect(screen.getAllByText('v26.11.3')).toHaveLength(2);
  });

  it('shows Landing panel cards when instances exist and empty hint when none are configured', async () => {
    installFetchMock();
    const { unmount } = render(App);

    expect(await screen.findByText('Server dashboard')).toBeInTheDocument();
    expect(screen.getByText('Client dashboard')).toBeInTheDocument();
    expect(screen.getByText('4')).toBeInTheDocument();
    expect(screen.getByText('2')).toBeInTheDocument();

    unmount();

    installFetchMock([
      {
        method: 'GET',
        match: '/ss/dashboard/api/instances',
        handler: () => ({ instances: [], clusters: [], refresh_interval_secs: 5 }),
      },
      {
        method: 'GET',
        match: '/ws/dashboard/api/instances',
        handler: () => ({ instances: [], refresh_interval_secs: 5 }),
      },
    ]);
    render(App);

    expect(
      await screen.findByText('No capabilities detected yet — check the backend instance configuration.'),
    ).toBeInTheDocument();
  });

  it('navigates across all 9 sidebar items via click, keyboard, and popstate', async () => {
    installFetchMock();
    const user = userEvent.setup();
    render(App);

    const nav = screen.getByRole('navigation');
    const settingsButtons = within(nav).getAllByRole('button', { name: 'Settings' });
    expect(settingsButtons).toHaveLength(2);

    const targets: Array<{ el: HTMLElement; path: string; heading: RegExp }> = [
      { el: within(nav).getByRole('button', { name: 'Users' }), path: '/ss', heading: /^Users$/ },
      { el: within(nav).getByRole('button', { name: 'Mesh cluster' }), path: '/ss/cluster', heading: /Mesh Cluster/ },
      { el: settingsButtons[0], path: '/ss/settings', heading: /Server Settings/ },
      { el: within(nav).getByRole('button', { name: 'Topology' }), path: '/ws', heading: /Topology/ },
      { el: within(nav).getByRole('button', { name: 'Uplinks' }), path: '/ws/uplinks', heading: /Uplinks/ },
      { el: within(nav).getByRole('button', { name: 'Routing' }), path: '/ws/routing', heading: /Routing/ },
      { el: within(nav).getByRole('button', { name: 'Uplink groups' }), path: '/ws/groups', heading: /Uplink groups/ },
      { el: settingsButtons[1], path: '/ws/settings', heading: /Client Settings/ },
      { el: within(nav).getByRole('button', { name: 'Overview' }), path: '/', heading: /^Overview$/ },
    ];

    for (const item of targets) {
      await user.click(item.el);
      expect(route.path).toBe(item.path);
      expect(item.el).toHaveClass('active');
      expect(await screen.findByRole('heading', { level: 1, name: item.heading })).toBeInTheDocument();
    }

    // Keyboard activation (Enter / Space)
    const usersBtn = within(nav).getByRole('button', { name: 'Users' });
    usersBtn.focus();
    await user.keyboard('{Enter}');
    expect(route.path).toBe('/ss');
    expect(usersBtn).toHaveClass('active');

    const topologyBtn = within(nav).getByRole('button', { name: 'Topology' });
    topologyBtn.focus();
    await user.keyboard(' ');
    expect(route.path).toBe('/ws');
    expect(topologyBtn).toHaveClass('active');

    // Browser popstate sync
    history.replaceState({}, '', '/ss/cluster');
    window.dispatchEvent(new PopStateEvent('popstate'));
    await waitFor(() => expect(route.path).toBe('/ss/cluster'));
    expect(await screen.findByRole('heading', { level: 1, name: /Mesh Cluster/ })).toBeInTheDocument();
  });

  it('toggles theme from Topbar button and persists choice', async () => {
    installFetchMock();
    const user = userEvent.setup();
    render(App);

    const themeBtn = await screen.findByRole('button', { name: /Switch to (dark|light) theme/ });
    const initialLabel = themeBtn.getAttribute('aria-label');
    await user.click(themeBtn);

    const nextMode = initialLabel?.includes('dark') ? 'dark' : 'light';
    expect(document.documentElement.dataset.theme).toBe(nextMode);
    expect(localStorage.getItem('theme')).toBe(nextMode);
    expect(themeBtn.getAttribute('aria-label')).not.toBe(initialLabel);
  });

  it('renders status and error toasts via Toasts store', async () => {
    installFetchMock();
    render(App);

    toast('Saved successfully');
    toast('Something failed', 'error');

    expect(await screen.findByRole('status')).toHaveTextContent('Saved successfully');
    expect(await screen.findByRole('alert')).toHaveTextContent('Something failed');
  });
});
