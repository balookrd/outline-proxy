import { describe, it, expect, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import SsTargetSelector from './SsTargetSelector.svelte';
import { ssTargetState } from '../../lib/ssTarget.svelte';
import { installFetchMock } from '../../test/mockApi';

describe('SsTargetSelector', () => {
  it('renders configured and auto-discovered clusters plus single nodes', async () => {
    installFetchMock();
    render(SsTargetSelector);

    const select = (await screen.findByLabelText('Target cluster or server')) as HTMLSelectElement;
    await waitFor(() => expect(select.disabled).toBe(false));

    expect(screen.getByRole('option', { name: 'cluster · cloud (2)' })).toHaveValue('cluster:cloud');
    expect(screen.getByRole('option', { name: 'cluster · nuxt+nuxt2 (2) · auto' })).toHaveValue(
      'cluster:nuxt+nuxt2',
    );
    expect(screen.getByRole('option', { name: 'cloud1' })).toHaveValue('instance:cloud1');
    expect(screen.getByRole('option', { name: 'nuxt' })).toHaveValue('instance:nuxt');
    expect(ssTargetState.target).toEqual({ kind: 'cluster', name: 'cloud' });
  });

  it('shows Switch to cluster button for a member instance and switches back to the cluster', async () => {
    installFetchMock();
    const user = userEvent.setup();
    render(SsTargetSelector);

    const select = (await screen.findByLabelText('Target cluster or server')) as HTMLSelectElement;
    await waitFor(() => expect(select.disabled).toBe(false));

    await user.selectOptions(select, 'instance:cloud1');
    expect(ssTargetState.target).toEqual({ kind: 'instance', name: 'cloud1' });

    const switchBtn = await screen.findByRole('button', { name: 'Switch to cluster cloud' });
    await user.click(switchBtn);

    expect(ssTargetState.target).toEqual({ kind: 'cluster', name: 'cloud' });
    expect(screen.queryByRole('button', { name: 'Switch to cluster cloud' })).not.toBeInTheDocument();
  });

  it('aborts target switch and restores select value when onBeforeChange returns false', async () => {
    installFetchMock();
    const user = userEvent.setup();
    const onBeforeChange = vi.fn().mockResolvedValue(false);

    render(SsTargetSelector, { onBeforeChange });

    const select = (await screen.findByLabelText('Target cluster or server')) as HTMLSelectElement;
    await waitFor(() => expect(select.value).toBe('cluster:cloud'));

    await user.selectOptions(select, 'instance:cloud1');

    expect(onBeforeChange).toHaveBeenCalledWith({ kind: 'instance', name: 'cloud1' });
    expect(ssTargetState.target).toEqual({ kind: 'cluster', name: 'cloud' });
    expect(select.value).toBe('cluster:cloud');
  });
});
