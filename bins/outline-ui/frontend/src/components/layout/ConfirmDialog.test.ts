import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import ConfirmDialog from './ConfirmDialog.svelte';

describe('ConfirmDialog', () => {
  it('renders title, message and danger button styling when opened', () => {
    render(ConfirmDialog, {
      open: true,
      title: 'Delete user?',
      message: 'This action cannot be undone.',
      confirmLabel: 'Delete',
      cancelLabel: 'Keep',
      danger: true,
      onconfirm: vi.fn(),
    });

    const dialog = document.querySelector('dialog');
    expect(dialog).not.toBeNull();
    expect(dialog?.open).toBe(true);
    expect(screen.getByRole('heading', { name: 'Delete user?' })).toBeInTheDocument();
    expect(screen.getByText('This action cannot be undone.')).toBeInTheDocument();

    const confirmBtn = screen.getByRole('button', { name: 'Delete' });
    expect(confirmBtn).toHaveClass('btn', 'danger');
    expect(screen.getByRole('button', { name: 'Keep' })).toBeInTheDocument();
  });

  it('invokes onconfirm and closes when confirm button is clicked', async () => {
    const user = userEvent.setup();
    const onconfirm = vi.fn();
    const oncancel = vi.fn();

    render(ConfirmDialog, {
      open: true,
      title: 'Confirm rotation',
      message: 'Rotate PSK now?',
      confirmLabel: 'Rotate PSK',
      onconfirm,
      oncancel,
    });

    await user.click(screen.getByRole('button', { name: 'Rotate PSK' }));

    expect(onconfirm).toHaveBeenCalledTimes(1);
    expect(oncancel).not.toHaveBeenCalled();
    expect(document.querySelector('dialog')?.open).toBe(false);
  });

  it('invokes oncancel and closes when cancel button is clicked', async () => {
    const user = userEvent.setup();
    const onconfirm = vi.fn();
    const oncancel = vi.fn();

    render(ConfirmDialog, {
      open: true,
      title: 'Confirm deletion',
      message: 'Delete item?',
      confirmLabel: 'Delete',
      cancelLabel: 'Cancel',
      onconfirm,
      oncancel,
    });

    await user.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(oncancel).toHaveBeenCalledTimes(1);
    expect(onconfirm).not.toHaveBeenCalled();
    expect(document.querySelector('dialog')?.open).toBe(false);
  });
});
