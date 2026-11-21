import { expect, test } from '@playwright/test';
import { attachErrorGuard, mockOutlineApi } from './mock-api.ts';

test.describe('SS dashboard workflows', () => {
  test('supports auto-discovered cluster names, user CRUD with native dialogs, AccessKeysModal QR/tabs, Cluster and ServerSettings', async ({
    page,
  }) => {
    const guard = attachErrorGuard(page);
    const api = await mockOutlineApi(page);

    await page.goto('/ss');

    const selector = page.getByLabel('Target cluster or server');
    await expect(selector).toBeEnabled();
    await expect(selector.locator('option', { hasText: 'cluster · cloud (2)' })).toBeAttached();
    await expect(
      selector.locator('option', { hasText: 'cluster · nuxt+nuxt2 (2) · auto' }),
    ).toBeAttached();

    // Switching to auto-discovered cluster encodes + as %2B
    await selector.selectOption('cluster:nuxt+nuxt2');
    await expect
      .poll(() => api.callsFor('GET', '/ss/dashboard/api/clusters/nuxt%2Bnuxt2/users').length)
      .toBeGreaterThan(0);

    await selector.selectOption('cluster:cloud');
    await expect(page.getByRole('table').getByText('alice')).toBeVisible();

    // Create user through UserDrawer
    await page.getByRole('button', { name: 'Add user' }).click();
    const drawer = page.locator('aside.drawer.open');
    await expect(drawer).toBeVisible();
    await drawer.getByLabel('User id').fill('e2e-user');
    await drawer.getByLabel('Password', { exact: true }).fill('e2e-password-secret');
    await drawer.getByRole('button', { name: 'Create' }).click();

    await expect(page.getByRole('table').getByText('e2e-user')).toBeVisible();

    // Open native <dialog> AccessKeysModal and navigate all 4 tabs + SVG QR
    await page.getByRole('button', { name: 'Links for e2e-user' }).click();
    const linksDialog = page.locator('dialog.links-dialog');
    await expect(linksDialog).toHaveJSProperty('open', true);
    await expect(linksDialog.getByRole('img', { name: 'Outline subscription QR code' })).toBeVisible();

    await linksDialog.getByRole('tab', { name: 'Happ / Xray' }).click();
    await expect(linksDialog.getByLabel('Happ / Xray subscription URL')).toBeVisible();
    await linksDialog.getByRole('tab', { name: 'App Config' }).click();
    await expect(linksDialog.getByLabel('outline-client config URL (.toml)')).toBeVisible();
    await linksDialog.getByRole('tab', { name: 'Share Links' }).click();
    await expect(linksDialog.getByRole('button', { name: 'Copy all' })).toBeVisible();

    await page.keyboard.press('Escape');
    await expect(linksDialog).toHaveJSProperty('open', false);

    // Delete user through native <dialog> ConfirmDialog
    await page.getByRole('button', { name: 'Delete e2e-user' }).click();
    const confirmDialog = page.locator('dialog.confirm-dialog');
    await expect(confirmDialog).toHaveJSProperty('open', true);
    await confirmDialog.getByRole('button', { name: 'Delete' }).click();

    await expect(confirmDialog).toHaveJSProperty('open', false);
    await expect(page.getByRole('table').getByText('e2e-user')).toHaveCount(0);

    const delCalls = api.callsFor('DELETE', '/ss/dashboard/api/clusters/cloud/users/e2e-user');
    expect(delCalls).toHaveLength(1);
    expect(delCalls[0].headers['content-type']).toContain('application/json');

    // Navigate to Mesh Cluster (/ss/cluster)
    await page.getByRole('navigation').getByRole('button', { name: 'Mesh cluster' }).click();
    await expect(page.getByRole('heading', { name: 'Cluster Members' })).toBeVisible();
    await expect(page.getByText('PSK: Match')).toBeVisible();

    // Navigate to Server Settings (/ss/settings), test 5 tabs & save
    await page.getByRole('navigation').getByRole('button', { name: 'Settings' }).first().click();
    const tablist = page.getByRole('tablist', { name: 'Server configuration sections' });
    await expect(tablist.getByRole('tab')).toHaveCount(5);

    await tablist.getByRole('tab', { name: 'Network & TLS' }).click();
    const listenInput = page.getByLabel('Listen address (per-node)');
    await listenInput.fill('0.0.0.0:9443');

    const saveBar = page.getByRole('region', { name: 'Unsaved settings bar' });
    await saveBar.getByRole('button', { name: /Save to cluster/ }).click();

    await expect
      .poll(() => api.callsFor('PATCH', '/ss/dashboard/api/clusters/cloud/config').length)
      .toBe(1);
    await expect(page.getByText(/Settings saved without requiring server restart/)).toBeVisible();

    guard.assertClean();
  });
});
