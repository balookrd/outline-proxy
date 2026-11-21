import { expect, test } from '@playwright/test';
import { attachErrorGuard, mockOutlineApi } from './mock-api.ts';

test.describe('WS dashboard workflows', () => {
  test('exercises Topology, Uplinks, Routing, UplinkGroups, and WsSettings flows', async ({ page }) => {
    const guard = attachErrorGuard(page);
    const api = await mockOutlineApi(page);

    // 1. Topology (/ws)
    await page.goto('/ws');
    await expect(page.getByText('beelink102-primary')).toBeVisible();
    await page.getByRole('button', { name: 'Reselect the active uplink for main' }).first().click();
    await expect.poll(() => api.callsFor('POST', '/ws/dashboard/api/reselect').length).toBe(1);

    // 2. Uplinks (/ws/uplinks)
    const nav = page.getByRole('navigation');
    await nav.getByRole('button', { name: 'Uplinks' }).click();
    await expect(page.getByText('cloud1-edge')).toBeVisible();

    await page.getByRole('button', { name: 'Add uplink' }).click();
    const uplinkDrawer = page.locator('aside.drawer.open');
    await uplinkDrawer.getByLabel('Name').fill('e2e-uplink');
    await uplinkDrawer.getByLabel('Use a share link').check();
    await uplinkDrawer
      .getByLabel('Share link', { exact: true })
      .fill('vless://11111111-1111-4111-8111-111111111111@edge.fleet.example:443');
    await uplinkDrawer.getByRole('button', { name: 'Create' }).click();

    await expect(page.getByText('e2e-uplink')).toBeVisible();
    await page.getByRole('button', { name: 'Apply now' }).click();
    await expect.poll(() => api.callsFor('POST', '/ws/dashboard/api/apply').length).toBe(1);

    // 3. Routing (/ws/routing)
    await nav.getByRole('button', { name: 'Routing' }).click();
    await expect(page.getByText('youtube.com')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Move rule #2 up' })).toBeDisabled();
    await expect(page.getByRole('button', { name: 'Delete rule #2' })).toBeDisabled();
    await expect(page.getByRole('button', { name: 'Move rule #1 down' })).toBeDisabled();

    await page.getByRole('button', { name: 'Add rule' }).click();
    const routeDrawer = page.locator('aside.drawer.open');
    await routeDrawer.getByLabel('Target (via)').selectOption('main');
    await routeDrawer.getByLabel('Domain suffixes').fill('example.org');
    await routeDrawer.getByRole('button', { name: 'Create' }).click();
    await expect(page.getByText('example.org')).toBeVisible();

    // 4. Uplink groups (/ws/groups)
    await nav.getByRole('button', { name: 'Uplink groups' }).click();
    await expect(page.getByRole('button', { name: 'Delete group main' })).toBeDisabled();
    await expect(page.getByRole('button', { name: 'Delete group empty-backup' })).toBeEnabled();

    page.once('dialog', (dialog) => dialog.accept());
    await page.getByRole('button', { name: 'Delete group empty-backup' }).click();
    await expect(page.getByText('empty-backup')).toHaveCount(0);

    // 5. Client Settings (/ws/settings)
    await nav.getByRole('button', { name: 'Settings' }).nth(1).click();
    const socksListen = page.getByLabel('SOCKS5 Listen Address');
    await expect(socksListen).toHaveValue('127.0.0.1:1080');
    await socksListen.fill('127.0.0.1:1081');

    await page.getByRole('button', { name: 'Save changes' }).click();
    await expect(page.getByText('RESTART REQUIRED')).toBeVisible();

    await page.getByRole('button', { name: 'Apply now' }).click();
    await expect.poll(() => api.callsFor('POST', '/ws/dashboard/api/apply').length).toBe(2);

    guard.assertClean();
  });
});
