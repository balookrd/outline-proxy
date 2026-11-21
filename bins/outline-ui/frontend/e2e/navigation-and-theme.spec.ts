import { expect, test } from '@playwright/test';
import { attachErrorGuard, mockOutlineApi } from './mock-api.ts';

test.describe('desktop shell, navigation, and theme', () => {
  test('renders version in sidebar footer, checks all 9 routes, theme persistence, and deep-links without errors', async ({
    page,
  }) => {
    const guard = attachErrorGuard(page);
    await mockOutlineApi(page);

    await page.goto('/');

    const sidebarFooter = page.locator('.sidebar .foot');
    await expect(sidebarFooter).toBeVisible();
    await expect(sidebarFooter).toContainText('outline-ui');
    await expect(sidebarFooter).toContainText('v26.11.3');
    await expect(page.locator('.topbar .ver-mobile')).toBeHidden();

    await expect(page.getByText('Server dashboard')).toBeVisible();
    await expect(page.getByText('Client dashboard')).toBeVisible();

    const overflowLanding = await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth + 1,
    );
    expect(overflowLanding).toBe(true);

    // Traverse all 9 sidebar items
    const nav = page.getByRole('navigation');
    const settingsBtns = nav.getByRole('button', { name: 'Settings' });

    const navChecks: Array<{ clickTarget: ReturnType<typeof nav.getByRole>; path: string; heading: RegExp }> = [
      { clickTarget: nav.getByRole('button', { name: 'Users' }), path: '/ss', heading: /^Users$/ },
      { clickTarget: nav.getByRole('button', { name: 'Mesh cluster' }), path: '/ss/cluster', heading: /Mesh Cluster/ },
      { clickTarget: settingsBtns.nth(0), path: '/ss/settings', heading: /Server Settings/ },
      { clickTarget: nav.getByRole('button', { name: 'Topology' }), path: '/ws', heading: /Topology/ },
      { clickTarget: nav.getByRole('button', { name: 'Uplinks' }), path: '/ws/uplinks', heading: /Uplinks/ },
      { clickTarget: nav.getByRole('button', { name: 'Routing' }), path: '/ws/routing', heading: /Routing/ },
      { clickTarget: nav.getByRole('button', { name: 'Uplink groups' }), path: '/ws/groups', heading: /Uplink groups/ },
      { clickTarget: settingsBtns.nth(1), path: '/ws/settings', heading: /Client Settings/ },
      { clickTarget: nav.getByRole('button', { name: 'Overview' }), path: '/', heading: /^Overview$/ },
    ];

    for (const item of navChecks) {
      await item.clickTarget.click();
      await expect(page).toHaveURL(new RegExp(`${item.path === '/' ? '/$' : item.path}$`));
      await expect(item.clickTarget).toHaveClass(/active/);
      await expect(page.getByRole('heading', { level: 1, name: item.heading })).toBeVisible();
      const fits = await page.evaluate(
        () => document.documentElement.scrollWidth <= window.innerWidth + 1,
      );
      expect(fits, `Horizontal overflow on ${item.path}`).toBe(true);
    }

    // Theme toggle + meta theme-color + persistence across reload
    const themeBtn = page.getByRole('button', { name: /Switch to (dark|light) theme/ });
    const initialLabel = await themeBtn.getAttribute('aria-label');
    const expectedNext = initialLabel?.includes('dark') ? 'dark' : 'light';

    await themeBtn.click();
    await expect(page.locator('html')).toHaveAttribute('data-theme', expectedNext);
    await expect(page.locator('meta[name="theme-color"]')).toHaveAttribute(
      'content',
      expectedNext === 'dark' ? '#020617' : '#f4f6fb',
    );

    await page.reload();
    await expect(page.locator('html')).toHaveAttribute('data-theme', expectedNext);
    await expect(page.locator('meta[name="theme-color"]')).toHaveAttribute(
      'content',
      expectedNext === 'dark' ? '#020617' : '#f4f6fb',
    );

    // Deep-link reload against real static server SPA fallback
    await page.goto('/ss/settings');
    await expect(page.getByRole('heading', { level: 1, name: /Server Settings/ })).toBeVisible();
    await page.reload();
    await expect(page.getByRole('heading', { level: 1, name: /Server Settings/ })).toBeVisible();

    await page.goto('/ws/routing');
    await expect(page.getByRole('heading', { level: 1, name: /Routing/ })).toBeVisible();

    guard.assertClean();
  });
});

test.describe('mobile responsive layout (<= 900px)', () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test('displays version in mobile topbar and prevents horizontal overflow across views', async ({ page }) => {
    const guard = attachErrorGuard(page);
    await mockOutlineApi(page);

    for (const path of ['/', '/ss', '/ss/settings', '/ws']) {
      await page.goto(path);
      const mobileVer = page.locator('.topbar .ver-mobile');
      await expect(mobileVer).toBeVisible();
      await expect(mobileVer).toHaveText('v26.11.3');
      await expect(page.locator('.sidebar .foot')).toBeHidden();

      const fits = await page.evaluate(
        () => document.documentElement.scrollWidth <= window.innerWidth + 1,
      );
      expect(fits, `Mobile horizontal overflow on ${path}`).toBe(true);
    }

    guard.assertClean();
  });
});
