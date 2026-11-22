import { expect, test, type Page } from '@playwright/test';
import { attachErrorGuard, mockOutlineApi } from './mock-api.ts';

async function assertFormsLayout(page: Page, contextLabel: string) {
  const issues = await page.evaluate(() => {
    const found: string[] = [];

    const docDiff = document.documentElement.scrollWidth - window.innerWidth;
    if (docDiff > 1) {
      found.push(`document overflow: scrollWidth=${document.documentElement.scrollWidth} > innerWidth=${window.innerWidth}`);
    }

    for (const sw of document.querySelectorAll('.switch input')) {
      const r = sw.getBoundingClientRect();
      if (r.width === 0 || r.height === 0) continue;
      if (r.width < 32) {
        const label = sw.closest('label')?.textContent?.trim()?.slice(0, 50) ?? 'switch';
        found.push(`squished switch (${Math.round(r.width)}px): ${label}`);
      }
    }

    const containers = document.querySelectorAll('.panel-form, .subcard, .drawer.open, .ui-dialog[open]');
    for (const c of containers) {
      const cr = c.getBoundingClientRect();
      if (cr.width === 0 || cr.height === 0) continue;

      const controls = c.querySelectorAll('input:not([type="checkbox"]):not([type="radio"]), select, textarea');
      for (const el of controls) {
        if (el.closest('.table-wrapper')) continue;
        const er = el.getBoundingClientRect();
        if (er.width === 0 || er.height === 0) continue;
        const id = el.getAttribute('id') || el.getAttribute('aria-label') || el.getAttribute('placeholder') || el.tagName;
        if (er.right > cr.right + 2 || er.left < cr.left - 2) {
          found.push(
            `control outside container [${id}]: el=[${Math.round(er.left)}..${Math.round(er.right)}], container=[${Math.round(cr.left)}..${Math.round(cr.right)}]`,
          );
        }
        if (er.width < 68) {
          found.push(`cramped control [${id}]: width=${Math.round(er.width)}px`);
        }
      }
    }

    const grids = document.querySelectorAll(
      '.form-grid-2, .form-grid-3, .form-grid-4, .form-grid-2-1, .form-grid-endpoint, .form-grid-kv-action, .tuning-grid, .settings-two-col',
    );
    for (const grid of grids) {
      const gr = grid.getBoundingClientRect();
      if (gr.width === 0 || gr.height === 0) continue;
      const children = Array.from(grid.children)
        .map((el) => ({ el, r: el.getBoundingClientRect() }))
        .filter((item) => item.r.width > 0 && item.r.height > 0);
      for (let i = 0; i < children.length; i++) {
        for (let j = i + 1; j < children.length; j++) {
          const a = children[i].r;
          const b = children[j].r;
          const ox = Math.min(a.right, b.right) - Math.max(a.left, b.left);
          const oy = Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top);
          if (ox > 2 && oy > 2) {
            found.push(`overlapping siblings in ${grid.className}: ox=${Math.round(ox)} oy=${Math.round(oy)}`);
          }
        }
      }
    }

    return found;
  });

  expect(issues, `Layout issues on ${contextLabel}:\n${issues.join('\n')}`).toEqual([]);
}

const VIEWPORTS = [
  { name: 'desktop-1280', width: 1280, height: 900 },
  { name: 'laptop-1080', width: 1080, height: 900 },
  { name: 'mobile-390', width: 390, height: 844 },
] as const;

for (const vp of VIEWPORTS) {
  test.describe(`forms geometry @ ${vp.name}`, () => {
    test.use({ viewport: { width: vp.width, height: vp.height } });

    test('ServerSettings, Cluster, WsSettings, and AccessKeysModal fit cleanly without overflow or squished switches', async ({
      page,
    }) => {
      const guard = attachErrorGuard(page);
      await mockOutlineApi(page);

      // 1. Server Settings: all 5 tabs + dynamic subcards + tuning grid
      await page.goto('/ss/settings');
      const tablist = page.getByRole('tablist', { name: 'Server configuration sections' });
      await expect(tablist).toBeVisible();

      const tabCount = await tablist.getByRole('tab').count();
      for (let i = 0; i < tabCount; i++) {
        const tab = tablist.getByRole('tab').nth(i);
        const tabName = (await tab.textContent())?.trim() ?? `tab-${i}`;
        await tab.click();

        if (tabName === 'Resumption & Camouflage') {
          await page.getByRole('button', { name: '+ Add SNI backend' }).click();
        }
        if (tabName === 'Tuning & System') {
          await page.locator('details.tuning-details > summary').click();
        }
        await assertFormsLayout(page, `ss-settings[${vp.name}]/${tabName}`);
      }

      // Discard so navigating away does not trigger ConfirmDialog
      await page.getByRole('button', { name: 'Discard' }).click();

      // 2. Mesh Cluster: cluster mode & single-node mode
      await page.goto('/ss/cluster');
      await expect(page.getByRole('heading', { name: 'Cluster Members' })).toBeVisible();
      await assertFormsLayout(page, `ss-cluster[${vp.name}]/cluster`);

      const selector = page.getByLabel('Target cluster or server');
      const singleValue = await selector
        .locator('option')
        .evaluateAll((opts) => opts.map((o) => (o as HTMLOptionElement).value).find((v) => v.startsWith('instance:')) ?? null);
      expect(singleValue).toBeTruthy();
      await selector.selectOption(singleValue!);
      await expect(page.getByRole('heading', { name: 'Local Mesh Configuration' })).toBeVisible();
      await assertFormsLayout(page, `ss-cluster[${vp.name}]/single`);

      // Switch back to cluster:cloud so SS target state is clean
      await selector.selectOption('cluster:cloud');

      // 3. AccessKeysModal (Outline + Share Links tabs)
      await page.goto('/ss');
      await page.getByRole('button', { name: 'Links for alice' }).click();
      const dialog = page.locator('dialog.links-dialog');
      await expect(dialog).toHaveJSProperty('open', true);
      await assertFormsLayout(page, `ss-access-keys[${vp.name}]/outline`);

      await dialog.getByRole('tab', { name: 'Share Links' }).click();
      await expect(dialog.getByRole('button', { name: 'Copy all' })).toBeVisible();
      await assertFormsLayout(page, `ss-access-keys[${vp.name}]/share-links`);
      await page.keyboard.press('Escape');
      await expect(dialog).toHaveJSProperty('open', false);

      // 4. Client Settings (WS): default fields + dynamic SOCKS5 user row
      await page.goto('/ws/settings');
      await expect(page.getByRole('heading', { level: 1, name: /Client Settings/ })).toBeVisible();
      await expect(page.getByLabel('SOCKS5 Listen Address')).toBeVisible();
      await page.getByRole('button', { name: '+ Add User' }).click();
      await assertFormsLayout(page, `ws-settings[${vp.name}]`);

      guard.assertClean();
    });
  });
}
