import { test, expect } from '@playwright/test';

test('landing chapters, interactive protocol and console entry', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Power needs a boundary.' })).toBeVisible();
  await expect(page.locator('[data-chapter]')).toHaveCount(7);
  await expect(page.getByRole('heading', { name: /After the breach/ })).toHaveCount(1);
  await expect(page.getByRole('link', { name: /Read Binance/ })).toHaveAttribute('href', 'https://www.binance.com/fr-AF/blog/community/3229153443759566763');
  await expect(page.getByText('A Bitcoin exchange', { exact: false })).toHaveCount(0);
  await page.locator('.instrument-controls').getByRole('button', { name: /Approve/ }).click();
  await expect(page.getByRole('img', { name: /Permission review mechanism/ })).toHaveAttribute('aria-label', /stage 2/);
  await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'The protocol', exact: true }).click();
  await expect(page.locator('#chapter-1')).toBeInViewport();
  await page.getByRole('button', { name: /Trust the outcome/ }).click();
  await expect(page.locator('#protocol-display')).toContainText('TARGET VERIFICATION');
  await page.getByRole('button', { name: /One person cannot become a quorum/ }).click();
  await expect(page.locator('#evidence-1')).toBeVisible();
  await page.getByRole('button', { name: /One person cannot become a quorum/ }).click();
  await expect(page.locator('#evidence-1')).toBeHidden();
  await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('link', { name: 'Enter console' }).click();
  await expect(page.getByTestId('signed-in-actor')).toContainText('user:rahul-assistant');
  await expect(page).toHaveURL(/#\/console\?demo=1$/);
  for (const tab of ['Policy history', 'Incidents', 'Audit']) {
    const response = page.waitForResponse(r => r.url().includes(tab === 'Incidents' ? '/ListIncidents' : tab === 'Audit' ? '/QueryAuditEvents' : '/ListPolicyHistory'));
    await page.getByRole('navigation', { name: 'Console' }).getByRole('button', { name: tab, exact: true }).click();
    const denied = await response;
    expect(denied.status()).toBe(403);
    if (tab === 'Incidents') expect(denied.request().postDataJSON().pageSize).toBe(20);
    await expect(page.getByTestId('access-restricted')).toBeVisible();
    await expect(page.getByRole('alert')).toHaveCount(0);
  }
  await page.getByRole('link', { name: 'Back to website' }).click();
  await expect(page.getByRole('heading', { name: 'Power needs a boundary.' })).toBeVisible();
  expect(errors).toEqual([]);
});

test('mobile menu, small screens and reduced motion', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  for (const width of [360, 390, 768, 1440]) {
    await page.setViewportSize({ width, height: 844 });
    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'Power needs a boundary.' })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    expect(await page.locator('.scroll-wheel > span').evaluate(el => getComputedStyle(el).animationName)).toBe('none');
    await page.locator('.chapter-dock').getByRole('button', { name: 'Enter Ratchet' }).click();
    await expect(page.locator('.entry-link')).toBeInViewport();
    await expect(page.locator('.chapter-dock button[aria-current]')).toHaveAttribute('aria-label', 'Enter Ratchet');
  }
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/');
  await page.getByRole('button', { name: 'Open menu' }).click();
  await expect(page.getByRole('button', { name: 'Close menu' })).toHaveAttribute('aria-expanded', 'true');
  await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('link', { name: 'Enter console' }).click();
  await expect(page.getByTestId('signed-in-actor')).toContainText('user:rahul-assistant');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});
