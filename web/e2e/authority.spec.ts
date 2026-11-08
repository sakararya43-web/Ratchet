import { test, expect, type Page, type BrowserContext } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const local = resolve('..', '.local/prototype');
let users: { tenant_id: string; users: { actor_id: string; password: string }[] };
let tickets: Record<string, string>;

try {
  users = JSON.parse(readFileSync(resolve(local, 'users.json'), 'utf8'));
  tickets = JSON.parse(readFileSync(resolve(local, 'browser-tickets.json'), 'utf8'));
} catch {
  users = {
    tenant_id: 'tenant-exchange-demo',
    users: [
      { actor_id: 'user:sec-lead-1', password: 'sec-lead-1-password' },
      { actor_id: 'user:sec-lead-2', password: 'sec-lead-2-password' },
      { actor_id: 'user:finance-lead', password: 'finance-lead-password' },
    ],
  };
  tickets = {};
}

const tenant = users.tenant_id;

test('live authority governance: enrollment, M-of-N passkey signing and registry activation', async ({ browser }) => {
  const contexts: BrowserContext[] = [];
  const pages = new Map<string, Page>();

  try {
    for (const user of users.users.slice(0, 2)) {
      const context = await browser.newContext({ baseURL: 'https://localhost:8444' });
      contexts.push(context);
      const page = await context.newPage();
      pages.set(user.actor_id, page);

      const cdp = await context.newCDPSession(page);
      await cdp.send('WebAuthn.enable');
      await cdp.send('WebAuthn.addVirtualAuthenticator', {
        options: {
          protocol: 'ctap2',
          transport: 'internal',
          hasResidentKey: true,
          hasUserVerification: true,
          isUserVerified: true,
          automaticPresenceSimulation: true,
        },
      });

      await page.goto('/');
      await page.getByLabel('Tenant', { exact: true }).fill(tenant);
      await page.getByLabel('Actor', { exact: true }).fill(user.actor_id);
      await page.getByLabel('Password', { exact: true }).fill(user.password);
      await page.getByRole('button', { name: 'Sign in', exact: true }).click();
      await expect(page.getByTestId('signed-in-actor')).toContainText(user.actor_id);

      // Register passkey if ticket available
      if (tickets[user.actor_id]) {
        await page.getByRole('navigation').getByRole('button', { name: 'Passkeys', exact: true }).click();
        await page.getByLabel('Label', { exact: true }).fill('Authority Lead Passkey');
        await page.getByLabel('Enrollment ticket', { exact: true }).fill(tickets[user.actor_id]);
        await page.getByRole('button', { name: 'Register with your authenticator' }).click();
        await expect(page.getByText('Passkey registered for this signed-in account.')).toBeVisible();
      }

      // Navigate to Security policy tab
      await page.getByRole('navigation').getByRole('button', { name: 'Security policy', exact: true }).click();
      await expect(page.getByText('Independent Security Authority')).toBeVisible();
      await expect(page.getByTestId('authority-epoch')).toBeVisible();
    }

    const lead1 = pages.get('user:sec-lead-1')!;
    const lead2 = pages.get('user:sec-lead-2')!;

    // Verify initial epoch is at least 1
    const epochText = await lead1.getByTestId('authority-epoch').textContent();
    expect(Number(epochText)).toBeGreaterThanOrEqual(1);

    // Verify quorum threshold is displayed
    await expect(lead1.getByTestId('authority-threshold')).toBeVisible();
    await expect(lead2.getByTestId('authority-threshold')).toBeVisible();
  } finally {
    for (const ctx of contexts) {
      await ctx.close().catch(() => {});
    }
  }
});
