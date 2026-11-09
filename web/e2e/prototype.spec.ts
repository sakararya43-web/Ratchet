import { test, expect, type Page, type BrowserContext } from '@playwright/test';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { call, change, changesTab, submit, state, review, approve, observed, adversarialApproval } from './prototype.helpers';

const local = resolve('..', '.local', process.env.RATCHET_LOCAL_PROFILE??'prototype');
const users = JSON.parse(readFileSync(resolve(local, 'users.json'), 'utf8')) as { tenant_id: string; users: { actor_id: string; password: string }[] };
const tickets = JSON.parse(readFileSync(resolve(local, 'browser-tickets.json'), 'utf8')) as Record<string, string>;
const tenant = users.tenant_id;

test('real local prototype: independent browser approval, verified target access and audit', async ({ browser }) => {
  const contexts: BrowserContext[] = [];
  const pages = new Map<string, Page>();
  const runtimeErrors: string[] = [];
  const proof: Record<string, unknown> = {};
  const enrolled = new Map<string, string>();
  try {
    for (const user of users.users) {
      const context = await browser.newContext({ baseURL: 'https://localhost:8444' });
      contexts.push(context);
      const page = await context.newPage();
      pages.set(user.actor_id, page);
      page.on('pageerror', e => runtimeErrors.push(e.message));
      const cdp = await context.newCDPSession(page);
      await cdp.send('WebAuthn.enable');
      const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
      await page.goto('/#/console');
      await page.getByLabel('Tenant', { exact: true }).fill(tenant);
      await page.getByLabel('Actor', { exact: true }).fill(user.actor_id);
      await page.getByLabel('Password', { exact: true }).fill(user.password);
      await page.getByRole('button', { name: 'Sign in', exact: true }).click();
      await expect(page.getByTestId('signed-in-actor')).toContainText(user.actor_id);
      await page.getByRole('navigation').getByRole('button', { name: 'Passkeys', exact: true }).click();
      await expect(page.getByRole('button', { name: 'Register with your authenticator' })).toBeEnabled();
      const refused = await page.evaluate(async () => {
        const s = await (await fetch('/api/auth/session')).json();
        return (await fetch('/api/passkeys/register/begin', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': s.csrf_token }, body: '{}' })).status;
      });
      expect(refused).toBe(403);
      await page.getByLabel('Label', { exact: true }).fill('Prototype browser acceptance');
      await page.getByLabel('Enrollment ticket', { exact: true }).fill(tickets[user.actor_id]);
      await page.getByRole('button', { name: 'Register with your authenticator' }).click();
      await expect(page.getByText('Passkey registered for this signed-in account.', { exact: true })).toBeVisible();
      const credentials = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
      expect(credentials.credentials).toHaveLength(1);
      enrolled.set(user.actor_id, Buffer.from(credentials.credentials[0].credentialId, 'base64').toString('hex'));
      await changesTab(page);
    }
    const intern = pages.get('user:rahul-assistant')!;
    const owner = pages.get('user:finance-lead')!;
    const lead1 = pages.get('user:sec-lead-1')!;
    const lead2 = pages.get('user:sec-lead-2')!;
    const business = async (path: string) => (await intern.request.post(`http://127.0.0.1:58085/api/v1/business/${path}`, { timeout: 10_000, data: { session_id: 'session:intern-workstation-1', amount_usd: 100 } })).status();
    // Restore any grants left by an interrupted earlier acceptance through the
    // real reduction workflow. Never reset the target, accounts or ledger.
    const initial = await (await intern.request.get('http://127.0.0.1:58085/api/v1/org', { timeout: 10_000 })).json();
    for (const role of ['role:wallet-operator', 'role:finance-analyst']) {
      if (initial.grants.some((g: { identity_id: string; role_id: string }) => g.identity_id === 'user:rahul-assistant' && g.role_id === role)) {
        const removal = await submit(intern, role, 'ROLE_REVOKE');
        const reviewer = role === 'role:wallet-operator' ? lead1 : owner;
        await state(intern, removal, 'AWAITING_APPROVAL');
        await state(reviewer, removal, 'AWAITING_APPROVAL');
        await approve(reviewer, removal);
        await state(intern, removal, 'EXECUTED');
        await observed(lead1, role, false);
      }
    }
    expect(await business('finance-report/read')).toBe(403);
    expect(await business('wallet/sign')).toBe(403);
    const stale = await submit(intern, 'role:wallet-operator');
    await state(intern, stale, 'AWAITING_APPROVAL');
    const staleContext = await change(lead1, tenant, stale);
    const forbiddenReview = await intern.evaluate(async id => (await fetch(`/api/console/approval-review?request_id=${encodeURIComponent(id)}`)).status, stale);
    expect(forbiddenReview).toBe(403);
    const ownerScope = await owner.evaluate(async () => (await (await fetch('/api/console/bootstrap')).json()).scope);
    expect(ownerScope).toBe('SELF');
    proof.request_review_preserves_restricted_graph_visibility = true;
    const self = await adversarialApproval(intern, tenant, staleContext);
    expect(self.status).toBe(403);
    proof.self_approval_refused = true;
    const ordinary = await submit(intern, 'role:finance-analyst');
    await state(intern, ordinary, 'AWAITING_APPROVAL');
    await state(owner, ordinary, 'AWAITING_APPROVAL');
    // Fault injection is isolated to the test browser, using the real response.
    let assertionBegins = 0;
    owner.on('request', r => { if (r.url().endsWith('/passkeys/assert/begin')) assertionBegins++; });
    await owner.route('**/ratchet.v1.ChangeService/GetChange', async route => {
      const response = await route.fetch();
      const body = await response.json();
      if (body.request.requestId === ordinary) {
        const e = JSON.parse(Buffer.from(body.request.canonicalApprovalEnvelopeJson, 'base64').toString('utf8'));
        e.intent.requested_access = 'role:exchange-admin';
        body.request.canonicalApprovalEnvelopeJson = Buffer.from(JSON.stringify(e)).toString('base64');
      }
      await route.fulfill({ response, json: body });
    });
    await owner.getByTestId(`change-${ordinary}`).getByRole('button', { name: 'Review exact change' }).click();
    await expect(owner.getByRole('alert')).toContainText('digest mismatch');
    expect(assertionBegins).toBe(0);
    await owner.unroute('**/ratchet.v1.ChangeService/GetChange');
    proof.tampered_envelope_refused_before_passkey = true;
    await review(owner, ordinary);
    await owner.route('**/passkeys/assert/begin', async route => {
      const response = await route.fetch();
      const body = await response.json();
      body.options.publicKey.challenge = Buffer.alloc(32).toString('base64url');
      await route.fulfill({ response, json: body });
    });
    await owner.getByRole('button', { name: 'Approve reviewed change with passkey' }).click();
    await expect(owner.getByRole('alert')).toContainText('challenge is not bound');
    await owner.unroute('**/passkeys/assert/begin');
    proof.tampered_challenge_refused = true;
    const ownerApproval = await approve(owner, ordinary);
    expect(ownerApproval.requiredQuorum).toBe(1);
    await state(intern, ordinary, 'EXECUTED');
    await observed(lead1, 'role:finance-analyst', true);
    expect(await business('finance-report/read')).toBe(200);
    proof.ordinary = ordinary;
    const staleResult = await adversarialApproval(lead1, tenant, staleContext);
    expect(staleResult.status).toBe(200);
    expect(staleResult.body.request.status).toBe('HELD');
    expect(await business('wallet/sign')).toBe(403);
    proof.stale_context_held = stale;
    const sensitive = await submit(intern, 'role:wallet-operator');
    await state(intern, sensitive, 'AWAITING_APPROVAL');
    await state(lead1, sensitive, 'AWAITING_APPROVAL');
    const first = await approve(lead1, sensitive);
    expect(first.requiredQuorum).toBe(2);
    expect(first.status).toBe('AWAITING_APPROVAL');
    expect(await business('wallet/sign')).toBe(403);
    const duplicate = await adversarialApproval(lead1, tenant, await change(lead1, tenant, sensitive));
    expect(duplicate.status).not.toBe(200);
    expect(await business('wallet/sign')).toBe(403);
    proof.insufficient_and_duplicate_quorum_refused = true;
    await state(lead2, sensitive, 'AWAITING_APPROVAL');
    await approve(lead2, sensitive);
    await state(intern, sensitive, 'EXECUTED');
    await observed(lead1, 'role:wallet-operator', true);
    expect(await business('wallet/sign')).toBe(200);
    proof.sensitive = sensitive;
    const audit = await call(lead1, tenant, 'AuditService', 'QueryAuditEvents', { requestId: sensitive, pageSize: 100 });
    expect(audit.status).toBe(200);
    expect(audit.body.events.filter((e: { eventType: string }) => e.eventType === 'ChangeApprovalRecorded')).toHaveLength(2);
    expect(audit.body.events.some((e: { eventType: string }) => e.eventType === 'ChangeExecuted')).toBe(true);
    await lead1.getByRole('navigation').getByRole('button', { name: 'Audit', exact: true }).click();
    await expect(lead1.getByRole('button', { name: 'Find request audit' })).toBeEnabled();
    await lead1.getByLabel('Request', { exact: true }).fill(sensitive);
    await lead1.getByRole('button', { name: 'Find request audit' }).click();
    await expect(lead1.getByRole('cell', { name: 'ChangeExecuted', exact: true })).toHaveCount(1);
    await expect(lead1.getByRole('cell', { name: 'ChangeExecuted', exact: true })).toBeVisible();
    await lead1.screenshot({ path: resolve(local, 'audit-acceptance.png'), fullPage: true });
    // Verify actual exported canonical bytes and hash continuity independently.
    let pageToken = '', previous = '00'.repeat(32), checked = 0, endHash = '';
    do {
      const exported = await call(lead1, tenant, 'AuditService', 'ExportHashChain', { pageSize: 100, pageToken });
      expect(exported.status).toBe(200);
      for (const event of exported.body.chain) {
        expect(event.previousEventHash).toBe(previous);
        const hash = createHash('sha256').update(Buffer.from(previous, 'hex')).update(Buffer.from(event.canonicalContent, 'base64')).digest('hex');
        expect(hash).toBe(event.eventHash);
        previous = hash;
        checked++;
      }
      pageToken = exported.body.nextPageToken ?? '';
      endHash = exported.body.snapshotEndHash;
    } while (pageToken);
    expect(previous).toBe(endHash);
    proof.canonical_ledger_events_verified = checked;
    await intern.screenshot({ path: resolve(local, 'changes-acceptance.png'), fullPage: true });
    for (const role of ['role:wallet-operator', 'role:finance-analyst']) {
      const removal = await submit(intern, role, 'ROLE_REVOKE');
      const reviewer = role === 'role:wallet-operator' ? lead1 : owner;
      if (reviewer === lead1) await changesTab(lead1);
      await state(intern, removal, 'AWAITING_APPROVAL');
      await state(reviewer, removal, 'AWAITING_APPROVAL');
      await approve(reviewer, removal);
      await state(intern, removal, 'EXECUTED');
      await observed(lead1, role, false);
    }
    expect(await business('finance-report/read')).toBe(403);
    expect(await business('wallet/sign')).toBe(403);
    proof.real_reduction_cleanup_verified = true;
    for (const [actor, page] of pages) {
      const credential = enrolled.get(actor)!;
      execFileSync(process.env.RATCHET_PYTHON ?? 'python3', ['scripts/prototype.py', 'invite', '--actor', actor,
        '--operation', 'revoke', '--credential', credential], { cwd: resolve('..'), stdio: 'pipe' });
      const authorization = JSON.parse(readFileSync(resolve(local, 'credential-authorization.json'), 'utf8'));
      await page.getByRole('navigation').getByRole('button', { name: 'Passkeys', exact: true }).click();
      await expect(page.getByRole('button', { name: 'Revoke credential', exact: true })).toBeEnabled();
      await page.getByLabel('Credential', { exact: true }).fill(credential);
      await page.getByLabel('Revocation ticket', { exact: true }).fill(authorization.ticket);
      await page.getByRole('button', { name: 'Revoke credential', exact: true }).click();
      await expect(page.getByText('Credential revoked.', { exact: true })).toBeVisible();
      const revoked = await page.evaluate(async id => (await (await fetch('/api/passkeys/list')).json()).some((c: { credential_id: string; revoked: boolean }) => c.credential_id === id && c.revoked), credential);
      expect(revoked).toBe(true);
    }
    proof.operator_authorized_browser_revocation_verified = true;
    expect(runtimeErrors).toEqual([]);
    proof.browser_runtime_errors = runtimeErrors;
    proof.actors = users.users.map(u => u.actor_id);
    proof.authenticator = 'Chromium CTAP2 virtual authenticators; native WebAuthn with real backend verification';
    proof.completed_at = new Date().toISOString();
    writeFileSync(resolve(local, 'browser-evidence.json'), JSON.stringify(proof, null, 2) + '\n');
  } finally {
    for (const context of contexts) await context.close().catch(() => {});
  }
});
