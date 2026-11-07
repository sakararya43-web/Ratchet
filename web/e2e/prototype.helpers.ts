import { expect, type Page } from '@playwright/test';

export async function call(page: Page, tenantId: string, service: string, method: string, body: object) {
  return page.evaluate(async ({ path, body }) => {
    const session = await (await fetch('/api/auth/session')).json();
    const response = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrf_token }, body: JSON.stringify(body) });
    return { status: response.status, body: await response.json() };
  }, { path: `/api/ratchet.v1.${service}/${method}`, body: { tenantId, ...body } });
}

export async function change(page: Page, tenant: string, id: string) {
  const r = await call(page, tenant, 'ChangeService', 'GetChange', { requestId: id });
  expect(r.status).toBe(200);
  return r.body.request;
}

export async function changesTab(page: Page) {
  await page.getByRole('navigation').getByRole('button', { name: 'Changes', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Submit for assessment' })).toBeEnabled();
}

export async function submit(page: Page, role: string, kind = 'ROLE_ASSIGN') {
  await page.getByLabel('Kind', { exact: true }).selectOption(kind);
  await page.getByLabel('Identity', { exact: true }).fill('user:rahul-assistant');
  await page.getByLabel('Access', { exact: true }).fill(role);
  await page.getByLabel('Justification', { exact: true }).fill(`Prototype acceptance ${kind} ${role}`);
  const response = page.waitForResponse(r => r.url().endsWith('.ChangeService/SubmitChange'));
  await page.getByRole('button', { name: 'Submit for assessment' }).click();
  const r = await response;
  expect(r.status()).toBe(200);
  return (await r.json()).request.requestId as string;
}

export async function state(page: Page, id: string, value: string) {
  await expect(page.getByTestId(`change-${id}`).getByTestId('change-status')).toHaveText(value);
}

export async function review(page: Page, id: string) {
  await page.getByTestId(`change-${id}`).getByRole('button', { name: 'Review exact change' }).click();
  await expect(page.getByTestId('verified-envelope-digest')).toHaveText(/^[a-f0-9]{64}$/);
  await expect(page.getByRole('button', { name: 'Approve reviewed change with passkey' })).toBeEnabled();
}

export async function approve(page: Page, id: string) {
  await review(page, id);
  const response = page.waitForResponse(r => r.url().endsWith('.ChangeService/ApproveChange'));
  await page.getByRole('button', { name: 'Approve reviewed change with passkey' }).click();
  const r = await response;
  expect(r.status()).toBe(200);
  return (await r.json()).request;
}

export async function observed(page: Page, role: string, present: boolean) {
  await expect.poll(async () => page.evaluate(async ({ role }) => {
    const graph = await (await fetch('/api/console/bootstrap')).json();
    return graph.edges.some((e: { source: string; target: string; kind: string }) => e.source === 'user:rahul-assistant' && e.target === role && e.kind === 'ASSIGNED');
  }, { role }), { intervals: [1000] }).toBe(present);
}

// Negative tests use the real browser authenticator and public session/CSRF/
// passkey endpoints. There is no fake assertion or alternate approval endpoint.
export async function adversarialApproval(page: Page, tenantId: string, c: { requestId: string; revision: string; changeDigest: string }) {
  return page.evaluate(async ({ tenantId, c }) => {
    const session = await (await fetch('/api/auth/session')).json();
    const post = async (path: string, body: object) => fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrf_token }, body: JSON.stringify(body) });
    const begin = await (await post('/api/passkeys/assert/begin', { change_digest: c.changeDigest })).json();
    const decode = (s: string) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), ch => ch.charCodeAt(0));
    const o = begin.options.publicKey;
    const credential = await navigator.credentials.get({ publicKey: { ...o, challenge: decode(o.challenge), allowCredentials: o.allowCredentials.map((v: { id: string }) => ({ ...v, id: decode(v.id) })) } }) as PublicKeyCredential;
    const assertion = credential.response as AuthenticatorAssertionResponse;
    const encode = (b: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(b)));
    const hex = (b: ArrayBuffer) => Array.from(new Uint8Array(b), x => x.toString(16).padStart(2, '0')).join('');
    const verified = await (await post('/api/passkeys/assert/finish', { session_id: begin.session_id, credential_id: hex(credential.rawId), client_data_json: encode(assertion.clientDataJSON), authenticator_data: encode(assertion.authenticatorData), signature: encode(assertion.signature) })).json();
    const response = await post('/api/ratchet.v1.ChangeService/ApproveChange', { tenantId, requestId: c.requestId, approvedEnvelopeDigest: c.changeDigest, assertionResponseJson: JSON.stringify(verified.submission), mutation: { idempotencyKey: crypto.randomUUID(), correlationId: crypto.randomUUID(), expectedRevision: c.revision } });
    return { status: response.status, body: await response.json() };
  }, { tenantId, c });
}
