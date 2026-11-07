import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { canonicalize, digestJSON } from './canon.ts';
import { verifyEnvelope, verifyChallenge, type EnvelopeView } from './envelope.ts';

async function example() {
 const e = { format_version: 2, tenant_id: 'tenant', request_id: 'request', request_revision: 3, authenticated_requester: 'requester', graph_version: 7, expires_at: '2026-11-08T12:00:00Z', intent: { kind: 'ROLE_ASSIGN', target_identity: 'intern', requested_access: 'finance', time_limit_seconds: 0, emergency: false }, impact_digest: [1], policy_bundle_hash: [2] };
 const raw = canonicalize(e);
 const view: EnvelopeView = { tenantId: 'tenant', requestId: 'request', requestedBy: 'requester', revision: '4', graphVersion: '7', kind: 'ROLE_ASSIGN', targetIdentity: 'intern', requestedAccess: 'finance', changeDigest: await digestJSON(raw), canonicalApprovalEnvelopeJson: Buffer.from(raw).toString('base64') };
 return { view, e };
}
test('browser verifies exact canonical server envelope and context before passkey', async () => {
 const { view, e } = await example(); assert.deepEqual(await verifyEnvelope(view, 'tenant', 0), e);
 for (const changed of [{ ...view, changeDigest: '00'.repeat(32) }, { ...view, requestId: 'other' }, { ...view, targetIdentity: 'other' }, { ...view, requestedAccess: 'admin' }, { ...view, graphVersion: '8' }, { ...view, requestedBy: 'other' }, { ...view, canonicalApprovalEnvelopeJson: Buffer.from(JSON.stringify(e, null, 2)).toString('base64') }]) await assert.rejects(verifyEnvelope(changed, 'tenant', 0));
 await assert.rejects(verifyEnvelope(view, 'other', 0)); await assert.rejects(verifyEnvelope(view, 'tenant', Date.parse(e.expires_at)));
});
test('browser checks the core domain-separated actor/digest/nonce challenge', async () => {
 const hash = 'ab'.repeat(32), nonce = 'cd'.repeat(32);
 const challenge = createHash('sha256').update('RATCHET_APPROVAL_V1:tenant:actor:').update(Buffer.from(hash, 'hex')).update(':').update(Buffer.from(nonce, 'hex')).digest('base64url');
 await verifyChallenge('tenant', 'actor', hash, nonce, challenge);
 for (const args of [['tenant', 'other', hash, nonce, challenge], ['tenant', 'actor', 'ef'.repeat(32), nonce, challenge], ['tenant', 'actor', hash, 'ef'.repeat(32), challenge]]) await assert.rejects(verifyChallenge(...args as [string, string, string, string, string]));
});
