import { canonicalizeJSON, digestJSON, digest } from './canon.ts';

export interface EnvelopeView {
 tenantId: string; requestId: string; kind: string; targetIdentity: string;
 requestedAccess: string; requestedBy?: string; revision: string; graphVersion?: string;
 changeDigest: string; canonicalApprovalEnvelopeJson?: string;
}
export interface ApprovalEnvelope {
 format_version: number; tenant_id: string; request_id: string; request_revision: number;
 authenticated_requester: string; graph_version: number; expires_at: string;
 intent: { kind: string; target_identity: string; requested_access: string; time_limit_seconds: number; emergency: boolean };
 impact_digest: number[]; policy_bundle_hash: number[];
}
function unhex(value: string): Uint8Array<ArrayBuffer> {
 if (!/^[a-f0-9]{64}$/.test(value)) throw new Error('Invalid approval digest or challenge nonce');
 return Uint8Array.from(value.match(/../g)!, b => parseInt(b, 16));
}
export async function verifyEnvelope(view: EnvelopeView, tenant: string, now = Date.now()): Promise<ApprovalEnvelope> {
 if (!view.canonicalApprovalEnvelopeJson || view.tenantId !== tenant) throw new Error('Exact authorized approval envelope unavailable');
 const raw = new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(atob(view.canonicalApprovalEnvelopeJson), c => c.charCodeAt(0)));
 if (canonicalizeJSON(raw) !== raw || await digestJSON(raw) !== view.changeDigest) throw new Error('Approval envelope digest mismatch; no passkey requested');
 const e = JSON.parse(raw) as ApprovalEnvelope;
 if (e.format_version !== 2 || e.tenant_id !== tenant || e.request_id !== view.requestId || e.intent.kind !== view.kind || e.intent.target_identity !== view.targetIdentity || e.intent.requested_access !== view.requestedAccess || (view.requestedBy && e.authenticated_requester !== view.requestedBy) || String(e.graph_version) !== view.graphVersion || !Number.isSafeInteger(e.request_revision) || e.request_revision < 1 || BigInt(e.request_revision) > BigInt(view.revision)) throw new Error('Approval envelope context mismatch');
 if (!Number.isFinite(Date.parse(e.expires_at)) || Date.parse(e.expires_at) <= now) throw new Error('Approval envelope expired; refresh the request');
 return e;
}
export async function verifyChallenge(tenant: string, actor: string, digest: string, nonce: string, challenge: string): Promise<void> {
 const prefix = new TextEncoder().encode(`RATCHET_APPROVAL_V1:${tenant}:${actor}:`);
 const hash = unhex(digest); const fresh = unhex(nonce);
 const bytes = new Uint8Array(prefix.length + hash.length + 1 + fresh.length);
 bytes.set(prefix); bytes.set(hash, prefix.length); bytes[prefix.length + hash.length] = 58; bytes.set(fresh, prefix.length + hash.length + 1);
 const expected = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
 const actual = Uint8Array.from(atob(challenge.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
 if (actual.length !== expected.length || actual.some((b, i) => b !== expected[i])) throw new Error('Passkey challenge is not bound to this exact envelope and actor');
}

export async function verifyImpact(impact: unknown, envelope: ApprovalEnvelope): Promise<void> {
 const bound = envelope.impact_digest;
 if (!Array.isArray(bound) || bound.length !== 32 || bound.some(b => !Number.isInteger(b) || b < 0 || b > 255)) throw new Error('Invalid bound impact digest');
 const expected = bound.map(b => b.toString(16).padStart(2, '0')).join('');
 if (await digest(impact) !== expected) throw new Error('Review impact digest mismatch; no passkey requested');
}
