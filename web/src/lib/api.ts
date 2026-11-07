import { verifyChallenge, verifyEnvelope } from './envelope.ts';
// Only the authenticated same-origin core is a browser API.
export interface Principal { tenant_id: string; actor_id: string }
export interface Session { principal: Principal; csrf_token: string }
export interface Bootstrap { principal: Principal; graph_version: number; scope: string; nodes: { id: string; type: string; display_name: string; tier?: number }[]; edges: { id: string; source: string; target: string; kind: string }[] }
export interface Change { requestId: string; tenantId: string; requestedBy?: string; canonicalApprovalEnvelopeJson?: string; graphVersion?: string; requiredApproverGroups?: string[]; kind: string; targetIdentity: string; requestedAccess: string; status: string; revision: string; changeDigest: string; requiredQuorum?: number; decisionReasons?: string[]; justification?: string }
export type Document = Record<string, unknown>;
let csrf = '';
export async function request<T>(path: string, body?: unknown, headers: Record<string, string> = {}): Promise<T> {
  if (!path.startsWith('/api/')) throw new Error('Same-origin core API required');
  const response = await fetch(path, { method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', headers: { ...headers, 'Content-Type': 'application/json', 'X-CSRF-Token': csrf }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  const text = await response.text();
  if (!response.ok) throw new Error(`${response.status}: ${text.slice(0, 1000)}`);
  return text ? JSON.parse(text) as T : undefined as T;
}
export async function session(): Promise<Session> { const s = await request<Session>('/api/auth/session'); csrf = s.csrf_token; return s; }
export async function login(tenant: string, actor: string, password: string): Promise<Session> { const s = await request<Session>('/api/auth/login', { tenant_id: tenant, actor_id: actor, password }); csrf = s.csrf_token; return s; }
export function rpc<T>(service: string, method: string, body: unknown): Promise<T> { return request<T>(`/api/ratchet.v1.${service}/${method}`, body); }
export function mutation(revision = '0') { return { idempotencyKey: crypto.randomUUID(), correlationId: crypto.randomUUID(), expectedRevision: revision }; }
export function decode(raw: string): Uint8Array<ArrayBuffer> { return Uint8Array.from(atob(raw.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)); }
export function encode(raw: ArrayBuffer): string { return btoa(String.fromCharCode(...new Uint8Array(raw))); }
function urlEncode(raw: ArrayBuffer): string { return encode(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function hex(raw: ArrayBuffer): string { return Array.from(new Uint8Array(raw), b => b.toString(16).padStart(2, '0')).join(''); }
type Options = { session_id: string; options: { publicKey: Record<string, unknown> }; challenge_nonce?: string };
function descriptors(value: unknown): PublicKeyCredentialDescriptor[] | undefined { return (value as { id: string; type: 'public-key' }[] | undefined)?.map(v => ({ ...v, id: decode(v.id) })); }
export async function registerPasskey(label: string, ticket: string): Promise<void> {
  const begin = await request<Options>('/api/passkeys/register/begin', {}, { 'X-Ratchet-Credential-Authorization': ticket });
  const o = begin.options.publicKey as unknown as Omit<PublicKeyCredentialCreationOptions, 'challenge' | 'user' | 'excludeCredentials'> & { challenge: string; user: { id: string; name: string; displayName: string }; excludeCredentials?: { id: string; type: 'public-key' }[] };
  const user = o.user as { id: string; name: string; displayName: string };
  const credential = await navigator.credentials.create({ publicKey: { ...o, challenge: decode(o.challenge as string), user: { ...user, id: decode(user.id) }, excludeCredentials: descriptors(o.excludeCredentials) } as PublicKeyCredentialCreationOptions }) as PublicKeyCredential | null;
  if (!credential) throw new Error('Registration cancelled');
  const response = credential.response as AuthenticatorAttestationResponse;
  await request(`/api/passkeys/register/finish?session_id=${encodeURIComponent(begin.session_id)}&label=${encodeURIComponent(label)}`, { id: credential.id, rawId: urlEncode(credential.rawId), type: credential.type, authenticatorAttachment: credential.authenticatorAttachment, clientExtensionResults: credential.getClientExtensionResults(), response: { attestationObject: urlEncode(response.attestationObject), clientDataJSON: urlEncode(response.clientDataJSON), transports: response.getTransports() } });
}
export async function approve(change: Change, tenantId: string): Promise<unknown> {
  const { request: fresh } = await rpc<{ request: Change }>('ChangeService', 'GetChange', { tenantId, requestId: change.requestId });
  if (fresh.status !== 'AWAITING_APPROVAL' || fresh.revision !== change.revision || fresh.changeDigest !== change.changeDigest) throw new Error('Request changed since review; refresh and review again');
  await verifyEnvelope(fresh, tenantId);
  const me = await session();
  if (me.principal.tenant_id !== tenantId) throw new Error('Authenticated tenant changed');
  const begin = await request<Options>('/api/passkeys/assert/begin', { change_digest: fresh.changeDigest });
  await verifyChallenge(tenantId, me.principal.actor_id, fresh.changeDigest, begin.challenge_nonce ?? '', begin.options.publicKey.challenge as string);
  const o = begin.options.publicKey;
  const credential = await navigator.credentials.get({ publicKey: { ...o, challenge: decode(o.challenge as string), allowCredentials: descriptors(o.allowCredentials) } as PublicKeyCredentialRequestOptions }) as PublicKeyCredential | null;
  if (!credential) throw new Error('Approval cancelled');
  const response = credential.response as AuthenticatorAssertionResponse;
  const verified = await request<{ submission: unknown }>('/api/passkeys/assert/finish', { session_id: begin.session_id, credential_id: hex(credential.rawId), client_data_json: encode(response.clientDataJSON), authenticator_data: encode(response.authenticatorData), signature: encode(response.signature) });
  return rpc('ChangeService', 'ApproveChange', { tenantId, requestId: change.requestId, assertionResponseJson: JSON.stringify(verified.submission), approvedEnvelopeDigest: change.changeDigest, mutation: mutation(change.revision) });
}

export function revokePasskey(credential: string, ticket: string): Promise<unknown> {
 return request('/api/passkeys/revoke', { credential_id: credential }, { 'X-Ratchet-Credential-Authorization': ticket });
}
