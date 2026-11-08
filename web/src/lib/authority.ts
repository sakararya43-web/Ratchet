import { request, session, decode, encode } from './api.ts';
import { verifyChallenge } from './envelope.ts';

export interface AuthorityMember {
  actor_id: string;
  display_name?: string;
  credential_id: string;
  public_key: string;
  is_active: boolean;
  rp_id?: string;
  origins?: string[];
  enrolled_at?: string;
}

export interface AuthorityCredential {
  credential_id: string;
  public_key: string;
}

export interface GenesisState {
  tenant_id: string;
  threshold_m: number;
  total_n: number;
  epoch: number;
  members: AuthorityMember[];
  genesis_digest: number[] | string;
  initialized_at: string;
}

export interface PolicyProposal {
  proposal_id: string;
  tenant_id: string;
  bundle_version: string;
  description: string;
  epoch: number;
  modules: Record<string, string>;
  data: Record<string, unknown>;
  bundle_digest: number[] | string;
  signatures: { actor_id: string; credential_id?: string; signature?: string }[];
  status: string; // PROPOSED, ACTIVE, SUPERSEDED
  proposed_at: string;
  activated_at?: string;
}

export interface RegistryProposal {
  proposal_id: string;
  tenant_id: string;
  current_epoch: number;
  target_epoch: number;
  proposed_m: number;
  proposed_n: number;
  proposed_members: AuthorityMember[];
  proposal_digest: number[] | string;
  signatures: { actor_id: string; credential_id?: string; signature?: string }[];
  status: string; // PROPOSED, ACTIVATED, SUPERSEDED
  proposed_at: string;
  activated_at?: string;
}

export interface AuthorityState {
  candidates: Record<string, AuthorityMember>;
  authority: {
    genesis: GenesisState | null;
    proposals?: Record<string, PolicyProposal>;
    active_bundle?: PolicyProposal | null;
    history?: PolicyProposal[];
    registry_proposals?: Record<string, RegistryProposal>;
    registry_history?: RegistryProposal[];
    checkpoints?: Record<string, unknown>;
  };
}

export interface AuthorityInput {
  command_id: string;
  operation: string;
  expected_epoch: number;
  proposal_id?: string;
  bundle_version?: string;
  description?: string;
  modules?: Record<string, string>;
  data?: Record<string, unknown>;
  threshold?: number;
  members?: AuthorityMember[];
  member?: AuthorityMember;
  proof?: unknown;
}

export interface AuthorityPreview {
  input: AuthorityInput;
  canonical_input_json: string;
  signing_digest: string | number[];
}

type AssertOptions = {
  session_id: string;
  options: { publicKey: Record<string, unknown> };
  challenge_nonce?: string;
};

export function digestHex(d: unknown): string {
  if (typeof d === 'string') return d;
  if (Array.isArray(d)) {
    return d.map(b => (typeof b === 'number' ? b.toString(16).padStart(2, '0') : '')).join('');
  }
  return '';
}

function hex(raw: ArrayBuffer): string {
  return Array.from(new Uint8Array(raw), b => b.toString(16).padStart(2, '0')).join('');
}

export async function getAuthorityState(): Promise<AuthorityState> {
  return request<AuthorityState>('/api/authority/state');
}

export async function getAuthorityCredentials(): Promise<AuthorityCredential[]> {
  return request<AuthorityCredential[]>('/api/authority/credentials');
}

export async function prepareAuthorityAction(input: AuthorityInput): Promise<AuthorityPreview> {
  return request<AuthorityPreview>('/api/authority/prepare', input);
}

export async function applyAuthorityAction(input: AuthorityInput): Promise<AuthorityState> {
  return request<AuthorityState>('/api/authority/apply', input);
}

export async function signAndApplyAuthority(input: AuthorityInput): Promise<AuthorityState> {
  const me = await session();
  // 1. Prepare to obtain the canonical preview and signing digest
  const preview = await prepareAuthorityAction(input);
  const signingDigestHex = digestHex(preview.signing_digest);

  // 2. Request assertion begin bound to preview's signing digest
  const begin = await request<AssertOptions>('/api/passkeys/assert/begin', {
    change_digest: signingDigestHex,
  });

  // 3. Independently verify challenge before navigator.credentials.get
  const challengeNonce = begin.challenge_nonce ?? '';
  const challengeStr = (begin.options.publicKey.challenge as string) ?? '';
  await verifyChallenge(
    me.principal.tenant_id,
    me.principal.actor_id,
    signingDigestHex,
    challengeNonce,
    challengeStr
  );

  const o = begin.options.publicKey;
  const credential = await navigator.credentials.get({
    publicKey: {
      ...o,
      challenge: decode(challengeStr),
    } as PublicKeyCredentialRequestOptions,
  }) as PublicKeyCredential | null;

  if (!credential) {
    throw new Error('Authority signature cancelled');
  }

  const response = credential.response as AuthenticatorAssertionResponse;
  const verified = await request<{ submission: unknown }>('/api/passkeys/assert/finish', {
    session_id: begin.session_id,
    credential_id: hex(credential.rawId),
    client_data_json: encode(response.clientDataJSON),
    authenticator_data: encode(response.authenticatorData),
    signature: encode(response.signature),
  });

  // 4. Complete input with proof and apply
  input.proof = verified.submission;
  return applyAuthorityAction(input);
}
