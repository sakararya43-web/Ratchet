import { request, session, decode, encode } from './api.ts';

export interface AuthorityMember {
  actor_id: string;
  credential_id: string;
  public_key: string;
  is_active: boolean;
}

export interface AuthorityCredential {
  credential_id: string;
  public_key: string;
}

export interface AuthorityState {
  candidates: Record<string, AuthorityMember>;
  authority: {
    epoch: number;
    threshold_m: number;
    threshold_n: number;
    members: AuthorityMember[];
    policy_proposals?: Record<string, {
      proposal_id: string;
      status: string;
      bundle_digest: string;
      bundle_version: string;
      description: string;
      signatures: { actor_id: string }[];
    }>;
    registry_proposals?: Record<string, {
      proposal_id: string;
      status: string;
      proposal_digest: string;
      proposed_m: number;
      proposed_n: number;
      proposed_members: AuthorityMember[];
      signatures: { actor_id: string }[];
    }>;
  };
}

export interface AuthorityInput {
  command_id: string;
  operation: string;
  expected_epoch: number;
  proposal_id?: string;
  bundle_version?: string;
  description?: string;
  threshold?: number;
  members?: AuthorityMember[];
  member?: AuthorityMember;
  proof?: unknown;
}

export interface AuthorityPreview {
  input: AuthorityInput;
  canonical_input_json: string;
  signing_digest: string;
}

type AssertOptions = {
  session_id: string;
  options: { publicKey: PublicKeyCredentialRequestOptions };
  challenge_nonce?: string;
};

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
  await session();
  // 1. Prepare to obtain the canonical preview and signing digest
  const preview = await prepareAuthorityAction(input);

  // 2. Request assertion begin bound to preview's signing digest
  const begin = await request<AssertOptions>('/api/passkeys/assert/begin', {
    change_digest: preview.signing_digest,
  });

  const o = begin.options.publicKey as unknown as Record<string, unknown>;
  const credential = await navigator.credentials.get({
    publicKey: {
      ...o,
      challenge: decode(o.challenge as string),
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

  // 3. Complete input with proof and apply
  input.proof = verified.submission;
  return applyAuthorityAction(input);
}
