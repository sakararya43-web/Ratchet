import { canonicalizeJSON, digest, digestJSON } from './canon.ts';
import { decode } from './api.ts';

export type Member = { actor_id: string; public_key: string; credential_id: string; rp_id: string; origins: string[]; display_name: string; enrolled_at: string; is_active: boolean };
export type AuthorityInput = { command_id: string; operation: string; expected_epoch: number; proposal_id?: string; bundle_version?: string; description?: string; modules?: Record<string,string>; data?: unknown; threshold?: number; members?: Member[]; member?: Member; proof?: unknown };
type Bundle = { proposal_id: string; tenant_id: string; epoch: number; bundle_version: string; description: string; modules: Record<string,string>; data: unknown; bundle_digest: number[]; signatures: { actor_id: string }[]; status: string };
type Rotation = { proposal_id: string; tenant_id: string; current_epoch: number; target_epoch: number; proposed_m: number; proposed_n: number; proposed_members: Member[]; proposal_digest: number[]; signatures: {actor_id:string}[]; status: string };
export type AuthorityState = { candidates: Record<string,Member>; authority: { genesis?: { epoch:number; threshold_m:number; members:Member[]; genesis_digest:number[] }; proposals?: Record<string,Bundle>; registry_proposals?: Record<string,Rotation>; active_bundle?:Bundle; registry_history?:unknown[] } };
export type AuthorityPreview = { input: AuthorityInput; canonical_input_json: string; signing_digest: number[] };
export function digestHex(bytes: number[]): string {
 if (bytes.length!==32 || bytes.some(b=>!Number.isInteger(b)||b<0||b>255)) throw new Error('Invalid Authority digest');
 return bytes.map(b=>b.toString(16).padStart(2,'0')).join('');
}
async function framedDigest(prefix: string, bytes: number[]): Promise<string> {
 digestHex(bytes); const start=new TextEncoder().encode(prefix); const value=new Uint8Array(start.length+32);value.set(start);value.set(bytes,start.length);
 return digestHex([...new Uint8Array(await crypto.subtle.digest('SHA-256',value))]);
}
export async function verifyAuthorityPreview(preview: AuthorityPreview,state:AuthorityState,tenant:string,actor:string):Promise<string>{
 const raw=new TextDecoder('utf-8',{fatal:true}).decode(decode(preview.canonical_input_json));
 if(canonicalizeJSON(raw)!==raw || await digestJSON(raw)!==await digest(preview.input))throw new Error('Authority input changed during review');
 const input=preview.input;let expected:string;
 if(input.operation==='bundle_sign'){
  const p=state.authority.proposals?.[input.proposal_id??''];if(!p||p.tenant_id!==tenant||p.epoch!==input.expected_epoch||p.status!=='PROPOSED')throw new Error('Current policy proposal unavailable');
  const body={bundle_version:p.bundle_version,data:p.data,description:p.description,epoch:p.epoch,modules:p.modules,tenant_id:p.tenant_id};
  if(await digest(body)!==digestHex(p.bundle_digest))throw new Error('Policy artifact digest mismatch');
  expected=await framedDigest(`RATCHET_POLICY_BUNDLE_V1:${tenant}:epoch:${p.epoch}:`,p.bundle_digest);
 }else if(input.operation==='registry_sign'){
  const p=state.authority.registry_proposals?.[input.proposal_id??''];if(!p||p.tenant_id!==tenant||p.current_epoch!==input.expected_epoch||p.status!=='PROPOSED')throw new Error('Current registry proposal unavailable');
  const body={tenant_id:p.tenant_id,current_epoch:p.current_epoch,target_epoch:p.target_epoch,proposed_m:p.proposed_m,proposed_n:p.proposed_n,proposed_members:p.proposed_members};
  if(await digest(body)!==digestHex(p.proposal_digest))throw new Error('Registry artifact digest mismatch');
  expected=await framedDigest(`RATCHET_REGISTRY_V1:${tenant}:epochs:${p.current_epoch}->${p.target_epoch}:`,p.proposal_digest);
 }else{
  expected=await digest({Domain:'RATCHET_AUTHORITY_ACTION_V1',Tenant:tenant,Actor:actor,Input:preview.input});
 }
 if(expected!==digestHex(preview.signing_digest))throw new Error('Authority operation digest mismatch; no passkey requested');
 return expected;
}
