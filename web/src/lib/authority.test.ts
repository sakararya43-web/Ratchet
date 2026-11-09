import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { canonicalize, digest } from './canon.ts';
import { verifyAuthorityPreview, type AuthorityPreview, type AuthorityState } from './authority.ts';

test('Authority action preview refuses altered bytes, actor and operation before a passkey',async()=>{
 const input={command_id:'550e8400-e29b-41d4-a716-446655440000',operation:'bundle_activate',expected_epoch:2,proposal_id:'proposal',proof:{tenant_id:'',actor_id:'',credential_id:null,client_data_json:null,authenticator_data:null,signature:null,challenge_nonce:null}};
 const hash=await digest({Domain:'RATCHET_AUTHORITY_ACTION_V1',Tenant:'tenant',Actor:'alice',Input:input});
 const preview:AuthorityPreview={input,canonical_input_json:Buffer.from(canonicalize(input)).toString('base64'),signing_digest:[...Buffer.from(hash,'hex')]};
 const state:AuthorityState={candidates:{},authority:{}};
 assert.equal(await verifyAuthorityPreview(preview,state,'tenant','alice'),hash);
 await assert.rejects(verifyAuthorityPreview(preview,state,'tenant','bob'));
 await assert.rejects(verifyAuthorityPreview(preview,state,'other','alice'));
 await assert.rejects(verifyAuthorityPreview({...preview,input:{...input,operation:'registry_activate'}},state,'tenant','alice'));
 await assert.rejects(verifyAuthorityPreview({...preview,canonical_input_json:Buffer.from(JSON.stringify(input,null,2)).toString('base64')},state,'tenant','alice'));
});

test('Authority policy signature hashes actual artifact and rejects changed policy or domain',async()=>{
 const body={bundle_version:'1.2.3',data:{required:2},description:'exact reviewed policy',epoch:2,modules:{'main.rego':'package example'},tenant_id:'tenant'};
 const bundle_digest=[...createHash('sha256').update(canonicalize(body)).digest()];
 const signing_digest=[...createHash('sha256').update('RATCHET_POLICY_BUNDLE_V1:tenant:epoch:2:').update(Buffer.from(bundle_digest)).digest()];
 const input={command_id:'550e8400-e29b-41d4-a716-446655440000',operation:'bundle_sign',expected_epoch:2,proposal_id:'p'};
 const preview:AuthorityPreview={input,canonical_input_json:Buffer.from(canonicalize(input)).toString('base64'),signing_digest};
 const proposal={...body,proposal_id:'p',bundle_digest,signatures:[],status:'PROPOSED'};
 const state:AuthorityState={candidates:{},authority:{proposals:{p:proposal}}};
 assert.equal(await verifyAuthorityPreview(preview,state,'tenant','alice'),Buffer.from(signing_digest).toString('hex'));
 await assert.rejects(verifyAuthorityPreview(preview,{...state,authority:{proposals:{p:{...proposal,data:{required:1}}}}},'tenant','alice'));
 await assert.rejects(verifyAuthorityPreview({...preview,signing_digest:bundle_digest},state,'tenant','alice'));
});
