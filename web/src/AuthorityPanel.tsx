import { useEffect, useState, type FormEvent } from 'react';
import { assertDigest, request } from './lib/api';
import { verifyAuthorityPreview, type AuthorityInput, type AuthorityPreview, type AuthorityState, type Member } from './lib/authority';

export function AuthorityPanel({tenant,actor}:{tenant:string;actor:string}){
 const[state,setState]=useState<AuthorityState|null>(null),[preview,setPreview]=useState<AuthorityPreview|null>(null),[error,setError]=useState(''),[notice,setNotice]=useState(''),[busy,setBusy]=useState(false);
 const[credentials,setCredentials]=useState<{credential_id:string;public_key:string}[]>([]),[selectedCredential,setSelectedCredential]=useState('');
 async function readState(){try{return await request<AuthorityState>('/api/authority/state');}catch{return request<AuthorityState>('/api/authority/enrollment-state');}}
 async function load(){setState(await readState());const keys=await request<{credential_id:string;public_key:string}[]>('/api/authority/credentials');setCredentials(keys);setSelectedCredential(old=>keys.some(k=>k.credential_id===old)?old:keys[0]?.credential_id??'');}
 async function work(action:()=>Promise<void>){setBusy(true);setError('');setNotice('');try{await action();}catch(e){setError(String(e));}finally{setBusy(false);}}
 useEffect(()=>{void work(load);},[tenant,actor]);
 const epoch=state?.authority.genesis?.epoch??0;
 const currentMember=state?.authority.genesis?.members.some(m=>m.actor_id===actor&&m.is_active)??false;
 async function prepare(value:Partial<AuthorityInput>){
  const input={command_id:crypto.randomUUID(),expected_epoch:epoch,...value} as AuthorityInput;
  const current=await readState();
  const proposed=await request<AuthorityPreview>('/api/authority/prepare',input);
  await verifyAuthorityPreview(proposed,current,tenant,actor);setState(current);setPreview(proposed);
 }
 async function enroll(){
  const key=credentials.find(k=>k.credential_id===selectedCredential);if(!key)throw new Error('Select an operator-authorized enrolled passkey first');
  const member:Member={actor_id:actor,public_key:key.public_key,credential_id:key.credential_id,rp_id:location.hostname,origins:[location.origin],display_name:actor,enrolled_at:'0001-01-01T00:00:00Z',is_active:true};
  await prepare({operation:'enroll',member});
 }
 async function confirm(){
  if(!preview||!state)return;
  const current=await readState();const digest=await verifyAuthorityPreview(preview,current,tenant,actor);
  const member=preview.input.operation==='enroll'?preview.input.member:current.authority.genesis?.members.find(m=>m.actor_id===actor&&m.is_active);
  if(!member)throw new Error('Current Authority member required');
  const proof=await assertDigest(digest,tenant,actor,member.credential_id);
  const result=await request<AuthorityState>('/api/authority/apply',{...preview.input,proof});setState(result);setPreview(null);setNotice('Authority operation committed. Core policy adoption is independently verified.');
 }
 function propose(e:FormEvent<HTMLFormElement>){e.preventDefault();const form=new FormData(e.currentTarget);void work(()=>prepare({operation:'bundle_propose',bundle_version:String(form.get('version')),description:String(form.get('description')),modules:JSON.parse(String(form.get('modules'))) as Record<string,string>,data:JSON.parse(String(form.get('data')))}));}
 function rotate(e:FormEvent<HTMLFormElement>){e.preventDefault();const form=new FormData(e.currentTarget);void work(async()=>{
  const ids=String(form.get('members')).split(',').map(v=>v.trim()).filter(Boolean);const members=ids.map(id=>{const m=state?.candidates[id];if(!m)throw new Error(`Enrolled candidate required: ${id}`);return m;});
  await prepare({operation:'registry_propose',threshold:Number(form.get('threshold')),members});
 });}
 return <section data-testid="authority-panel"><h3>Independent Authority</h3><p>Registry epoch {epoch}; required distinct-member signatures {state?.authority.genesis?.threshold_m??'not established'}. Every change requires an exact-artifact passkey confirmation.</p>
 {error&&<p role="alert">{error}</p>}{notice&&<p role="status">{notice}</p>}<button disabled={busy} onClick={()=>void work(load)}>Refresh Authority</button><label htmlFor="authority-credential">Authority credential</label><select id="authority-credential" value={selectedCredential} onChange={e=>setSelectedCredential(e.target.value)}>{credentials.map(key=><option key={key.credential_id} value={key.credential_id}>{key.credential_id}</option>)}</select><button disabled={busy||!selectedCredential} onClick={()=>void work(enroll)}>Enroll my Authority passkey</button>
 {preview&&<article data-testid="authority-preview"><h4>Confirm {preview.input.operation}</h4><p>Review the complete input below. The browser verified its signing digest; changed context requires a new review.</p><pre>{JSON.stringify(preview.input,null,2)}</pre><button disabled={busy} onClick={()=>void work(confirm)}>Confirm Authority operation with passkey</button><button disabled={busy} onClick={()=>setPreview(null)}>Cancel Authority review</button></article>}
 {epoch>0&&currentMember&&<><form onSubmit={propose}><h4>Propose policy</h4><label>Version<input name="version" required /></label><label>Description<input name="description" required /></label><label>Rego modules as JSON<textarea name="modules" required rows={8}/></label><label>Policy data as JSON<textarea name="data" required rows={4}/></label><button disabled={busy}>Review policy proposal</button></form>
 {Object.values(state?.authority.proposals??{}).map(p=><article key={p.proposal_id} data-testid={`authority-${p.proposal_id}`}><h4>{p.bundle_version}: {p.description}</h4><p>{p.status}; epoch {p.epoch}; independent signatures: {p.signatures?.map(s=>s.actor_id).join(', ')||'none'}</p><pre>{JSON.stringify({modules:p.modules,data:p.data},null,2)}</pre>{p.status==='PROPOSED'&&<><button disabled={busy} onClick={()=>void work(()=>prepare({operation:'bundle_sign',proposal_id:p.proposal_id}))}>Review policy signature</button><button disabled={busy} onClick={()=>void work(()=>prepare({operation:'bundle_activate',proposal_id:p.proposal_id}))}>Review policy activation</button></>}</article>)}
 <form onSubmit={rotate}><h4>Propose membership, credential rotation or threshold</h4><p>Enroll replacement credentials first. List the exact candidate actors to retain; omitted actors lose Authority membership after current-quorum approval.</p><label>Candidate actors, comma separated<input name="members" required/></label><label>New threshold<input name="threshold" type="number" min="1" max="20" required/></label><button disabled={busy}>Review registry proposal</button></form>
 {Object.values(state?.authority.registry_proposals??{}).map(p=><article key={p.proposal_id} data-testid={`authority-registry-${p.proposal_id}`}><h4>Registry {p.current_epoch} to {p.target_epoch}: {p.status}</h4><p>Proposed threshold {p.proposed_m}; members {p.proposed_members.map(m=>m.actor_id).join(', ')}; signatures {p.signatures?.map(s=>s.actor_id).join(', ')||'none'}</p>{p.status==='PROPOSED'&&<><button disabled={busy} onClick={()=>void work(()=>prepare({operation:'registry_sign',proposal_id:p.proposal_id}))}>Review registry signature</button><button disabled={busy} onClick={()=>void work(()=>prepare({operation:'registry_activate',proposal_id:p.proposal_id}))}>Review registry activation</button></>}</article>)}
 <details><summary>Registry history and enrolled candidates</summary><pre>{JSON.stringify({history:state?.authority.registry_history,candidates:state?.candidates},null,2)}</pre></details></>}
 </section>;
}
