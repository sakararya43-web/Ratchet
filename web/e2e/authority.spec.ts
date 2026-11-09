import { test,expect,type Page,type BrowserContext,type CDPSession } from '@playwright/test';
import { readFileSync,writeFileSync,existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import type { AuthorityState } from '../src/lib/authority';

const local=resolve('..','.local/completion-a');
const accounts=JSON.parse(readFileSync(resolve(local,'users.json'),'utf8')) as {tenant_id:string;users:{actor_id:string;password:string;enrollment_ticket:string}[]};
const initial=JSON.parse(readFileSync(resolve(local,'initial-policy.json'),'utf8')) as {version:string;description:string;modules:Record<string,string>;data:unknown};
const python=process.env.RATCHET_PYTHON!;

async function panel(page:Page){await page.getByRole('navigation').getByRole('button',{name:'Security policy',exact:true}).click();await expect(page.getByTestId('authority-panel')).toBeVisible();await page.getByRole('button',{name:'Refresh Authority',exact:true}).click();await expect(page.getByRole('button',{name:'Enroll my Authority passkey',exact:true})).toBeEnabled();}
async function current(page:Page):Promise<AuthorityState>{return page.evaluate(async()=>{const response=await fetch('/api/authority/state');if(!response.ok)throw new Error('Current Authority state unavailable');return response.json();});}
async function confirm(page:Page,success=true){
 await expect(page.getByTestId('authority-preview')).toBeVisible();const response=page.waitForResponse(r=>r.url().endsWith('/api/authority/apply'));
 await page.getByRole('button',{name:'Confirm Authority operation with passkey',exact:true}).click();const result=await response;
 expect(result.status()).toBe(success?200:409);if(success)await expect(page.getByTestId('authority-preview')).toHaveCount(0);else await page.getByRole('button',{name:'Cancel Authority review'}).click();
}
async function proposal(page:Page,version:string){
 await panel(page);const existing=new Set(Object.keys((await current(page)).authority.proposals??{}));await page.getByLabel('Version',{exact:true}).fill(version);await page.getByLabel('Description',{exact:true}).fill('Native browser governance '+version);
 await page.getByLabel('Rego modules as JSON').fill(JSON.stringify(initial.modules));await page.getByLabel('Policy data as JSON').fill(JSON.stringify(initial.data));
 await page.getByRole('button',{name:'Review policy proposal',exact:true}).click();await confirm(page);
 const state=await current(page);return Object.values(state.authority.proposals??{}).find(p=>p.bundle_version===version&&!existing.has(p.proposal_id))!.proposal_id;
}
async function policyAction(page:Page,id:string,action:'signature'|'activation',success=true){await panel(page);await page.getByTestId(`authority-${id}`).getByRole('button',{name:`Review policy ${action}`,exact:true}).click();await confirm(page,success);}
async function registryProposal(page:Page,actors:string[],threshold:number){
 await panel(page);await page.getByLabel('Candidate actors, comma separated').fill(actors.join(','));await page.getByLabel('New threshold').fill(String(threshold));
 await page.getByRole('button',{name:'Review registry proposal',exact:true}).click();await confirm(page);
 const state=await current(page);return Object.values(state.authority.registry_proposals??{}).find(p=>p.status==='PROPOSED')!.proposal_id;
}
async function registryAction(page:Page,id:string,action:'signature'|'activation',success=true){await panel(page);await page.getByTestId(`authority-registry-${id}`).getByRole('button',{name:`Review registry ${action}`,exact:true}).click();await confirm(page,success);}
async function ready(page:Page){await expect.poll(async()=>{try{return(await page.request.get('/readyz',{timeout:10_000})).status();}catch{return 0;}},{timeout:60_000,intervals:[1000]}).toBe(200);}
async function adopted(page:Page,version:string){await expect.poll(async()=>page.evaluate(async tenant=>{try{const session=await(await fetch('/api/auth/session')).json();const response=await fetch('/api/ratchet.v1.ChangeService/ListPolicyHistory',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':session.csrf_token},body:JSON.stringify({tenantId:tenant,pageSize:100})});if(!response.ok)return '';const data=await response.json();return data.activations?.at(-1)?.bundleVersion??'';}catch{return '';}},accounts.tenant_id),{timeout:45_000,intervals:[1000]}).toBe(version);await ready(page);}

test('live Authority: native genesis, quorum policy, membership, threshold and credential rotation',async({browser})=>{
 test.setTimeout(600_000);
 const contexts:BrowserContext[]=[];const pages=new Map<string,Page>();const authenticators=new Map<string,{cdp:CDPSession;id:string}>();const errors:string[]=[];
 const evidence:Record<string,unknown>={authenticator:'Chromium native WebAuthn with virtual CTAP2 devices; not physical hardware acceptance'};
 const retainedPath=resolve(local,'virtual-authenticators.json');const retained=existsSync(retainedPath)?JSON.parse(readFileSync(retainedPath,'utf8')) as Record<string,Parameters<CDPSession['send']>[1][]>:{};
 try{
  for(const user of accounts.users){
   const context=await browser.newContext({baseURL:'https://localhost:8444'});contexts.push(context);const page=await context.newPage();pages.set(user.actor_id,page);page.on('pageerror',e=>errors.push(e.message));
   const cdp=await context.newCDPSession(page);await cdp.send('WebAuthn.enable');const{id}=await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}}).then(r=>({id:r.authenticatorId}));authenticators.set(user.actor_id,{cdp,id});
   for(const credential of retained[user.actor_id]??[])await cdp.send('WebAuthn.addCredential',{authenticatorId:id,credential:credential as never});
   await page.goto('/#/console');await page.getByLabel('Tenant',{exact:true}).fill(accounts.tenant_id);await page.getByLabel('Actor',{exact:true}).fill(user.actor_id);await page.getByLabel('Password',{exact:true}).fill(user.password);await page.getByRole('button',{name:'Sign in',exact:true}).click();await expect(page.getByTestId('signed-in-actor')).toContainText(user.actor_id);
   if(!(retained[user.actor_id]?.length)){await page.getByRole('navigation').getByRole('button',{name:'Passkeys',exact:true}).click();await page.getByLabel('Label',{exact:true}).fill('Completion A native acceptance');await page.getByLabel('Enrollment ticket',{exact:true}).fill(user.enrollment_ticket);await page.getByRole('button',{name:'Register with your authenticator'}).click();await expect(page.getByText('Passkey registered for this signed-in account.',{exact:true})).toBeVisible();}
  }
  const first=pages.get('user:sec-lead-1')!,second=pages.get('user:sec-lead-2')!,candidate=pages.get('user:finance-lead')!;
  for(const page of [first,second]){await panel(page);const state=await current(page);if(!state.authority.genesis){await page.getByRole('button',{name:'Enroll my Authority passkey'}).click();await confirm(page);}}
  const genesis=(await current(first)).authority.genesis!;expect(genesis.epoch).toBe(1);expect(genesis.members).toHaveLength(2);expect(genesis.members.every(m=>!!m.credential_id)).toBe(true);evidence.genesis_digest=genesis.genesis_digest;
  const initialPolicy=await proposal(first,'1.0.0');await policyAction(first,initialPolicy,'signature');await policyAction(first,initialPolicy,'signature',false);await policyAction(first,initialPolicy,'activation',false);expect((await current(first)).authority.active_bundle).toBeNull();
  await policyAction(second,initialPolicy,'signature');await policyAction(first,initialPolicy,'activation');
  const noTargetAPI=await first.evaluate(async()=>{const s=await(await fetch('/api/auth/session')).json();return(await fetch('/api/ratchet.v1.ChangeService/SubmitChange',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':s.csrf_token},body:'{}'})).status;});expect(noTargetAPI).toBe(404);
  execFileSync(python,[resolve('..','scripts/completion-a.py'),'start','--no-build'],{cwd:resolve('..'),stdio:'pipe',timeout:180_000});
  await adopted(first,'1.0.0');for(const page of pages.values())await page.reload();evidence.root_pinned_after_actual_quorum=true;
  // A candidate proves possession of its own enrolled credential; this does not
  // grant a vote or expose member-only policy state.
  await panel(candidate);await candidate.getByRole('button',{name:'Enroll my Authority passkey'}).click();await confirm(candidate);expect(await candidate.getByRole('button',{name:'Review policy proposal',exact:true}).count()).toBe(0);
  const membership=await registryProposal(first,['user:sec-lead-1','user:finance-lead'],2);await registryAction(first,membership,'signature');await registryAction(second,membership,'signature');await registryAction(first,membership,'activation');
  await panel(second);expect(await second.getByRole('button',{name:'Review policy proposal',exact:true}).count()).toBe(0);evidence.removed_member_refused=true;
  const policy2=await proposal(first,'1.1.0');await policyAction(first,policy2,'signature');await policyAction(candidate,policy2,'signature');await policyAction(first,policy2,'activation');await adopted(first,'1.1.0');
  const threshold=await registryProposal(first,['user:sec-lead-1','user:finance-lead'],1);await registryAction(first,threshold,'signature');await registryAction(first,threshold,'activation',false);await registryAction(candidate,threshold,'signature');await registryAction(first,threshold,'activation');evidence.threshold_change_requires_old_quorum=true;
  const policy3=await proposal(first,'1.2.0');await policyAction(first,policy3,'signature');await policyAction(first,policy3,'activation');await adopted(first,'1.2.0');
  // Rotate a real enrolled credential through the current quorum. The old key
  // remains usable only until that exact registry transition is activated.
  const original=(await current(first)).authority.genesis!.members.find(m=>m.actor_id==='user:sec-lead-1')!.credential_id;
  execFileSync(python,[resolve('..','scripts/prototype.py'),'invite','--actor','user:sec-lead-1'],{cwd:resolve('..'),env:{...process.env,RATCHET_LOCAL_PROFILE:'completion-a'},stdio:'pipe',timeout:30_000});
  const ticket=JSON.parse(readFileSync(resolve(local,'credential-authorization.json'),'utf8')).ticket;
  await first.getByRole('navigation').getByRole('button',{name:'Passkeys',exact:true}).click();await first.getByLabel('Label',{exact:true}).fill('Rotated native Authority key');await first.getByLabel('Enrollment ticket',{exact:true}).fill(ticket);await first.getByRole('button',{name:'Register with your authenticator'}).click();await expect(first.getByText('Passkey registered for this signed-in account.',{exact:true})).toBeVisible();
  await panel(first);const credentialOptions=first.getByLabel('Authority credential',{exact:true}).locator('option');await expect(credentialOptions).toHaveCount(2);const choices=await credentialOptions.evaluateAll(options=>options.map(o=>(o as HTMLOptionElement).value));const replacement=choices.find(id=>id!==original)!;expect(replacement).toBeTruthy();await first.getByLabel('Authority credential',{exact:true}).selectOption(replacement);await first.getByRole('button',{name:'Enroll my Authority passkey'}).click();await confirm(first);
  const rotation=await registryProposal(first,['user:sec-lead-1','user:finance-lead'],1);await registryAction(first,rotation,'signature');await registryAction(first,rotation,'activation');
  const finalPolicy=await proposal(first,'1.3.0');await policyAction(first,finalPolicy,'signature');await policyAction(first,finalPolicy,'activation');await adopted(first,'1.3.0');
  const final=await current(first);expect(final.authority.genesis!.epoch).toBe(4);expect(final.authority.genesis!.genesis_digest).toEqual(genesis.genesis_digest);expect(final.authority.genesis!.members.find(m=>m.actor_id==='user:sec-lead-1')!.credential_id).toBe(replacement);evidence.credential_rotation_verified=true;
  // Retain virtual private keys only in the ignored, private acceptance directory
  // so a failed later test never destroys this lab's Authority recovery material.
  const devices:Record<string,unknown>={};for(const[actor,{cdp,id}]of authenticators){devices[actor]=(await cdp.send('WebAuthn.getCredentials',{authenticatorId:id})).credentials;}
  writeFileSync(resolve(local,'virtual-authenticators.json'),JSON.stringify(devices,null,2),{mode:0o600});
  evidence.final_epoch=4;evidence.final_policy='1.3.0';evidence.browser_runtime_errors=errors;expect(errors).toEqual([]);evidence.completed_at=new Date().toISOString();writeFileSync(resolve(local,'authority-browser-evidence.json'),JSON.stringify(evidence,null,2));
 }finally{
  const retained:Record<string,unknown>={};for(const[actor,{cdp,id}]of authenticators){try{retained[actor]=(await cdp.send('WebAuthn.getCredentials',{authenticatorId:id})).credentials;}catch{/* A closed test page has no live authenticator to export. */}}
  if(Object.keys(retained).length)writeFileSync(resolve(local,'virtual-authenticators.json'),JSON.stringify(retained,null,2),{mode:0o600});
  for(const context of contexts)await context.close();
 }
});
