// Native Chromium WebAuthn presenter. Keys and cookies stay in ignored .local/.
// This is an explicit virtual-authenticator demo, not hardware-key acceptance.
import { chromium, expect as baseExpect } from '../web/node_modules/@playwright/test/index.mjs';
import { readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync, unlinkSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { execFileSync, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { adversarialApproval } from '../web/e2e/prototype.helpers.ts';

const expect = baseExpect.configure({timeout:30000});

const root = resolve(import.meta.dirname, '..');
const local = resolve(root, '.local/demo-ready');
const profile = resolve(root, '.local/prototype');
const stateFile = resolve(local, 'presenter-private.json');
const presenterLease = resolve(local, 'presenter-running.json');
const action = process.argv[2] ?? 'prepare';
const headed = process.argv.includes('--headed');
const origin = 'https://localhost:8444';
const accounts = JSON.parse(readFileSync(resolve(profile, 'users.json'), 'utf8'));
const tenant = accounts.tenant_id;
const roles = [
  ['user:rahul-assistant', 'Requester'], ['user:finance-lead', 'Finance owner'],
  ['user:sec-lead-1', 'Security lead 1'], ['user:sec-lead-2', 'Security lead 2'],
];
const saved = existsSync(stateFile) ? JSON.parse(readFileSync(stateFile, 'utf8')) : {};
const errors = [];
const contexts = new Map();
const pages = new Map();
const devices = new Map();
let browser;
let closing = false;
let loginWindowReady = false;
let recorder;
let activePage;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function privateWrite(path, value) {
  writeFileSync(path, JSON.stringify(value, null, 2) + '\n', {mode:0o600});
  chmodSync(path, 0o600);
}
function ticket(actor) {
  execFileSync(process.env.RATCHET_PYTHON ?? 'python', ['scripts/prototype.py', 'invite', '--actor', actor], {cwd:root, stdio:'pipe'});
  return JSON.parse(readFileSync(resolve(profile, 'credential-authorization.json'), 'utf8')).ticket;
}
async function save() {
  for (const [actor, device] of devices) {
    if (device.page.isClosed()) continue;
    saved[actor] = {credentials:(await device.cdp.send('WebAuthn.getCredentials', {authenticatorId:device.id})).credentials,
      storage:await contexts.get(actor).storageState()};
  }
  privateWrite(stateFile, saved);
}
async function pauseForLoginWindow() {
  const stamp = resolve(local, 'presenter-login-window.json');
  let latest = existsSync(stamp) ? JSON.parse(readFileSync(stamp, 'utf8')).started_at : 0;
  const report = resolve(profile, 'browser-results.json');
  if (existsSync(report)) latest = Math.max(latest, Date.parse(JSON.parse(readFileSync(report, 'utf8')).stats?.startTime ?? '') || 0);
  const delay = Math.max(0, 66000 - (Date.now() - latest));
  if (delay) {
    console.log(`Respecting the login rate window (${Math.ceil(delay / 1000)} seconds).`);
    await new Promise(r => setTimeout(r, delay));
  }
  privateWrite(stamp, {started_at:Date.now()});
}
async function setup() {
  mkdirSync(local, {recursive:true});
  browser = await chromium.launch({headless:!headed});
  for (const [actor, label] of roles) {
    const context = await browser.newContext({baseURL:origin, viewport:{width:1440,height:1000},
      ...(saved[actor]?.storage ? {storageState:saved[actor].storage} : {})});
    contexts.set(actor, context);
    const page = await context.newPage(); pages.set(actor, page);
    page.on('pageerror', error => errors.push(`${label}: ${error.message}`));
    const cdp = await context.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    const {authenticatorId} = await cdp.send('WebAuthn.addVirtualAuthenticator', {options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
    devices.set(actor, {page,cdp,id:authenticatorId});
    for (const credential of saved[actor]?.credentials ?? []) await cdp.send('WebAuthn.addCredential', {authenticatorId,credential});
    const resumed = await context.request.get(origin + '/api/auth/session');
    if (resumed.ok() && (await resumed.json()).principal.actor_id !== actor) throw new Error('Presenter session actor mismatch');
    await page.goto(`${origin}/#/console`);
    if (!resumed.ok()) {
      if (!loginWindowReady) { await pauseForLoginWindow(); loginWindowReady = true; }
      const user = accounts.users.find(u => u.actor_id === actor);
      await page.getByLabel('Tenant',{exact:true}).fill(tenant);
      await page.getByLabel('Actor',{exact:true}).fill(actor);
      await page.getByLabel('Password',{exact:true}).fill(user.password);
      await page.getByRole('button',{name:'Sign in',exact:true}).click();
    }
    await expect(page.getByTestId('signed-in-actor')).toContainText(actor);
    if (!saved[actor]?.credentials?.length) {
      await page.getByRole('navigation').getByRole('button',{name:'Passkeys',exact:true}).click();
      await expect(page.getByRole('button',{name:'Register with your authenticator'})).toBeEnabled();
      await page.getByLabel('Label',{exact:true}).fill(`Prepared demo: ${label}`);
      await page.getByLabel('Enrollment ticket',{exact:true}).fill(ticket(actor));
      await page.getByRole('button',{name:'Register with your authenticator'}).click();
      await expect(page.getByText('Passkey registered for this signed-in account.',{exact:true})).toBeVisible();
    }
    await page.getByRole('navigation').getByRole('button',{name:'Changes',exact:true}).click();
    await expect(page.getByRole('button',{name:'Submit for assessment'})).toBeEnabled();
    await page.evaluate(label => {document.title = `${label} · RATCHET`;}, label);
    await save();
    // Persist signature counters after each real native assertion, including
    // manual presenter clicks, so reopening cannot roll a counter backwards.
    cdp.on('WebAuthn.credentialAsserted', () => { void save().catch(() => {}); });
    console.log(`${label}: authenticated, native passkey ready.`);
  }
}
async function close() {
  if (closing) return; closing = true;
  try {if (recorder) {const current=recorder;recorder=null;await current.stop();}}
  finally {
    if (browser?.isConnected()) {try {await save();} finally {await browser.close();}}
    if(existsSync(presenterLease)&&JSON.parse(readFileSync(presenterLease,'utf8')).pid===process.pid)unlinkSync(presenterLease);
  }
}

async function call(page, service, method, body) {
  return page.evaluate(async ({service,method,body,tenant}) => {
    const session = await (await fetch('/api/auth/session')).json();
    const response = await fetch(`/api/ratchet.v1.${service}/${method}`, {method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':session.csrf_token},body:JSON.stringify({tenantId:tenant,...body})});
    return {status:response.status,body:await response.json()};
  }, {service,method,body,tenant});
}
async function nav(page, tab) {
  const paths = {Changes:'.ChangeService/ListChanges',Overview:'.OverviewService/GetAttentionItems',Audit:'.AuditService/QueryAuditEvents'};
  const button = page.getByRole('navigation').getByRole('button',{name:tab,exact:true});
  await expect(button).toBeEnabled();
  const response = paths[tab] ? page.waitForResponse(r=>r.url().endsWith(paths[tab])) : null;
  if (await button.getAttribute('aria-current')==='page') await page.getByRole('button',{name:'Refresh',exact:true}).click();
  else await button.click();
  if(response)await response;
  await expect(page.getByRole('button',{name:'Refresh',exact:true})).toBeEnabled();
}
async function focus(page,id) {
  await nav(page,'Changes');
  await page.getByLabel('Filter this page by request, identity or role').fill(id);
  await expect(page.getByTestId(`change-${id}`)).toBeVisible();
}
async function submit(page,role,kind='ROLE_ASSIGN') {
  await nav(page,'Changes');
  await page.getByLabel('Filter this page by request, identity or role').fill('');
  await page.getByRole('combobox',{name:'Kind',exact:true}).selectOption(kind);
  await page.getByLabel('Identity',{exact:true}).fill('user:rahul-assistant');
  await page.getByLabel('Access',{exact:true}).fill(role);
  await page.getByLabel('Justification',{exact:true}).fill(kind==='ROLE_REVOKE'?'End the approved demonstration access window.':'Reviewed access for daily exchange reconciliation.');
  const waiting=page.waitForResponse(r=>r.url().endsWith('.ChangeService/SubmitChange'));
  await page.getByRole('button',{name:'Submit for assessment'}).click();
  const response=await waiting;expect(response.status()).toBe(200);
  const change=(await response.json()).request;
  await focus(page,change.requestId);
  return change.requestId;
}
async function state(page,id,wanted) {
  await focus(page,id);
  await expect(page.getByTestId(`change-${id}`).getByTestId('change-status')).toHaveText(wanted);
}
async function review(page,id) {
  await focus(page,id);
  await page.getByTestId(`change-${id}`).getByRole('button',{name:'Review exact change'}).click();
  await expect(page.getByTestId('verified-envelope-digest')).toHaveText(/^[a-f0-9]{64}$/);
  await expect(page.getByRole('button',{name:'Approve reviewed change with passkey'})).toBeEnabled();
  await page.getByTestId('approval-review').scrollIntoViewIfNeeded();
}
async function approveReviewed(page,success=true) {
  const waiting=page.waitForResponse(r=>r.url().endsWith('.ChangeService/ApproveChange'));
  await page.getByRole('button',{name:'Approve reviewed change with passkey'}).click();
  const response=await waiting;
  if(success)expect(response.status()).toBe(200);else expect(response.status()).not.toBe(200);
  await save();
  return {status:response.status(),body:await response.json()};
}
async function probe(page,path) {
  const response=await page.request.post(`http://127.0.0.1:58085/api/v1/business/${path}`,{data:{session_id:'session:intern-workstation-1',amount_usd:100},timeout:10000});
  return response.status();
}
async function observed(role,present) {
  const lead=pages.get('user:sec-lead-1');
  await expect.poll(async()=>lead.evaluate(async role=>{
    const graph=await(await fetch('/api/console/bootstrap')).json();
    return graph.edges.some(e=>e.source==='user:rahul-assistant'&&e.target===role&&e.kind==='ASSIGNED');
  },role),{intervals:[500],timeout:30000}).toBe(present);
}
async function revoke(role) {
  const requester=pages.get('user:rahul-assistant');
  const reviewer=pages.get(role==='role:wallet-operator'?'user:sec-lead-1':'user:finance-lead');
  const id=await submit(requester,role,'ROLE_REVOKE');
  await state(requester,id,'AWAITING_APPROVAL');
  await review(reviewer,id);await approveReviewed(reviewer);
  await state(requester,id,'EXECUTED');await observed(role,false);
  return id;
}
async function verifyLedger(page) {
  let pageToken='',previous='00'.repeat(32),count=0,endHash='';
  do {
    const response=await call(page,'AuditService','ExportHashChain',{pageSize:100,pageToken});
    expect(response.status).toBe(200);
    for(const event of response.body.chain){
      expect(event.previousEventHash).toBe(previous);
      const hash=createHash('sha256').update(Buffer.from(previous,'hex')).update(Buffer.from(event.canonicalContent,'base64')).digest('hex');
      expect(event.eventHash).toBe(hash);previous=hash;count++;
    }
    pageToken=response.body.nextPageToken??'';endHash=response.body.snapshotEndHash;
  }while(pageToken);
  expect(previous).toBe(endHash);return {events:count,end_hash:endHash};
}
async function startRecording(path) {
  const cache=resolve(process.env.LOCALAPPDATA,'ms-playwright');
  const tools=readdirSync(cache).filter(n=>/^ffmpeg-\d+$/.test(n)).sort((a,b)=>Number(b.split('-')[1])-Number(a.split('-')[1]));
  const executable=tools.map(n=>resolve(cache,n,'ffmpeg-win64.exe')).find(existsSync);
  if(!executable)throw new Error('The installed Playwright video encoder is unavailable');
  const encoder=spawn(executable,['-hide_banner','-loglevel','warning','-f','image2pipe','-vcodec','mjpeg','-framerate','2','-i','pipe:0','-an','-c:v','libvpx-vp9','-b:v','900k','-deadline','realtime','-cpu-used','8','-pix_fmt','yuv420p','-y',path],{stdio:['pipe','ignore','pipe']});
  let encoderLog='',stopping=false,frames=0,captureError;
  encoder.stderr.on('data',chunk=>{encoderLog=(encoderLog+chunk).slice(-20000);});
  encoder.stdin.on('error',error=>{captureError=error;stopping=true;});
  const finished=once(encoder,'exit');
  const loop=(async()=>{
    while(!stopping){
      const tick=Date.now();
      try{
        const frame=await activePage.screenshot({type:'jpeg',quality:90,animations:'disabled',timeout:10000});
        if(!encoder.stdin.write(frame))await once(encoder.stdin,'drain');
        frames++;
      }catch(error){captureError=error;break;}
      await sleep(Math.max(0,500-(Date.now()-tick)));
    }
    encoder.stdin.end();
  })();
  return {async stop(){stopping=true;await loop;const [code]=await finished;writeFileSync(resolve(local,'recording-encoder.log'),encoderLog);if(code!==0||captureError)throw new Error(`Recording encoder/capture failed (${code})`);return {frames,fps:2,duration_seconds:frames/2};}};
}
async function runStory() {
  const requester=pages.get('user:rahul-assistant'),owner=pages.get('user:finance-lead'),lead1=pages.get('user:sec-lead-1'),lead2=pages.get('user:sec-lead-2');
  const proof={started_at:new Date().toISOString(),authenticator:'Native Chromium WebAuthn; virtual CTAP2 devices; not a physical hardware-key claim',scenes:[],preflight_cleanup_requests:[]};
  const core=execFileSync('docker',['compose','--env-file',resolve(profile,'prototype.env'),'-f','deploy/prototype.compose.yaml','ps','-q','core'],{cwd:root,encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim();
  proof.runtime_image_id=execFileSync('docker',['inspect','--format','{{.Image}}',core],{cwd:root,encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim();
  proof.embedded_manifest_sha256=createHash('sha256').update(readFileSync(resolve(root,'internal/webassets/assets/manifest.json'))).digest('hex');
  const snapshots=resolve(local,'screenshots');mkdirSync(snapshots,{recursive:true});
  // Recover only through actual independently reviewed revocations. Never clear
  // the target, reset trust or delete ledger history after an interrupted demo.
  const initial=await(await requester.request.get('http://127.0.0.1:58085/api/v1/org')).json();
  for(const role of ['role:wallet-operator','role:finance-analyst']){
    if(initial.grants.some(g=>g.identity_id==='user:rahul-assistant'&&g.role_id===role))proof.preflight_cleanup_requests.push(await revoke(role));
  }
  async function scene(page,key,title,detail,seconds){
    activePage=page;if(headed)await page.bringToFront();
    await page.evaluate(({title,detail})=>{
      let caption=document.getElementById('ratchet-demo-caption');
      if(!caption){caption=document.createElement('aside');caption.id='ratchet-demo-caption';document.body.append(caption);document.body.style.paddingBottom='120px';}
      caption.style.cssText='position:fixed;bottom:0;left:0;right:0;z-index:2147483647;background:#081324f2;border-top:2px solid #60a5fa;padding:17px 40px;color:#e2e8f0;font:16px/1.5 Segoe UI,sans-serif;pointer-events:none;box-shadow:0 -8px 30px #0005';
      caption.replaceChildren();const heading=document.createElement('strong');heading.style.cssText='display:block;color:#93c5fd;font-size:18px;margin-bottom:4px';heading.textContent=title;const text=document.createElement('div');text.textContent=detail;caption.append(heading,text);
    },{title,detail});
    // Keep the relevant real control/event above the recording caption.
    const reviewButton=page.getByRole('button',{name:'Approve reviewed change with passkey'});
    const executionCell=page.getByRole('cell',{name:'ChangeExecuted',exact:true});
    const anchor=await reviewButton.count()?reviewButton:(await executionCell.count()===1?executionCell:null);
    if(anchor)await anchor.evaluate(element=>{const bottom=element.getBoundingClientRect().bottom;const safeBottom=innerHeight-130;if(bottom>safeBottom)scrollBy(0,bottom-safeBottom);});
    if(action==='record'&&!recorder)recorder=await startRecording(resolve(local,'ratchet-demo.webm'));
    await page.screenshot({path:resolve(snapshots,key+'.png')});
    proof.scenes.push({key,title,detail,at:new Date().toISOString()});console.log(title);
    await sleep(action==='record'?seconds*1000:250);
  }
  await nav(requester,'Overview');
  await requester.evaluate(()=>scrollTo(0,0));
  await scene(requester,'01-overview','RATCHET | Review what access makes possible','Four isolated logins use native WebAuthn with virtual CTAP2 devices and real backend verification. This is a local simulator demo.',20);
  proof.initial_finance_status=await probe(requester,'finance-report/read');proof.initial_wallet_status=await probe(requester,'wallet/sign');
  expect(proof.initial_finance_status).toBe(403);expect(proof.initial_wallet_status).toBe(403);
  await scene(requester,'02-initial-access','1 | Start with denied access','Actual target probes: finance report HTTP 403; wallet signing HTTP 403. No demonstration access is currently granted.',15);
  const ordinary=await submit(requester,'role:finance-analyst');proof.ordinary_request=ordinary;
  await state(requester,ordinary,'AWAITING_APPROVAL');
  await scene(requester,'03-request','2 | Request ordinary finance access','The employee submits a role change. The core assesses consequences and requires an independent resource owner.',20);
  const selfReviewButton=requester.getByTestId(`change-${ordinary}`).getByRole('button',{name:'Review exact change'});
  await expect(selfReviewButton).toBeDisabled();await selfReviewButton.scrollIntoViewIfNeeded();
  const selfReview=await requester.request.get(`${origin}/api/console/approval-review?request_id=${encodeURIComponent(ordinary)}`);
  proof.self_review_status=selfReview.status();expect(proof.self_review_status).toBe(403);
  const ordinaryContext=await call(lead1,'ChangeService','GetChange',{requestId:ordinary});expect(ordinaryContext.status).toBe(200);
  const self=await adversarialApproval(requester,tenant,ordinaryContext.body.request);expect(self.status).toBe(403);proof.self_approval_status=self.status;
  await scene(requester,'04-self-refused','3 | A valid session cannot approve its own escalation','Both the requester review and an actual requester passkey approval are refused with HTTP 403. Authentication alone cannot grant more power.',15);
  await review(owner,ordinary);
  await scene(owner,'05-owner-review','4 | The finance owner reviews the exact consequence','New resources, changed powers and the canonical digest are visible before the independent owner signs. This change requires one eligible owner.',25);
  await approveReviewed(owner);await state(requester,ordinary,'EXECUTED');await observed('role:finance-analyst',true);
  proof.finance_after_owner_status=await probe(requester,'finance-report/read');expect(proof.finance_after_owner_status).toBe(200);
  await scene(requester,'06-finance-verified','5 | Approved, executed and independently verified','The request is EXECUTED only after target read-back. An actual finance-report probe now returns HTTP 200.',20);
  const sensitive=await submit(requester,'role:wallet-operator');proof.sensitive_request=sensitive;
  await state(requester,sensitive,'AWAITING_APPROVAL');await review(lead1,sensitive);
  await scene(lead1,'07-critical-review','6 | Critical access requires a stronger quorum','The impact exposes a tier-0 wallet signing path. Two distinct eligible security leads must independently approve the exact change.',25);
  const first=await approveReviewed(lead1);expect(first.body.request.requiredQuorum).toBe(2);expect(first.body.request.status).toBe('AWAITING_APPROVAL');
  proof.wallet_after_one_approval_status=await probe(requester,'wallet/sign');expect(proof.wallet_after_one_approval_status).toBe(403);
  await review(lead1,sensitive);
  await scene(lead1,'08-one-is-insufficient','7 | One approval is insufficient','Recorded approvals: 1 of 2. The actual wallet signing probe still returns HTTP 403; no critical access has been granted.',30);
  const duplicate=await approveReviewed(lead1,false);proof.duplicate_approval_status=duplicate.status;
  await expect(lead1.getByRole('alert')).toBeVisible();
  expect(await probe(requester,'wallet/sign')).toBe(403);
  await scene(lead1,'09-duplicate-refused','8 | The same reviewer cannot count twice',`A second real passkey approval from security lead 1 is rejected (HTTP ${duplicate.status}). Distinct people are required.`,15);
  await review(lead2,sensitive);
  await scene(lead2,'10-second-review','9 | A second independent security lead reviews','Security lead 2 sees the same bound operation and the existing approval before signing with their own native passkey.',20);
  await approveReviewed(lead2);await state(requester,sensitive,'EXECUTED');await observed('role:wallet-operator',true);
  proof.wallet_after_two_approvals_status=await probe(requester,'wallet/sign');expect(proof.wallet_after_two_approvals_status).toBe(200);
  await scene(requester,'11-wallet-verified','10 | Quorum unlocks verified execution','Two distinct approvals are recorded, target execution is independently verified, and actual wallet signing now returns HTTP 200.',20);
  const audit=await call(lead1,'AuditService','QueryAuditEvents',{requestId:sensitive,pageSize:100});expect(audit.status).toBe(200);
  proof.sensitive_approval_events=audit.body.events.filter(e=>e.eventType==='ChangeApprovalRecorded').length;expect(proof.sensitive_approval_events).toBe(2);
  expect(audit.body.events.some(e=>e.eventType==='ChangeExecuted')).toBe(true);
  await nav(lead1,'Audit');await lead1.getByLabel('Request',{exact:true}).fill(sensitive);
  const auditResponse=lead1.waitForResponse(r=>r.url().endsWith('.AuditService/QueryAuditEvents'));
  await lead1.getByRole('button',{name:'Find request audit'}).click();await auditResponse;
  await expect(lead1.getByRole('cell',{name:'ChangeExecuted',exact:true})).toBeVisible();
  await scene(lead1,'12-audit','11 | Inspect the permanent audit trail','The actual request history contains two independent approval events and a verified execution event. Request IDs link the evidence.',25);
  proof.wallet_revocation_request=await revoke('role:wallet-operator');
  proof.wallet_after_revocation_status=await probe(requester,'wallet/sign');expect(proof.wallet_after_revocation_status).toBe(403);
  await scene(requester,'13-wallet-revoked','12 | Revoke through the real review workflow','The reviewed wallet role revocation is independently verified. Wallet signing returns HTTP 403 again; no target reset was used.',20);
  proof.finance_revocation_request=await revoke('role:finance-analyst');
  proof.finance_after_revocation_status=await probe(requester,'finance-report/read');expect(proof.finance_after_revocation_status).toBe(403);
  await scene(requester,'14-finance-revoked','13 | Restore the starting access safely','Finance access also returns to HTTP 403 after its reviewed revocation. The ledger, identities and trust root remain intact.',15);
  proof.ledger=await verifyLedger(lead1);expect(errors).toEqual([]);proof.browser_runtime_errors=errors;
  await nav(requester,'Overview');await requester.evaluate(()=>scrollTo(0,0));
  await scene(requester,'15-final','Demonstrated | Assess, independently approve, verify',`${proof.ledger.events} canonical audit events independently hash-checked. This demo covers access review and role revocation; live containment and full automation remain future work.`,20);
  if(recorder){const current=recorder;recorder=null;proof.recording=await current.stop();}
  proof.completed_at=new Date().toISOString();
  privateWrite(resolve(local,action==='record'?'recording-evidence.json':'rehearsal-evidence.json'),proof);
  console.log(`PASS: ${action}; actual target access restored to denied and audit retained.`);
}

try {
  if (!['prepare','present','rehearse','record'].includes(action)) throw new Error('Unknown presenter action');
  if(existsSync(presenterLease)){
    const owner=JSON.parse(readFileSync(presenterLease,'utf8'));let alive=false;
    try{process.kill(owner.pid,0);alive=true;}catch{/* Stale presenter after a crash. */}
    if(alive)throw new Error('A presenter is already open. Run python scripts/demo.py close before starting another browser journey.');
    unlinkSync(presenterLease);
  }
  if(action==='present')privateWrite(presenterLease,{pid:process.pid,started_at:new Date().toISOString()});
  await setup();
  if (action === 'prepare') {
    if (errors.length) throw new Error('Browser runtime error during presenter setup');
    privateWrite(resolve(local,'presenter-evidence.json'),{actors:roles.map(([id])=>id),authenticator:'Native Chromium WebAuthn; virtual CTAP2 devices',prepared_at:new Date().toISOString(),browser_runtime_errors:errors});
    const requester = pages.get(roles[0][0]);
    const overviewLoaded = requester.waitForResponse(r => r.url().endsWith('.OverviewService/GetAttentionItems'));
    await requester.getByRole('navigation').getByRole('button',{name:'Overview',exact:true}).click();
    await overviewLoaded;
    await expect(requester.getByRole('button',{name:'Open access changes'})).toBeEnabled();
    await requester.screenshot({path:resolve(local,'presenter-overview.png')});
    console.log('Presenter sessions saved privately. Reopen with python scripts/demo.py present.');
  } else if (action === 'present') {
    const stopFile = resolve(local,'presenter-stop');
    if (existsSync(stopFile)) unlinkSync(stopFile);
    await nav(pages.get(roles[0][0]),'Overview');
    await pages.get(roles[0][0]).bringToFront();
    console.log('Four isolated presenter windows are ready. Keep this process running; Ctrl+C saves sessions and exits.');
    process.on('SIGINT', () => {void close();});
    process.on('SIGTERM', () => {void close();});
    const timer = setInterval(() => {if(existsSync(stopFile))void close();},500);
    await new Promise(resolve => browser.on('disconnected',resolve));
    clearInterval(timer);
  } else {
    await runStory();
  }
} catch (error) {
  writeFileSync(resolve(local,'demo-private-error.txt'),String(error.stack??error));
  if(activePage&&!activePage.isClosed())await activePage.screenshot({path:resolve(local,'demo-failure.png')}).catch(()=>{});
  // Avoid dumping browser call logs that can include enrollment tickets.
  console.error(`Demo ${action} failed: ${String(error.message).split('\n')[0]}`);
  process.exitCode = 1;
} finally {
  await close();
}
