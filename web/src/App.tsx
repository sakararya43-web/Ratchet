import { useEffect, useState, type FormEvent } from 'react';
import { ShieldCheck, RefreshCw } from 'lucide-react';
import { approve, login, mutation, registerPasskey, request, rpc, session, type Bootstrap, type Change, type Document, type Session } from './lib/api';

const tabs = ['Overview', 'Changes', 'Infrastructure', 'Impact', 'Policy history', 'Incidents', 'Audit', 'Passkeys'] as const;
type Tab = typeof tabs[number];
function Data({ value }: { value: unknown }) { return <pre className="data" tabIndex={0}>{JSON.stringify(value, null, 2)}</pre>; }
function Fields({ names }: { names: string[] }) { return <>{names.map(name => <label key={name}>{name}<input name={name} required autoComplete="off" /></label>)}</>; }

export function App() {
  const [identity, setIdentity] = useState<Session | null>(null);
  const [bootstrap, setBootstrap] = useState<Bootstrap | null>(null);
  const [tab, setTab] = useState<Tab>('Overview');
  const [result, setResult] = useState<unknown>(null);
  const [changes, setChanges] = useState<Change[]>([]);
  const [next, setNext] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [plan, setPlan] = useState<Document | null>(null);
  const tenantId = identity?.principal.tenant_id;
  async function work(action: () => Promise<void>) { setBusy(true); setError(''); try { await action(); } catch (e) { setError(e instanceof Error ? e.message : String(e)); } finally { setBusy(false); } }
  useEffect(() => { void session().then(setIdentity).catch(() => {}); }, []);
  useEffect(() => { if (identity) void work(async () => { setBootstrap(await request<Bootstrap>('/api/console/bootstrap')); }); }, [identity]);
  async function load(pageToken = '') {
    if (!tenantId) return;
    setResult(null); setNext('');
    if (tab === 'Infrastructure' || tab === 'Impact') return;
    if (tab === 'Changes') { const r = await rpc<{ requests?: Change[]; nextPageToken?: string }>('ChangeService', 'ListChanges', { tenantId, pageSize: 50, pageToken }); setChanges(r.requests ?? []); setNext(r.nextPageToken ?? ''); return; }
    if (tab === 'Passkeys') { setResult(await request('/api/passkeys/list')); return; }
    const [service, method] = tab === 'Overview' ? ['OverviewService', 'GetAttentionItems'] : tab === 'Policy history' ? ['ChangeService', 'ListPolicyHistory'] : tab === 'Incidents' ? ['IncidentService', 'ListIncidents'] : ['AuditService', 'QueryAuditEvents'];
    const r = await rpc<Document>(service, method, { tenantId, ...(tab === 'Overview' ? {} : { pageSize: 50, ...(tab === 'Policy history' ? { afterEventPosition: pageToken || '0' } : { pageToken }) }) });
    setResult(r); setNext(String(r.nextPageToken ?? (r.hasMore ? r.nextEventPosition : '') ?? ''));
  }
  useEffect(() => { if (identity) void work(() => load()); }, [identity, tab]);
  function form(e: FormEvent<HTMLFormElement>, action: (values: Record<string, string>) => Promise<void>) { e.preventDefault(); const data = Object.fromEntries(new FormData(e.currentTarget)) as Record<string, string>; void work(() => action(data)); }
  if (!identity) return <main className="login"><ShieldCheck size={38} /><h1>RATCHET</h1><p>Sign in to the security control plane</p><form onSubmit={e => form(e, async v => { setIdentity(await login(v.Tenant, v.Actor, v.Password)); })}><Fields names={['Tenant', 'Actor']} /><label>Password<input name="Password" type="password" autoComplete="current-password" required /></label><button disabled={busy}>Sign in</button></form>{error && <p role="alert">{error}</p>}</main>;
  return <div><header><div><h1><ShieldCheck size={24} /> RATCHET</h1><p>Security control plane</p></div><div>{tenantId} / {identity.principal.actor_id}<br /><button onClick={() => void work(async () => { await request('/api/auth/logout', {}); setIdentity(null); setBootstrap(null); })}>Sign out</button></div></header><nav aria-label="Console">{tabs.map(t => <button key={t} aria-current={t === tab ? 'page' : undefined} onClick={() => setTab(t)}>{t}</button>)}</nav><main><div className="heading"><h2>{tab}</h2><button disabled={busy} onClick={() => void work(async () => { setBootstrap(await request<Bootstrap>('/api/console/bootstrap')); await load(); })}><RefreshCw size={16} /> Refresh</button></div>{error && <p role="alert">{error}</p>}{busy && <p role="status">Waiting for the server or your passkey…</p>}
    {bootstrap && <p className="muted">Graph version {bootstrap.graph_version} · {bootstrap.scope === 'SELF' ? 'Your identity only; organization visibility requires investigator authorization.' : 'Organization visibility authorized by core policy.'}</p>}
    {tab === 'Infrastructure' && bootstrap && <><h3>Observed nodes</h3><table><thead><tr><th>Name</th><th>Type</th><th>Tier</th><th>Identity</th></tr></thead><tbody>{bootstrap.nodes.map(n => <tr key={n.id}><td>{n.display_name || n.id}</td><td>{n.type}</td><td>{n.tier ?? '—'}</td><td>{n.id}</td></tr>)}</tbody></table><h3>Observed relationships</h3><Data value={bootstrap.edges} /></>}
    {(tab === 'Changes' || tab === 'Impact') && <section><h3>{tab === 'Changes' ? 'Request an access change' : 'Assess an access change'}</h3><form onSubmit={e => form(e, async v => { const body = { tenantId, kind: v.Kind, targetIdentity: v.Identity, requestedAccess: v.Access, requestedBy: identity.principal.actor_id, ...(tab === 'Changes' ? { justification: v.Justification, mutation: mutation() } : {}) }; setResult(await rpc(tab === 'Changes' ? 'ChangeService' : 'ImpactService', tab === 'Changes' ? 'SubmitChange' : 'SimulateChange', body)); if (tab === 'Changes') { const r = await rpc<{ requests?: Change[] }>('ChangeService', 'ListChanges', { tenantId, pageSize: 50 }); setChanges(r.requests ?? []); } })}><label>Kind<select name="Kind"><option>ROLE_ASSIGN</option><option>ROLE_REVOKE</option></select></label><Fields names={['Identity', 'Access', ...(tab === 'Changes' ? ['Justification'] : [])]} /><button disabled={busy}>{tab === 'Changes' ? 'Submit for assessment' : 'Compute impact on server'}</button></form></section>}
    {tab === 'Changes' && changes.map(c => <section key={c.requestId}><h3>{c.kind} · {c.targetIdentity} → {c.requestedAccess}</h3><p>{c.status} · revision {c.revision} · quorum {c.requiredQuorum ?? 0}</p><p>{c.justification}</p><p>{c.decisionReasons?.join(' · ')}</p><details><summary>Exact approval digest and decision evidence</summary><code>{c.changeDigest}</code><button disabled={busy} onClick={() => void work(async () => setResult(await rpc('ChangeService', 'GetDecisionEvidence', { tenantId, requestId: c.requestId })))}>Load decision evidence</button></details><button disabled={busy || c.status !== 'AWAITING_APPROVAL'} onClick={() => void work(async () => { await approve(c, tenantId!); await load(); })}>Approve exact envelope with passkey</button><form onSubmit={e => form(e, async v => { await rpc('ChangeService', v.Action, { tenantId, requestId: c.requestId, reason: v.Reason, mutation: mutation(c.revision) }); await load(); })}><label>Review action<select name="Action"><option value="HoldChange">Hold</option><option value="RejectChange">Reject</option></select></label><Fields names={['Reason']} /><button disabled={busy}>Apply review action</button></form></section>)}
    {tab === 'Changes' && !busy && changes.length === 0 && <p>No requests in this authorized page.</p>}
    {tab === 'Incidents' && <section><h3>Plan containment</h3><form onSubmit={e => form(e, async v => { const r = await rpc<{ plan: Document }>('ContainmentService', 'PlanContainment', { tenantId, compromisedIdentity: v.Identity, mutation: mutation() }); setPlan(r.plan); setResult(r); })}><Fields names={['Identity']} /><button disabled={busy}>Compute plan</button></form>{plan && <><Data value={plan} /><button disabled={busy} onClick={() => void work(async () => setResult(await rpc('IncidentService', 'OpenIncident', { tenantId, planId: plan.planId, planDigest: plan.planDigest, mutation: mutation() })))}>Open incident for this exact plan</button></>}<h3>Request reviewed restoration</h3><form onSubmit={e => form(e, async v => setResult(await rpc('ContainmentService', 'RestoreAccess', { tenantId, incidentId: v.Incident, targetIdentity: v.Identity, accessToRestore: v.Access, justification: v.Justification, mutation: mutation() }))) }><Fields names={['Incident', 'Identity', 'Access', 'Justification']} /><button disabled={busy}>Submit restoration request</button></form></section>}
    {tab === 'Passkeys' && <section><h3>Register a passkey</h3><form onSubmit={e => form(e, async v => { await registerPasskey(v.Label); await load(); })}><Fields names={['Label']} /><button disabled={busy}>Register with your authenticator</button></form><h3>Revoke a credential</h3><form onSubmit={e => form(e, async v => { await request('/api/passkeys/revoke', { credential_id: v.Credential }); await load(); })}><Fields names={['Credential']} /><button disabled={busy}>Revoke credential</button></form></section>}
    {result !== null && <Data value={result} />}{next && <button disabled={busy} onClick={() => void work(() => load(next))}>Next page</button>}
  </main></div>;
}
