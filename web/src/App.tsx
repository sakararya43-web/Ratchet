import { useEffect, useState, type FormEvent } from 'react';
import { ShieldCheck, RefreshCw } from 'lucide-react';
import { approve, executeContainment, login, mutation, registerPasskey, revokePasskey, request, rpc, session, type Bootstrap, type Change, type Document, type Session } from './lib/api';
import { verifyEnvelope, verifyImpact, type ApprovalEnvelope } from './lib/envelope';

const tabs = ['Overview', 'Changes', 'Infrastructure', 'Impact', 'Policy history', 'Incidents', 'Audit', 'Passkeys'] as const;
type Tab = typeof tabs[number];
type Resource = { id: string; displayName?: string; tier?: number };
type Impact = { graphVersion?: string; monotonicReduction?: boolean; newResources?: Resource[]; newControlledIdentities?: string[]; newTier0PathsCount?: number; safeguardsWeakened?: { id: string; description?: string }[]; affectedIdentities?: { identityId: string; newPowers?: { nodeId: string; action: string }[]; removedPowers?: { nodeId: string; action: string }[] }[] };
type Review = { change: Change; envelope: ApprovalEnvelope; impact: Impact; approvers: string[] };
type BoundImpact = {
 graph_version: number; monotonic_reduction: boolean; safeguards_weakened: { id: string; display_name?: string }[];
 affected_identities: { identity_id: string; new_resources: { id: string; display_name?: string; tier: number }[];
 new_controlled_identities: string[]; new_tier0_routes: unknown[];
 new_powers: { node_id: string; action: string }[]; removed_powers?: { node_id: string; action: string }[] }[];
};
function boundImpactView(impact: BoundImpact): Impact {
 const resources = new Map<string, Resource>(); const controlled = new Set<string>(); let paths = 0;
 for (const actor of impact.affected_identities) {
  for (const resource of actor.new_resources) resources.set(resource.id, { id: resource.id, displayName: resource.display_name, tier: resource.tier });
  for (const id of actor.new_controlled_identities) controlled.add(id);
  paths += actor.new_tier0_routes.length;
 }
 return { graphVersion: String(impact.graph_version), monotonicReduction: impact.monotonic_reduction,
  newResources: [...resources.values()], newControlledIdentities: [...controlled], newTier0PathsCount: paths,
  safeguardsWeakened: impact.safeguards_weakened.map(s => ({ id: s.id, description: s.display_name })),
  affectedIdentities: impact.affected_identities.map(a => ({ identityId: a.identity_id,
   newPowers: a.new_powers.map(p => ({ nodeId: p.node_id, action: p.action })),
   removedPowers: a.removed_powers?.map(p => ({ nodeId: p.node_id, action: p.action })) })) };
}
type AuditEvent = { sequenceNumber: string; eventType: string; eventHash: string; streamId: string; recordedAt: string };
function Data({ value }: { value: unknown }) { return <pre className="data" tabIndex={0}>{JSON.stringify(value, null, 2)}</pre>; }
function Fields({ names }: { names: string[] }) { return <>{names.map(name => <label key={name}>{name}<input name={name} required autoComplete="off" /></label>)}</>; }
function ImpactView({ impact }: { impact: Impact }) {
  return <div className="impact"><p>Graph version {impact.graphVersion} | {impact.monotonicReduction ? 'Verified access reduction' : 'Access expansion assessed'}</p>
    <h4>Newly reachable resources</h4>{impact.newResources?.length ? <ul>{impact.newResources.map(r => <li key={r.id}>{r.displayName || r.id} - tier {r.tier ?? 0} <code>{r.id}</code></li>)}</ul> : <p>No newly reachable resources.</p>}
    <p>New tier-0 paths: <strong>{impact.newTier0PathsCount ?? 0}</strong></p>
    <h4>Additional controlled identities</h4>{impact.newControlledIdentities?.length ? <ul>{impact.newControlledIdentities.map(id => <li key={id}>{id}</li>)}</ul> : <p>None.</p>}
    <h4>Changed authority by identity</h4>{impact.affectedIdentities?.map(a => <div key={a.identityId}><strong>{a.identityId}</strong><ul>{a.newPowers?.map(p => <li key={`add:${p.nodeId}:${p.action}`}>Gain {p.action} on {p.nodeId}</li>)}{a.removedPowers?.map(p => <li key={`remove:${p.nodeId}:${p.action}`}>Remove {p.action} on {p.nodeId}</li>)}</ul></div>)}
    <h4>Weakened safeguards</h4>{impact.safeguardsWeakened?.length ? <ul>{impact.safeguardsWeakened.map(s => <li key={s.id}>{s.description || s.id}</li>)}</ul> : <p>None observed.</p>}
  </div>;
}
export function App() {
  const [identity, setIdentity] = useState<Session | null>(null);
  const [bootstrap, setBootstrap] = useState<Bootstrap | null>(null);
  const [tab, setTab] = useState<Tab>('Overview');
  const [result, setResult] = useState<unknown>(null);
  const [changes, setChanges] = useState<Change[]>([]);
  const [next, setNext] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const [plan, setPlan] = useState<Document | null>(null);
  const [review, setReview] = useState<Review | null>(null);
  const tenantId = identity?.principal.tenant_id;
  async function work(action: () => Promise<void>) { setBusy(true); setError(''); setNotice(''); try { await action(); } catch (e) { setError(e instanceof Error ? e.message : String(e)); } finally { setBusy(false); } }
  useEffect(() => { void session().then(setIdentity).catch(() => {}); }, []);
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
  useEffect(() => { if (identity) void work(async () => { setReview(null); setBootstrap(await request<Bootstrap>('/api/console/bootstrap')); await load(); }); }, [identity, tab]);
  useEffect(() => {
    if (!identity || tab !== 'Changes' || busy || next) return;
    let cancelled = false;
    const timer = setTimeout(() => { void rpc<{ requests?: Change[] }>('ChangeService', 'ListChanges', { tenantId, pageSize: 50 }).then(r => { if (!cancelled) setChanges(r.requests ?? []); }).catch(e => { if (!cancelled) setError(String(e)); }); }, 2000);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [identity, tab, busy, changes, next]);
  function form(e: FormEvent<HTMLFormElement>, action: (values: Record<string, string>) => Promise<void>) { e.preventDefault(); const element = e.currentTarget; const data = Object.fromEntries(new FormData(element)) as Record<string, string>; void work(async () => { await action(data); element.reset(); }); }
  async function inspect(c: Change) {
    const { request: fresh } = await rpc<{ request: Change }>('ChangeService', 'GetChange', { tenantId, requestId: c.requestId });
    const envelope = await verifyEnvelope(fresh, tenantId!);
    const r = await request<{ request_id: string; revision: number; change_digest: string; impact: BoundImpact; approvers: string[] }>(`/api/console/approval-review?request_id=${encodeURIComponent(fresh.requestId)}`);
    if (r.request_id !== fresh.requestId || String(r.revision) !== fresh.revision || r.change_digest !== fresh.changeDigest) throw new Error('Request changed since review; refresh again');
    await verifyImpact(r.impact, envelope);
    setReview({ change: fresh, envelope, impact: boundImpactView(r.impact), approvers: r.approvers });
  }
  function reset() { setIdentity(null); setBootstrap(null); setChanges([]); setResult(null); setReview(null); setPlan(null); setNext(''); setNotice(''); setTab('Overview'); }
  if (!identity) return <main className="login"><ShieldCheck size={38} /><h1>RATCHET</h1><p>Sign in to the security control plane</p><form onSubmit={e => form(e, async v => { setIdentity(await login(v.Tenant, v.Actor, v.Password)); })}><Fields names={['Tenant', 'Actor']} /><label>Password<input name="Password" type="password" autoComplete="current-password" required /></label><button disabled={busy}>Sign in</button></form>{error && <p role="alert">{error}</p>}</main>;
  const overview = result as { attentionItems?: { itemId: string; title: string; description: string }[] } | null;
  const audit = result as { events?: AuditEvent[] } | null;
  return <div><header><div><h1><ShieldCheck size={24} /> RATCHET</h1><p>Security control plane</p></div><div><span data-testid="signed-in-actor">{tenantId} / {identity.principal.actor_id}</span><br /><button disabled={busy} onClick={() => void work(async () => { await request('/api/auth/logout', {}); reset(); })}>Sign out</button></div></header>
    <nav aria-label="Console">{tabs.map(t => <button disabled={busy} key={t} aria-current={t === tab ? 'page' : undefined} onClick={() => setTab(t)}>{t}</button>)}</nav>
    <main><div className="heading"><h2>{tab}</h2><button disabled={busy} onClick={() => void work(async () => { setBootstrap(await request<Bootstrap>('/api/console/bootstrap')); await load(); })}><RefreshCw size={16} /> Refresh</button></div>
      {error && <p role="alert">{error}</p>}{notice && <p role="status" className="notice">{notice}</p>}{busy && <p role="status">Waiting for the server or your passkey?</p>}
      {bootstrap && <p className="muted">Graph version {bootstrap.graph_version} | {bootstrap.scope === 'SELF' ? 'Your identity only; organization visibility requires investigator authorization.' : 'Organization visibility authorized by core policy.'}</p>}
      {tab === 'Overview' && <section><h3>Attention items</h3>{overview?.attentionItems?.length ? overview.attentionItems.map(item => <article key={item.itemId}><h4>{item.title}</h4><p>{item.description}</p></article>) : <p>No attention items returned for this account.</p>}<button disabled={busy} onClick={() => setTab('Changes')}>Open access changes</button><button disabled={busy} onClick={() => setTab('Passkeys')}>Manage your passkeys</button></section>}
      {tab === 'Infrastructure' && bootstrap && (
        <section>
          <h3>Observed infrastructure nodes ({bootstrap.nodes.length})</h3>
          <p className="muted">Target graph snapshot version {bootstrap.graph_version}. Highlighted nodes are critical Tier-0 infrastructure.</p>
          <table>
            <thead><tr><th>Name</th><th>Type</th><th>Tier</th><th>Identity / Resource ID</th></tr></thead>
            <tbody>
              {bootstrap.nodes.map(n => (
                <tr key={n.id} style={n.tier === 0 ? { background: '#1c1917', borderLeft: '4px solid #ef4444' } : undefined}>
                  <td>{n.display_name || n.id}</td>
                  <td>{n.type}</td>
                  <td>{n.tier === 0 ? <strong style={{ color: '#f87171' }}>Tier 0 (Critical)</strong> : (n.tier ?? '—')}</td>
                  <td><code>{n.id}</code></td>
                </tr>
              ))}
            </tbody>
          </table>
          <details><summary>Observed relationships ({bootstrap.edges.length})</summary><Data value={bootstrap.edges} /></details>
        </section>
      )}
      {(tab === 'Changes' || tab === 'Impact') && <section>
        <h3>{tab === 'Changes' ? 'Request an access change' : 'Assess an access change'}</h3>
        <p>Choose an identity and exact role. The server assesses reachability and selects independent reviewers.</p>
        <form onSubmit={e => form(e, async v => {
          const duration = parseInt(v.DurationSeconds || '0', 10);
          const emergency = v.Emergency === 'true';
          const body = {
            tenantId,
            kind: v.Kind,
            targetIdentity: v.Identity,
            requestedAccess: v.Access,
            requestedBy: identity.principal.actor_id,
            ...(duration > 0 ? { durationSeconds: duration } : {}),
            ...(emergency ? { emergency: true } : {}),
            ...(tab === 'Changes' ? { justification: v.Justification, mutation: mutation() } : {})
          };
          const r = await rpc<{ request?: Change; impact?: Impact }>(tab === 'Changes' ? 'ChangeService' : 'ImpactService', tab === 'Changes' ? 'SubmitChange' : 'SimulateChange', body);
          if (r.request) {
            setNotice(`Request ${r.request.requestId} submitted. Assessment and execution status update automatically.`);
            await load();
          } else setResult(r);
        })}>
          <label>Kind<select name="Kind"><option>ROLE_ASSIGN</option><option>ROLE_REVOKE</option></select></label>
          <Fields names={['Identity', 'Access', ...(tab === 'Changes' ? ['Justification'] : [])]} />
          {tab === 'Changes' && (
            <>
              <label>Duration limit in seconds (0 for permanent)<input name="DurationSeconds" type="number" defaultValue="0" min="0" max="86400" /></label>
              <label>Emergency request?<select name="Emergency"><option value="false">No (Standard review)</option><option value="true">Yes (Emergency review)</option></select></label>
            </>
          )}
          <button disabled={busy}>{tab === 'Changes' ? 'Submit for assessment' : 'Compute impact on server'}</button>
        </form>
      </section>}
      {tab === 'Impact' && result !== null && <section><h3>Computed impact</h3><ImpactView impact={(result as { impact: Impact }).impact} /></section>}
      {tab === 'Changes' && review && <section className="review" data-testid="approval-review"><h3>Review the exact change</h3><p>Recorded independent approvals: {review.approvers.length} / {review.change.requiredQuorum ?? 0}{review.approvers.length > 0 && ` (${review.approvers.join(", ")})`}</p><dl><dt>Identity</dt><dd>{review.envelope.intent.target_identity}</dd><dt>Action / role</dt><dd>{review.envelope.intent.kind} / {review.envelope.intent.requested_access}</dd><dt>Requester</dt><dd>{review.envelope.authenticated_requester}</dd><dt>Approval expires</dt><dd>{review.envelope.expires_at}</dd><dt>Required independent reviewers</dt><dd>{review.change.requiredQuorum} | {review.change.requiredApproverGroups?.join(', ')}</dd></dl><ImpactView impact={review.impact} /><p className="notice">Canonical envelope digest verified in this browser. The passkey challenge is checked against this digest and your signed-in actor.</p><code data-testid="verified-envelope-digest">{review.change.changeDigest}</code><details><summary>Exact canonical envelope</summary><Data value={review.envelope} /></details><button disabled={busy || review.change.status !== 'AWAITING_APPROVAL'} onClick={() => void work(async () => { const r = await approve(review.change, tenantId!) as { request: Change }; setReview(null); await load(); setNotice(`Approval recorded. Server state: ${r.request.status}. Required independent quorum: ${r.request.requiredQuorum ?? 0}.`); })}>Approve reviewed change with passkey</button><button disabled={busy} onClick={() => setReview(null)}>Close review</button></section>}
      {tab === 'Changes' && changes.map(c => <section key={c.requestId} data-testid={`change-${c.requestId}`}>
        <h3>
          {c.kind === 'ROLE_ASSIGN' ? 'Assign role' : c.kind === 'ROLE_REVOKE' ? 'Revoke role' : c.kind}: {c.requestedAccess}
          {c.emergency && <span style={{ marginLeft: 8, padding: '2px 8px', background: '#dc2626', borderRadius: 4, fontSize: 11, fontWeight: 700 }}>EMERGENCY</span>}
        </h3>
        <p>{c.targetIdentity} | requested by {c.requestedBy}</p>
        <p><strong data-testid="change-status">{c.status}</strong> | revision {c.revision} | required independent quorum {c.requiredQuorum ?? 0}</p>
        {c.timeLimitSeconds && c.timeLimitSeconds > 0 ? (
          <p className="notice">Temporary grant: {c.timeLimitSeconds}s duration | Status: <strong>{c.expiryStatus || 'SCHEDULED'}</strong>{c.grantExpiresAt ? ` | Expires: ${c.grantExpiresAt}` : ''}</p>
        ) : null}
        <p>{c.justification}</p>
        <p>{c.decisionReasons?.join(' | ')}</p>
        <code>Request {c.requestId}</code>
        <p>{c.status === 'EXECUTED' ? 'Target change and independent read-back verified by core.' : c.status === 'EXECUTING' ? 'Awaiting independently verified target evidence; access is not confirmed yet.' : c.status === 'AWAITING_APPROVAL' ? 'Waiting for the required independent approvals.' : c.status === 'REVOKING' ? 'Target expiry revocation in progress.' : c.status === 'REVOKED' ? 'Time-bounded grant expired and verified revoked at target.' : ''}</p>
        <button disabled={busy || !c.changeDigest || c.status !== 'AWAITING_APPROVAL'} onClick={() => void work(() => inspect(c))}>Review exact change</button>
        <details><summary>Decision and review actions</summary>
          <button disabled={busy} onClick={() => void work(async () => setResult(await rpc('ChangeService', 'GetDecisionEvidence', { tenantId, requestId: c.requestId })))}>Load decision evidence</button>
          <form onSubmit={e => form(e, async v => {
            await rpc('ChangeService', v.Action, { tenantId, requestId: c.requestId, reason: v.Reason, mutation: mutation(c.revision) });
            await load();
          })}>
            <label>Review action<select name="Action"><option value="HoldChange">Hold</option><option value="RejectChange">Reject</option></select></label>
            <Fields names={['Reason']} />
            <button disabled={busy}>Apply review action</button>
          </form>
        </details>
      </section>)}
      {tab === 'Changes' && !busy && changes.length === 0 && <p>No requests in this authorized page.</p>}
      {tab === 'Incidents' && <section>
        <h3>Containment and Incident Response</h3>
        <p>Assess blast radius, compute minimal disruption cuts, and execute exact-plan containment confirmed by native passkey assertion.</p>
        <form onSubmit={e => form(e, async v => {
          const r = await rpc<{ plan: Document }>('ContainmentService', 'PlanContainment', { tenantId, compromisedIdentity: v.Identity, mutation: mutation() });
          setPlan(r.plan);
          setResult(r);
        })}>
          <Fields names={['Identity']} />
          <button disabled={busy}>Compute containment plan</button>
        </form>
        {plan && (
          <div className="review">
            <h4>Containment Proposal: {String(plan.planId)}</h4>
            <p>Compromised identity: <strong>{String(plan.compromisedIdentity)}</strong></p>
            <p>Disruption cost: <strong>{String(plan.disruptionCost)}</strong> | Severed tier-0 routes: <strong>{String(plan.severedTier0RoutesCount)}</strong></p>
            <p>{plan.minimumProved ? '✓ Proven minimal disruption cut' : 'Sub-optimal cut'}</p>
            <p>Plan digest: <code>{String(plan.planDigest)}</code></p>
            <details><summary>Canonical Plan Evidence</summary><Data value={plan} /></details>
            <button disabled={busy} onClick={() => void work(async () => {
              const res = await executeContainment({ planId: plan.planId as string, planDigest: plan.planDigest as string }, tenantId!);
              setNotice('Containment executed with native passkey assertion and verified zero tier-0 reach.');
              setResult(res);
              await load();
            })}>Execute containment with passkey confirmation</button>
            <button disabled={busy} onClick={() => void work(async () => {
              const res = await rpc('IncidentService', 'OpenIncident', { tenantId, planId: plan.planId, planDigest: plan.planDigest, mutation: mutation() });
              setNotice('Incident opened for investigation.');
              setResult(res);
              await load();
            })}>Open incident without execution</button>
          </div>
        )}
        <h3>Request reviewed restoration</h3>
        <p>Submit a fresh independently reviewed restoration request linked to an incident. Session resurrection is forbidden.</p>
        <form onSubmit={e => form(e, async v => {
          const res = await rpc('ContainmentService', 'RestoreAccess', {
            tenantId,
            incidentId: v.Incident,
            targetIdentity: v.Identity,
            accessToRestore: v.Access,
            justification: v.Justification,
            mutation: mutation(),
          });
          setNotice('Restoration request submitted. Independent review required.');
          setResult(res);
          await load();
        })}>
          <Fields names={['Incident', 'Identity', 'Access', 'Justification']} />
          <button disabled={busy}>Submit restoration request</button>
        </form>
      </section>}
      {tab === 'Passkeys' && <section><h3>Register a passkey</h3><p>Use a one-use enrollment ticket issued by your operator. A signed-in session alone cannot change approval credentials.</p><form onSubmit={e => form(e, async v => { await registerPasskey(v.Label, v.Ticket); await load(); setNotice('Passkey registered for this signed-in account.'); })}><Fields names={['Label']} /><label>Enrollment ticket<input name="Ticket" type="password" autoComplete="off" required /></label><button disabled={busy}>Register with your authenticator</button></form><h3>Revoke a credential</h3><form onSubmit={e => form(e, async v => { await revokePasskey(v.Credential, v.RevocationTicket); await load(); setNotice('Credential revoked.'); })}><Fields names={['Credential']} /><label>Revocation ticket<input name="RevocationTicket" type="password" autoComplete="off" required /></label><button disabled={busy}>Revoke credential</button></form></section>}
      {tab === 'Audit' && <section><h3>Permanent audit trail</h3><form onSubmit={e => form(e, async v => setResult(await rpc('AuditService', 'QueryAuditEvents', { tenantId, requestId: v.Request, pageSize: 50 })))}><Fields names={['Request']} /><button disabled={busy}>Find request audit</button></form><table><thead><tr><th>Sequence</th><th>Event</th><th>Stream</th><th>Recorded</th><th>Event hash</th></tr></thead><tbody>{audit?.events?.map(event => <tr key={event.sequenceNumber}><td>{event.sequenceNumber}</td><td>{event.eventType}</td><td>{event.streamId}</td><td>{event.recordedAt}</td><td><code>{event.eventHash}</code></td></tr>)}</tbody></table>{!audit?.events?.length && <p>No events in this authorized query.</p>}</section>}
      {result !== null && tab !== 'Overview' && tab !== 'Impact' && <details><summary>Server evidence</summary><Data value={result} /></details>}{next && <button disabled={busy} onClick={() => void work(() => load(next))}>Next page</button>}
    </main></div>;
}
