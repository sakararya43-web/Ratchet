import { useEffect, useState, type FormEvent } from 'react';
import { CheckCircle2, CircleSlash, Fingerprint, FolderOpen, Undo2 } from 'lucide-react';
import { executeContainment, mutation, rpc, type Document } from '../lib/api';
import { auditEvents, getIncident, pathsToCritical, reach, short, type Incident, type LedgerEvent, type Plan, type Reach, type Route } from './api';
import { useConsole } from './context';
import { RoutePath } from './impact';
import { Chips, DataTable, Empty, EntityLink, Inspector, KeyValues, TierBadge, When, type Column } from './ui';

const statuses = ['All', 'OPEN', 'CONTAINING', 'CONTAINED', 'RESOLVED'] as const;
type Status = typeof statuses[number];

export function IncidentsTab({ result, refresh }: { result: unknown; refresh: () => Promise<void> }) {
  const { tenantId, busy, work, notify, focus, bootstrap, go, containment, reloadChanges } = useConsole();
  const incidents = ((result ?? {}) as { incidents?: Incident[] }).incidents ?? [];
  const [status, setStatus] = useState<Status>('All');
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<string | null>(null);
  const [plan, setPlan] = useState<Plan | null>(null);
  const [restoreId, setRestoreId] = useState('');
  useEffect(() => { if (focus?.incidentId) setSelected(focus.incidentId); }, [focus]);
  const counts = Object.fromEntries(statuses.map(s => [s, s === 'All' ? incidents.length : incidents.filter(i => i.status === s).length])) as Record<Status, number>;
  const rows = incidents.filter(i => (status === 'All' || i.status === status) && `${i.incidentId} ${i.affectedIdentity} ${i.title} ${i.rootCauseType}`.toLowerCase().includes(search.toLowerCase()));
  const columns: Column<Incident>[] = [
    { key: 'id', label: 'Incident', width: '14%', sort: i => i.openedAt ?? '', render: i => <><code title={i.incidentId}>{short(i.incidentId)}</code><span className="cell-sub">{i.title}</span></> },
    { key: 'identity', label: 'Affected identity', width: '20%', sort: i => i.affectedIdentity ?? '', render: i => <EntityLink id={i.affectedIdentity}/> },
    { key: 'type', label: 'Type', width: '16%', sort: i => i.rootCauseType ?? '', render: i => (i.rootCauseType ?? '—').replace(/_/g, ' ').toLowerCase() },
    { key: 'severity', label: 'Severity', width: '11%', sort: i => i.severity ?? '', render: i => <span className="severity" data-severity={i.severity}>{i.severity ?? '—'}</span> },
    { key: 'detected', label: 'Detected', width: '12%', sort: i => i.openedAt ?? '', render: i => <When iso={i.openedAt}/> },
    { key: 'status', label: 'Status', width: '13%', sort: i => i.status ?? '', render: i => <strong className="status-badge" data-status={i.status === 'CONTAINED' || i.status === 'RESOLVED' ? 'EXECUTED' : 'AWAITING_APPROVAL'}>{i.status}</strong> },
    { key: 'containment', label: 'Containment', width: '14%', render: i => i.containedAt && !i.containedAt.startsWith('0001') ? <>Verified <When iso={i.containedAt}/></> : i.containmentPlan ? `${i.containmentPlan.recommendedRevocations?.length ?? 0} actions planned` : 'Not planned' },
  ];
  function planFor(e: FormEvent<HTMLFormElement>) {
    e.preventDefault(); const v = Object.fromEntries(new FormData(e.currentTarget)) as Record<string, string>;
    void work(async () => { const r = await rpc<{ plan: Plan }>('ContainmentService', 'PlanContainment', { tenantId, compromisedIdentity: v.Identity, mutation: mutation() }); setPlan(r.plan); });
  }
  function restore(e: FormEvent<HTMLFormElement>) {
    e.preventDefault(); const element = e.currentTarget; const v = Object.fromEntries(new FormData(element)) as Record<string, string>;
    void work(async () => { const res = await rpc<{ changeRequestId?: string }>('ContainmentService', 'RestoreAccess', { tenantId, incidentId: v.Incident, targetIdentity: v.Identity, accessToRestore: v.Access, justification: v.Justification, mutation: mutation() });
      setRestoreId(res.changeRequestId ?? ''); notify('Restoration request submitted. Independent review required.'); element.reset(); });
  }
  return <>
    <div className={selected ? 'workspace-split has-inspector' : 'workspace-split'}><div className="workspace-main">
      <section><div className="section-title"><h3>Incident queue</h3><span className="small-count">{incidents.length}</span></div>
        <Chips label="Incident status" options={statuses} value={status} onChange={setStatus} counts={counts}/>
        <label className="request-filter">Search incidents<input type="search" value={search} onChange={e => setSearch(e.target.value)} placeholder="Incident ID, identity or type"/></label>
        <DataTable columns={columns} rows={rows} rowKey={i => i.incidentId} selected={selected ?? undefined} onRow={i => setSelected(i.incidentId)}
          empty={<Empty title={incidents.length ? 'No incidents match.' : 'No incidents recorded.'}>{incidents.length ? 'Change the status filter or search.' : 'Incidents appear when a responder opens one from a containment plan below, or when drift or a suspicious escalation is detected.'}</Empty>}/>
      </section>
      {!containment && <section><h3>Containment and restoration</h3><p className="inline-note" data-testid="containment-unavailable">Containment planning is not enabled on this deployment. The core serves it only when the operator has configured revocation costs, which the minimum-disruption cut needs to weigh each action. Incident records above remain available.</p></section>}
      {containment && <section><h3>Containment planning</h3><p>Enter a compromised identity. RATCHET computes the smallest set of revocations that cuts every route to a tier-0 asset while keeping unrelated work running.</p>
        <form onSubmit={planFor}><label>Identity<input key={focus?.identity ?? ''} defaultValue={focus?.identity ?? ''} name="Identity" required autoComplete="off" placeholder="Choose an identity" list="incident-identities"/></label><datalist id="incident-identities">{(bootstrap?.nodes ?? []).filter(n => n.type === 'Human' || n.type === 'ServiceAccount').map(n => <option key={n.id} value={n.id}>{n.display_name}</option>)}</datalist><button disabled={busy}>Compute containment plan</button></form>
        {plan && <PlanView plan={plan} onExecute={() => void work(async () => { const res = await executeContainment({ planId: plan.planId, planDigest: plan.planDigest }, tenantId) as { incidentId?: string }; await refresh(); await reloadChanges(); notify('Containment dispatched on the priority stream with passkey confirmation. Awaiting target verification.'); if (res.incidentId) setSelected(res.incidentId); })}
          onOpen={() => void work(async () => { const res = await rpc<{ incident?: Incident } & Document>('IncidentService', 'OpenIncident', { tenantId, planId: plan.planId, planDigest: plan.planDigest, mutation: mutation() }); await refresh(); notify('Incident opened for investigation.'); if (res.incident?.incidentId) setSelected(res.incident.incidentId); })}/>}
      </section>}
      {containment && <section><h3>Request reviewed restoration</h3><p>Restoring revoked access creates a fresh access request that goes through normal independent approval. Terminated sessions are never resurrected.</p>
        <form onSubmit={restore}>{['Incident', 'Identity', 'Access', 'Justification'].map(name => <label key={name}>{name}<input name={name} required autoComplete="off"/></label>)}<button disabled={busy}><Undo2 size={13}/> Submit restoration request</button></form>
        {restoreId && <p className="inline-note">Restoration request <button type="button" className="entity-link" onClick={() => go('Changes', { requestId: restoreId })}>{short(restoreId)}</button> created; it now needs independent approval in Changes.</p>}
      </section>}
    </div>{/* Keyed by status so an open inspector reloads when containment changes the incident. */}
    {selected && <IncidentInspector key={`${selected}:${incidents.find(i => i.incidentId === selected)?.status ?? ''}`} incidentId={selected} onClose={() => setSelected(null)}/>}</div>
  </>;
}

function PlanView({ plan, onExecute, onOpen }: { plan: Plan; onExecute: () => void; onOpen: () => void }) {
  const { busy } = useConsole();
  const preserved = plan.preservedActivities ?? []; const disrupted = plan.disruptedActivities ?? [];
  return <div className="review" data-testid="containment-plan"><h4>Containment proposal <code>{short(plan.planId)}</code></h4>
    <KeyValues rows={[['Compromised identity', <EntityLink id={plan.compromisedIdentity}/>], ['Tier-0 routes severed', String(plan.severedTier0RoutesCount ?? 0)], ['Disruption cost', String(plan.disruptionCost ?? '—')],
      ['Optimality', plan.minimumProved ? `Proven minimum-disruption cut${plan.optimalityScope ? ` (${plan.optimalityScope})` : ''}` : 'Not proven minimal'], ['Zero tier-0 reach after cut', plan.proposedZeroTier0Proved ? 'Proven' : 'Not proven'],
      ['Algorithm', plan.algorithm ?? '—'], ['Graph version', plan.graphVersion ?? '—'], ['Plan digest', <code>{short(plan.planDigest, 20)}</code>], ['Expires', <When iso={plan.expiresAt}/>]]}/>
    <h4>Proposed actions ({plan.recommendedRevocations?.length ?? 0})</h4>
    {plan.recommendedRevocations?.length ? <ol className="action-list">{plan.recommendedRevocations.map((a, i) => <li key={a.actionId ?? i}><span className="action-type">{(a.actionType ?? '').replace(/_/g, ' ')}</span><span><EntityLink id={a.targetIdentity}/> · <EntityLink id={a.resourceOrRole}/></span><small>{a.reason}</small></li>)}</ol> : <p className="muted">No revocation is needed: this identity has no route to a tier-0 asset.</p>}
    <h4>Business continuity</h4>
    <div className="continuity"><div><p className="eyebrow"><CheckCircle2 size={12}/> REMAINS OPERATIONAL ({preserved.length})</p>{preserved.length ? <ul className="plain-list">{preserved.map((p, i) => <li key={i}><EntityLink id={p.identityId}/> · {p.permittedAction} <EntityLink id={p.resourceId} label={p.resourceName || p.resourceId}/> <TierBadge tier={p.tier ?? 0}/></li>)}</ul> : <p className="muted">No other access was assessed.</p>}</div>
      <div><p className="eyebrow is-critical"><CircleSlash size={12}/> ISOLATED BY CONTAINMENT ({disrupted.length})</p>{disrupted.length ? <ul className="plain-list">{disrupted.map((p, i) => <li key={i}><EntityLink id={p.identityId}/> · {p.permittedAction} <EntityLink id={p.resourceId} label={p.resourceName || p.resourceId}/> <TierBadge tier={p.tier ?? 0}/></li>)}</ul> : <p className="muted">No legitimate activity is disrupted.</p>}</div></div>
    <details><summary>Canonical plan evidence</summary><pre className="data" tabIndex={0}>{JSON.stringify({ ...plan, canonicalPlanJson: undefined }, null, 2)}</pre></details>
    <div className="inspector-actions"><button className="button-dark" disabled={busy} onClick={onExecute}><Fingerprint size={14}/> Execute containment with passkey confirmation</button><button disabled={busy} onClick={onOpen}><FolderOpen size={13}/> Open incident without execution</button></div>
  </div>;
}

function IncidentInspector({ incidentId, onClose }: { incidentId: string; onClose: () => void }) {
  const { tenantId, changes, go } = useConsole();
  const [incident, setIncident] = useState<Incident | null>(null);
  const [timeline, setTimeline] = useState<LedgerEvent[]>([]);
  const [access, setAccess] = useState<Reach | null>(null);
  const [routes, setRoutes] = useState<Route[] | null>(null);
  useEffect(() => {
    let live = true; setIncident(null); setTimeline([]); setAccess(null); setRoutes(null);
    void getIncident(tenantId, incidentId).then(r => { if (!live || !r.incident) return; setIncident(r.incident); const who = r.incident.affectedIdentity;
      if (who) { void reach(tenantId, who).then(x => live && setAccess(x)).catch(() => undefined); void pathsToCritical(tenantId, who).then(x => live && setRoutes(x.routes ?? [])).catch(() => undefined); } }).catch(() => undefined);
    void auditEvents(tenantId, { incidentId, pageSize: 50 }).then(r => live && setTimeline(r.events ?? [])).catch(() => undefined);
    return () => { live = false; };
  }, [tenantId, incidentId]);
  const related = changes.filter(c => incident?.affectedIdentity && (c.targetIdentity === incident.affectedIdentity || c.requestedBy === incident.affectedIdentity)).slice(0, 8);
  return <Inspector eyebrow={`INCIDENT ${short(incidentId)}`} title={incident?.title ?? 'Loading incident…'} onClose={onClose} testId="incident-inspector">
    {incident && <><KeyValues rows={[['Affected identity', <EntityLink id={incident.affectedIdentity}/>], ['Type', (incident.rootCauseType ?? '—').replace(/_/g, ' ').toLowerCase()], ['Severity', incident.severity ?? '—'], ['Status', incident.status ?? '—'],
      ['Detected', <When iso={incident.openedAt}/>], ['Contained', incident.containedAt && !incident.containedAt.startsWith('0001') ? <When iso={incident.containedAt}/> : 'Not yet'], ['Observed graph', incident.observedGraphVersion ?? '—']]}/>
      <h4>Current permissions</h4>{access?.powers?.length ? <ul className="plain-list">{access.powers.map(p => <li key={`${p.nodeId}${p.action}`}><span className="power-action">{p.action}</span> <EntityLink id={p.nodeId}/></li>)}</ul> : <p className="muted">{access ? 'No effective access remains.' : 'Loading…'}</p>}
      {!!access?.controlledIdentities?.length && <><h4>Controllable identities</h4><ul className="plain-list">{access.controlledIdentities.map(id => <li key={id}><EntityLink id={id}/></li>)}</ul></>}
      <h4>Routes to critical assets</h4>{routes === null ? <p className="muted">Tracing…</p> : routes.length ? routes.map((r, i) => <RoutePath key={i} route={r}/>) : <p className="muted">No route to a tier-0 asset remains.</p>}
      {!!incident.residualRoutes?.length && <><h4>Residual routes recorded at containment</h4>{incident.residualRoutes.map((r, i) => <RoutePath key={i} route={r}/>)}</>}
      <h4>Actions taken</h4>{incident.actionsTaken?.length ? <ol className="timeline">{incident.actionsTaken.map((a, i) => <li key={i}><span>{a}</span></li>)}</ol> : <p className="muted">No containment action has executed yet.</p>}
      {incident.containmentPlan && <><h4>Plan</h4><p className="muted">{incident.containmentPlan.recommendedRevocations?.length ?? 0} actions · {incident.containmentPlan.severedTier0RoutesCount ?? 0} tier-0 routes severed · plan {short(incident.containmentPlan.planId)}</p></>}
      <h4>Related access changes</h4>{related.length ? <ul className="plain-list">{related.map(c => <li key={c.requestId}><button type="button" className="entity-link" onClick={() => go('Changes', { requestId: c.requestId })}>{c.kind === 'ROLE_REVOKE' ? 'Revoke' : 'Assign'} {c.requestedAccess}</button> · {c.status}</li>)}</ul> : <p className="muted">None in your visible scope.</p>}
      <h4>Incident timeline</h4>{timeline.length ? <ol className="timeline">{timeline.map(e => <li key={e.sequenceNumber}><span>{e.eventType}</span><When iso={e.recordedAt}/><code>#{e.sequenceNumber}</code></li>)}</ol> : <p className="muted">No ledger events recorded for this incident yet.</p>}
      <button type="button" className="entity-link" onClick={() => go('Audit', { incidentId })}>Open in Audit</button></>}
  </Inspector>;
}
