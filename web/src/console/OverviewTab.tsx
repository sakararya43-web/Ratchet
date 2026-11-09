import { ArrowRight, ArrowUpRight, Fingerprint, GitPullRequest, Network, ScanLine, Siren } from 'lucide-react';
import type { Change } from '../lib/api';
import { Mechanism } from '../Brand';
import { decisionOf, short, type Attention } from './api';
import { nodeName, useConsole } from './context';
import { DecisionBadge, Empty, EntityLink, StatusBadge, When } from './ui';

type QueueItem = { id: string; kind: 'change' | 'incident'; who?: string; what: string; type: string; status: string; at?: string; reason: string };

export function OverviewTab({ result }: { result: unknown }) {
  const { bootstrap, changes, go, busy, actor } = useConsole();
  const data = (result ?? {}) as Attention;
  const items = data.attentionItems ?? [];
  const byId = new Map(changes.map(c => [c.requestId, c]));
  for (const c of data.pendingRequests ?? []) byId.set(c.requestId, { ...byId.get(c.requestId), ...c });
  const queue: QueueItem[] = [];
  const seen = new Set<string>();
  for (const item of items) {
    const c = byId.get(item.entityId ?? item.itemId);
    if (item.itemType === 'ACTIVE_INCIDENT') { queue.push({ id: item.entityId ?? item.itemId, kind: 'incident', what: item.title, type: 'Incident', status: item.severity?.toUpperCase() ?? 'OPEN', at: item.createdAt, reason: item.description ?? '' }); continue; }
    seen.add(item.entityId ?? item.itemId);
    queue.push({ id: item.entityId ?? item.itemId, kind: 'change', who: c?.targetIdentity, what: c ? `${c.kind === 'ROLE_REVOKE' ? 'Revoke' : 'Assign'} ${nodeName(bootstrap, c.requestedAccess)}` : item.title,
      type: c?.kind ?? item.itemType.replace(/_/g, ' '), status: c?.status ?? item.title.split(':')[0], at: item.createdAt ?? c?.createdAt, reason: item.description || c?.decisionReasons?.join(' · ') || '' });
  }
  for (const c of changes.filter(c => c.status === 'AWAITING_APPROVAL' && !seen.has(c.requestId))) {
    queue.push({ id: c.requestId, kind: 'change', who: c.targetIdentity, what: `${c.kind === 'ROLE_REVOKE' ? 'Revoke' : 'Assign'} ${nodeName(bootstrap, c.requestedAccess)}`, type: c.kind, status: c.status, at: c.createdAt,
      reason: c.requestedBy === actor ? `Waiting for ${c.requiredQuorum ?? 0} independent approval${(c.requiredQuorum ?? 0) === 1 ? '' : 's'}` : (c.decisionReasons?.join(' · ') || 'Independent approval required') });
  }
  for (const incident of data.activeIncidents ?? []) if (!queue.some(q => q.id === incident.incidentId)) queue.push({ id: incident.incidentId, kind: 'incident', who: incident.affectedIdentity, what: incident.title ?? 'Security incident', type: incident.rootCauseType ?? 'Incident', status: incident.status ?? 'OPEN', at: incident.openedAt, reason: `Severity ${incident.severity ?? 'unknown'}` });
  queue.sort((a, b) => (b.at ?? '').localeCompare(a.at ?? ''));
  const awaiting = changes.filter(c => c.status === 'AWAITING_APPROVAL').length;
  const held = changes.filter(c => c.status === 'HELD').length;
  const rejected = changes.filter(c => c.status === 'REJECTED').length;
  const gated = changes.filter(c => (c.requiredQuorum ?? 0) >= 2).length;
  const activity = changes.flatMap(c => [{ at: c.createdAt, c, label: 'submitted' }, ...(c.updatedAt && c.updatedAt !== c.createdAt ? [{ at: c.updatedAt, c, label: c.status.toLowerCase().replace(/_/g, ' ') }] : [])])
    .filter(a => a.at).sort((a, b) => (b.at ?? '').localeCompare(a.at ?? '')).slice(0, 12);
  const decisions = [...changes].sort((a, b) => (b.createdAt ?? '').localeCompare(a.createdAt ?? '')).slice(0, 8);
  const open = (q: QueueItem) => q.kind === 'incident' ? go('Incidents', { incidentId: q.id }) : go('Changes', { requestId: q.id });
  return <>
    <div className="overview-stats">
      <button type="button" className="stat" onClick={() => go('Infrastructure')}><span>Observed nodes</span><strong>{bootstrap?.nodes.length ?? '—'}</strong><Network size={18}/></button>
      <button type="button" className="stat" onClick={() => go('Infrastructure')}><span>Relationships</span><strong>{bootstrap?.edges.length ?? '—'}</strong><GitPullRequest size={18}/></button>
      <button type="button" className="stat" onClick={() => go('Changes', { filter: 'Awaiting approval' })}><span>Awaiting approval</span><strong>{awaiting}</strong><ScanLine size={18}/></button>
      <button type="button" className="stat" onClick={() => document.getElementById('attention-queue')?.scrollIntoView({ behavior: 'smooth' })}><span>Attention items</span><strong>{queue.length}</strong><Siren size={18}/></button>
    </div>
    <section className="intro"><div><p className="eyebrow">CONSEQUENCE-DRIVEN ACCESS REVIEW</p><h3>Know what changes.<br/><span className="serif-word">Before it changes.</span></h3><p>Map the impact. Collect independent approvals.<br/>Verify the outcome at the target.</p><button disabled={busy} onClick={() => go('Changes')}>Open access changes <ArrowUpRight size={18}/></button></div><div className="intro-mechanism"><Mechanism/></div></section>
    <section id="attention-queue"><div className="section-title"><h3>Attention queue</h3><span className="small-count">{queue.length}</span></div>
      {queue.length ? <div className="queue">{queue.slice(0, 10).map(q => <button type="button" key={`${q.kind}${q.id}`} className="queue-item" onClick={() => open(q)}>
        <span className="queue-id"><code>{short(q.id)}</code><small>{q.type.replace(/_/g, ' ')}</small></span>
        <span className="queue-what"><strong>{q.what}</strong>{q.who && <small>{nodeName(bootstrap, q.who)}</small>}</span>
        <span>{q.kind === 'change' ? <StatusBadge status={q.status}/> : <span className="status-badge" data-status="HELD">{q.status}</span>}</span>
        <span className="queue-reason">{q.reason}</span><span className="queue-age"><When iso={q.at}/></span><ArrowRight size={14}/></button>)}</div>
        : <Empty title="Nothing needs your attention.">No pending approvals, held requests or active incidents are visible to this account.</Empty>}
    </section>
    <div className="overview-grid">
      <section><div className="section-title"><h3>Operational activity</h3><span className="small-count">{activity.length}</span></div>
        {activity.length ? <ol className="activity">{activity.map((a, i) => <li key={i}><span className="activity-dot" data-status={a.c.status}/><div><p><EntityLink id={a.c.targetIdentity}/> · {a.c.kind === 'ROLE_REVOKE' ? 'revoke' : 'assign'} <EntityLink id={a.c.requestedAccess}/> <strong>{a.label}</strong></p><small><When iso={a.at}/> · <button type="button" className="entity-link" onClick={() => go('Changes', { requestId: a.c.requestId })}>{short(a.c.requestId)}</button></small></div></li>)}</ol>
          : <Empty title="No recent activity.">Submitted, approved, executed and revoked changes appear here as they happen.</Empty>}
      </section>
      <section><div className="section-title"><h3>Recent security decisions</h3></div>
        <p className="boundaries"><span><strong>{held}</strong> held</span><span><strong>{rejected}</strong> rejected</span><span><strong>{gated}</strong> tier-0 escalations gated by two leads</span></p>
        {decisions.length ? <ul className="decisions">{decisions.map((c: Change) => <li key={c.requestId}><button type="button" onClick={() => go('Changes', { requestId: c.requestId })}><DecisionBadge decision={decisionOf(c)}/><span><strong>{c.kind === 'ROLE_REVOKE' ? 'Revoke' : 'Assign'} {nodeName(bootstrap, c.requestedAccess)}</strong><small>{c.decisionReasons?.join(' · ') || 'No decision reasons recorded'}</small></span><When iso={c.createdAt}/></button></li>)}</ul>
          : <Empty title="No decisions yet.">Each request is assessed against the signed policy; its decision and reasons appear here.</Empty>}
      </section>
    </div>
    <section className="workflow-strip"><ol className="journey"><li><strong><span>01</span> Assess the impact</strong><span>Trace newly reachable resources and critical paths.</span></li><li><strong><span>02</span> Review independently</strong><span>Approve the exact change with a bound passkey.</span></li><li><strong><span>03</span> Verify the outcome</strong><span>Confirm independent target read-back.</span></li></ol><button className="passkey-shortcut" disabled={busy} onClick={() => go('Passkeys')}><Fingerprint size={17}/> Manage your passkeys <ArrowRight size={15}/></button></section>
  </>;
}
