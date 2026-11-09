import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { Fingerprint, MessageSquare, PauseCircle, XCircle } from 'lucide-react';
import { ApiError, approve, mutation, request, rpc, type Change } from '../lib/api';
import { verifyEnvelope, verifyImpact, type ApprovalEnvelope } from '../lib/envelope';
import { auditEvents, decisionEvidence, decodeJSON, parsePolicyRules, reach, short, type Evidence, type LedgerEvent, type Reach } from './api';
import { nodeName, useConsole } from './context';
import { AssessedImpactView, boundImpactView, ImpactView, type BoundImpact, type Impact } from './impact';
import { Chips, DataTable, Empty, EntityLink, Inspector, KeyValues, StatusBadge, When, type Column } from './ui';

type Review = { change: Change; envelope: ApprovalEnvelope; impact: Impact; approvers: string[] };
const filters = ['All', 'Needs my action', 'Awaiting approval', 'Allowed', 'Held', 'Rejected', 'Executed', 'Expired', 'Revoked'] as const;
type Filter = typeof filters[number];
function matches(c: Change, f: Filter, actor: string): boolean {
  switch (f) {
    case 'All': return true;
    case 'Needs my action': return c.status === 'AWAITING_APPROVAL' && c.requestedBy !== actor && c.targetIdentity !== actor;
    case 'Awaiting approval': return c.status === 'AWAITING_APPROVAL';
    case 'Allowed': return c.status === 'ALLOWED';
    case 'Held': return c.status === 'HELD';
    case 'Rejected': return c.status === 'REJECTED';
    case 'Executed': return c.status === 'EXECUTED';
    case 'Expired': return c.status === 'EXPIRED';
    case 'Revoked': return c.status === 'REVOKED' || c.expiryStatus === 'REVOKED';
  }
}
const statusLine = (c: Change) => c.status === 'EXECUTED' ? 'Target change and independent read-back verified by core.' : c.status === 'EXECUTING' ? 'Awaiting independently verified target evidence; access is not confirmed yet.'
  : c.status === 'AWAITING_APPROVAL' ? 'Waiting for the required independent approvals.' : c.status === 'REVOKING' ? 'Target expiry revocation in progress.'
  : c.status === 'REVOKED' ? 'Time-bounded grant expired and verified revoked at target.' : c.status === 'HELD' ? 'Held: the decision needs more context or the situation changed.' : '';

export function ChangesTab() {
  const { tenantId, actor, changes, busy, work, notify, reloadChanges, focus, bootstrap } = useConsole();
  const [text, setText] = useState('');
  const [filter, setFilter] = useState<Filter>('All');
  const [selected, setSelected] = useState<string | null>(null);
  const [review, setReview] = useState<Review | null>(null);
  useEffect(() => { if (focus?.requestId) { setSelected(focus.requestId); setText(''); setFilter('All'); } if (focus?.filter) setFilter(focus.filter as Filter); }, [focus]);
  const counts = useMemo(() => Object.fromEntries(filters.map(f => [f, changes.filter(c => matches(c, f, actor)).length])) as Record<Filter, number>, [changes, actor]);
  const visible = changes.filter(c => matches(c, filter, actor) && `${c.requestId} ${c.targetIdentity} ${c.requestedAccess} ${c.status} ${c.requestedBy ?? ''}`.toLowerCase().includes(text.trim().toLowerCase()));
  const current = changes.find(c => c.requestId === selected) ?? null;

  async function inspect(c: Change) {
    const { request: fresh } = await rpc<{ request: Change }>('ChangeService', 'GetChange', { tenantId, requestId: c.requestId });
    const envelope = await verifyEnvelope(fresh, tenantId);
    const r = await request<{ request_id: string; revision: number; change_digest: string; impact: BoundImpact; approvers: string[] }>(`/api/console/approval-review?request_id=${encodeURIComponent(fresh.requestId)}`);
    if (r.request_id !== fresh.requestId || String(r.revision) !== fresh.revision || r.change_digest !== fresh.changeDigest) throw new Error('Request changed since review; refresh again');
    await verifyImpact(r.impact, envelope);
    setSelected(c.requestId);
    setReview({ change: fresh, envelope, impact: boundImpactView(r.impact), approvers: r.approvers });
  }
  function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault(); const element = e.currentTarget; const v = Object.fromEntries(new FormData(element)) as Record<string, string>;
    void work(async () => {
      const duration = parseInt(v.DurationSeconds || '0', 10); const emergency = v.Emergency === 'true';
      const r = await rpc<{ request?: Change }>('ChangeService', 'SubmitChange', { tenantId, kind: v.Kind, targetIdentity: v.Identity, requestedAccess: v.Access, requestedBy: actor,
        ...(duration > 0 ? { durationSeconds: duration } : {}), ...(emergency ? { emergency: true } : {}), justification: v.Justification, mutation: mutation() });
      if (r.request) notify(`Request ${r.request.requestId} submitted. Assessment and execution status update automatically.`);
      await reloadChanges(); element.reset();
    });
  }
  const columns: Column<Change>[] = [
    { key: 'request', label: 'Request', width: '13%', sort: c => c.createdAt ?? '', render: c => <><code title={c.requestId}>{short(c.requestId)}</code><span className="cell-sub">{c.kind === 'ROLE_REVOKE' ? 'Revoke role' : c.kind === 'ROLE_ASSIGN' ? 'Assign role' : c.kind}{c.emergency && <span className="emergency-badge">EMERGENCY</span>}</span></> },
    { key: 'target', label: 'Target · access', width: '23%', sort: c => c.targetIdentity, render: c => <><EntityLink id={c.targetIdentity}/><span className="cell-sub"><EntityLink id={c.requestedAccess}/></span></> },
    { key: 'requester', label: 'Requester', width: '14%', sort: c => c.requestedBy ?? '', render: c => <EntityLink id={c.requestedBy}/> },
    { key: 'status', label: 'Decision · status', width: '17%', sort: c => c.status, render: c => <><strong className="status-badge" data-status={c.status} data-testid="change-status">{c.status}</strong>{c.timeLimitSeconds && c.timeLimitSeconds > 0 ? <span className="cell-sub" data-testid="grant-expiry">Grant {c.timeLimitSeconds}s · {c.expiryStatus || 'SCHEDULED'}</span> : null}</> },
    { key: 'approvers', label: 'Required approvers', width: '13%', sort: c => c.requiredQuorum ?? 0, render: c => (c.requiredQuorum ?? 0) > 0 ? <>{c.requiredQuorum} of {c.requiredApproverGroups?.map(g => nodeName(bootstrap, g)).join(', ') || 'reviewers'}</> : <span className="muted">None</span> },
    { key: 'submitted', label: 'Submitted', width: '9%', sort: c => c.createdAt ?? '', render: c => <When iso={c.createdAt}/> },
    { key: 'action', label: 'Action', width: '13%', render: c => c.status !== 'AWAITING_APPROVAL' ? <span className="muted">—</span> : <button type="button" className="row-action" disabled={busy || !c.changeDigest || c.status !== 'AWAITING_APPROVAL' || c.requestedBy === actor} title={c.requestedBy === actor ? 'You requested this change; an independent reviewer must approve it.' : undefined} onClick={e => { e.stopPropagation(); void work(() => inspect(c)); }}>Review exact change</button> },
  ];
  return <>
    <section><h3>Request an access change</h3><p>Choose an identity and exact role. The server assesses reachability and selects independent reviewers.</p>
      <form onSubmit={submit}><label>Kind<select name="Kind"><option>ROLE_ASSIGN</option><option>ROLE_REVOKE</option></select></label>
        {['Identity', 'Access', 'Justification'].map(name => <label key={name}>{name}<input name={name} required autoComplete="off"/></label>)}
        <label>Duration limit in seconds (0 for permanent)<input name="DurationSeconds" type="number" defaultValue="0" min="0" max="86400"/></label>
        <label>Emergency request?<select name="Emergency"><option value="false">No (standard review)</option><option value="true">Yes (emergency review)</option></select></label>
        <button disabled={busy}>Submit for assessment</button></form></section>
    <div className={current ? 'workspace-split has-inspector' : 'workspace-split'}>
      <div className="workspace-main">
        <div className="table-toolbar"><label className="request-filter">Filter this page by request, identity or role<input value={text} onChange={e => setText(e.target.value)} type="search" placeholder="Paste a request ID or type a role"/></label></div>
        <Chips label="Filter by status" options={filters} value={filter} onChange={setFilter} counts={counts}/>
        <DataTable columns={current ? columns.filter(c => c.key !== 'requester' && c.key !== 'approvers') : columns} rows={visible} rowKey={c => c.requestId} rowTestId={c => `change-${c.requestId}`} selected={selected ?? undefined} onRow={c => { setSelected(c.requestId); if (review?.change.requestId !== c.requestId) setReview(null); }} pageSize={25}
          empty={changes.length ? <Empty title="No requests match.">Clear the search or choose another status filter.</Empty> : <Empty title="No requests in this authorized page.">Requests you submit, and those you are asked to review, appear here.</Empty>}/>
      </div>
      {current && <ChangeInspector change={current} review={review?.change.requestId === current.requestId ? review : null} onReview={() => void work(() => inspect(current))} onClose={() => { setSelected(null); setReview(null); }}
        onApprove={() => void work(async () => { if (!review) return; const r = await approve(review.change, tenantId) as { request: Change }; setReview(null); await reloadChanges(); notify(`Approval recorded. Server state: ${r.request.status}. Required independent quorum: ${r.request.requiredQuorum ?? 0}.`); })}/>}
    </div>
  </>;
}

function ChangeInspector({ change: c, review, onReview, onApprove, onClose }: { change: Change; review: Review | null; onReview: () => void; onApprove: () => void; onClose: () => void }) {
  const { tenantId, actor, busy, work, notify, reloadChanges, organization, go, bootstrap } = useConsole();
  const [evidence, setEvidence] = useState<Evidence | null>(null);
  const [evidenceState, setEvidenceState] = useState<'loading' | 'restricted' | 'ready' | 'missing'>('loading');
  const [timeline, setTimeline] = useState<LedgerEvent[] | null>(null);
  const [current, setCurrent] = useState<Reach | null>(null);
  useEffect(() => {
    let live = true; setEvidence(null); setEvidenceState('loading'); setTimeline(null); setCurrent(null);
    void decisionEvidence(tenantId, c.requestId).then(e => { if (live) { setEvidence(e); setEvidenceState(e ? 'ready' : 'missing'); } }).catch(e => { if (live) setEvidenceState(e instanceof ApiError && e.status === 403 ? 'restricted' : 'missing'); });
    if (organization) void auditEvents(tenantId, { requestId: c.requestId, pageSize: 50 }).then(r => { if (live) setTimeline(r.events ?? []); }).catch(() => undefined);
    void reach(tenantId, c.targetIdentity).then(r => { if (live) setCurrent(r); }).catch(() => undefined);
    return () => { live = false; };
  }, [tenantId, c.requestId, c.revision, c.targetIdentity, organization]);
  const decision = evidence?.change.decision;
  const rules = parsePolicyRules(evidence?.bundle?.modules['change.rego']);
  const rule = rules.find(r => decision && r.outcome === decision.outcome && r.reasons.join() === decision.reasons.join());
  const approvals = (timeline ?? []).filter(e => e.eventType === 'ChangeApprovalRecorded');
  const approvalActors = approvals.map(e => decodeJSON<{ actor_id?: string; payload?: { facts?: { approval?: { approver?: string } } } }>(e.canonicalContent)).map(x => x?.payload?.facts?.approval?.approver).filter(Boolean) as string[];
  const controlled = (evidence?.graph?.edges ?? []).filter(e => e.kind === 'CAN_ADMINISTER' && e.source === c.requestedBy).map(e => e.target);
  const eligible = (evidence?.change.facts.owners ?? []).filter(id => id !== c.requestedBy && !controlled.includes(id));
  const target = evidence?.change.impact.affected.find(a => a.identityId === c.targetIdentity);
  const canReview = !!c.changeDigest && c.status === 'AWAITING_APPROVAL' && c.requestedBy !== actor;
  const act = (method: 'HoldChange' | 'RejectChange' | 'RequestMoreInfo') => (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault(); const element = e.currentTarget; const v = Object.fromEntries(new FormData(element)) as Record<string, string>;
    void work(async () => {
      await rpc('ChangeService', method, { tenantId, requestId: c.requestId, ...(method === 'RequestMoreInfo' ? { question: v.Text } : { reason: v.Text }), mutation: mutation(c.revision) });
      notify(method === 'HoldChange' ? 'Change held.' : method === 'RejectChange' ? 'Change rejected.' : 'Question sent to the requester.'); await reloadChanges(); element.reset();
    });
  };
  return <Inspector eyebrow={`CHANGE ${short(c.requestId)} · REVISION ${c.revision}`} title={<>{c.kind === 'ROLE_REVOKE' ? 'Revoke' : 'Assign'} {nodeName(bootstrap, c.requestedAccess)}</>} onClose={onClose} testId="change-inspector">
    <p className="inspector-id"><StatusBadge status={c.status}/>{c.emergency && <span className="emergency-badge">EMERGENCY</span>}<span className="muted">{statusLine(c)}</span></p>
    {review && <section className="review" data-testid="approval-review"><h3>Review the exact change</h3><p>Recorded independent approvals: {review.approvers.length} / {review.change.requiredQuorum ?? 0}{review.approvers.length > 0 && ` (${review.approvers.join(', ')})`}</p>
      <dl><dt>Identity</dt><dd>{review.envelope.intent.target_identity}</dd><dt>Action / role</dt><dd>{review.envelope.intent.kind} / {review.envelope.intent.requested_access}</dd><dt>Requester</dt><dd>{review.envelope.authenticated_requester}</dd><dt>Approval expires</dt><dd>{review.envelope.expires_at}</dd><dt>Required independent reviewers</dt><dd>{review.change.requiredQuorum} | {review.change.requiredApproverGroups?.join(', ')}</dd></dl>
      <ImpactView impact={review.impact}/><p className="notice">Canonical envelope digest verified in this browser. The passkey challenge is checked against this digest and your signed-in actor.</p><code data-testid="verified-envelope-digest">{review.change.changeDigest}</code>
      <details><summary>Exact canonical envelope</summary><pre className="data" tabIndex={0}>{JSON.stringify(review.envelope, null, 2)}</pre></details>
      <div className="inspector-actions"><button className="button-dark" disabled={busy || review.change.status !== 'AWAITING_APPROVAL'} onClick={onApprove}><Fingerprint size={14}/> Approve reviewed change with passkey</button><button disabled={busy} onClick={onClose}>Close review</button></div></section>}
    {!review && <div className="inspector-actions">{canReview ? <button className="button-dark" disabled={busy} onClick={onReview}><Fingerprint size={14}/> Review and approve</button> : <span className="muted">{c.requestedBy === actor && c.status === 'AWAITING_APPROVAL' ? 'You requested this change. RATCHET refuses self-approval; an independent reviewer must approve it.' : c.status === 'AWAITING_APPROVAL' ? '' : 'No approval is pending for this request.'}</span>}</div>}
    <h4>Request details</h4>
    <KeyValues rows={[['Request ID', <code>{c.requestId}</code>], ['Requester', <EntityLink id={c.requestedBy}/>], ['Target identity', <EntityLink id={c.targetIdentity}/>], ['Requested role', <EntityLink id={c.requestedAccess}/>],
      ['Justification', c.justification || '—'], ['Duration', c.timeLimitSeconds ? `${c.timeLimitSeconds}s${c.grantExpiresAt && !c.grantExpiresAt.startsWith('0001') ? ` · expires ${c.grantExpiresAt}` : ''}` : 'Permanent'], ['Emergency', c.emergency ? 'Yes' : 'No'],
      ['Submitted', <When iso={c.createdAt}/>], ['Last update', <When iso={c.updatedAt}/>]]}/>
    <h4>Decision explanation</h4>
    {evidenceState === 'loading' && <p className="muted">Loading decision evidence…</p>}
    {evidenceState === 'restricted' && <><KeyValues rows={[['Decision reasons', c.decisionReasons?.join(' · ') || '—'], ['Graph version', c.graphVersion ?? '—'], ['Policy bundle', c.policyBundleHash ? <code>{short(c.policyBundleHash, 16)}</code> : '—']]}/><p className="inline-note">The full decision evidence is available to independent reviewers and investigators.</p></>}
    {evidence && decision && <KeyValues rows={[['Decision', <span className="decision-badge" data-decision={decision.outcome}>{decision.outcome.replace('_', ' ')}</span>], ['Reasons', decision.reasons.join(' · ')],
      ['Policy rule', rule ? <button type="button" className="entity-link" onClick={() => go('Security policy')}>Rule {rule.order} of change.rego v{evidence.bundle?.version}</button> : '—'], ['Evaluator', evidence.change.facts.evaluator ?? '—'],
      ['Graph version', String(evidence.change.graphVersion ?? '—')], ['Policy bundle hash', <code>{short(evidence.change.policyBundleHash, 20)}</code>], ['Assessment event', `#${evidence.eventSequence} · ${short(evidence.eventHash, 16)}`]]}/>}
    <h4>Approval requirements</h4>
    <KeyValues rows={[['Required quorum', (c.requiredQuorum ?? 0) > 0 ? `${c.requiredQuorum} independent approval${(c.requiredQuorum ?? 0) > 1 ? 's' : ''}` : 'No approval required'], ['Approver group', c.requiredApproverGroups?.map(g => nodeName(bootstrap, g)).join(', ') || '—'],
      ['Approvals recorded', timeline ? `${approvals.length} of ${c.requiredQuorum ?? 0}${approvalActors.length ? ` (${approvalActors.join(', ')})` : ''}` : organization ? 'Loading…' : 'Visible to investigators']]}/>
    {evidence && <ul className="plain-list approver-list">
      {eligible.map(id => <li key={id}><span className="eligibility" data-eligible="true">Eligible</span><EntityLink id={id}/></li>)}
      {c.requestedBy && <li><span className="eligibility" data-eligible="false">Excluded</span><EntityLink id={c.requestedBy}/> <span className="muted">requester — cannot approve their own change</span></li>}
      {controlled.map(id => <li key={id}><span className="eligibility" data-eligible="false">Excluded</span><EntityLink id={id}/> <span className="muted">controlled by the requester</span></li>)}
    </ul>}
    <h4>Current versus requested access</h4>
    <div className="compare-columns"><div><p className="eyebrow">CURRENT ACCESS</p>{current?.powers?.length ? <ul className="plain-list">{current.powers.map(p => <li key={`${p.nodeId}${p.action}`}><span className="power-action">{p.action}</span> <EntityLink id={p.nodeId}/></li>)}</ul> : <p className="muted">{current ? 'No effective powers.' : 'Not visible to your account.'}</p>}</div>
      <div><p className="eyebrow">ADDED BY THIS CHANGE</p>{target?.newPowers.length ? <ul className="plain-list">{target.newPowers.map(p => <li key={`${p.nodeId}${p.action}`}><span className="power-action is-new">+ {p.action}</span> <EntityLink id={p.nodeId}/></li>)}</ul> : <p className="muted">{evidence ? 'No new powers for the target.' : 'Shown with decision evidence.'}</p>}</div></div>
    <h4>Impact analysis</h4>
    {evidence ? <AssessedImpactView impact={evidence.change.impact}/> : review ? <ImpactView impact={review.impact}/> : <p className="muted">The assessed impact is shown to independent reviewers. Use Impact to simulate changes to your own access.</p>}
    {canReview || c.status === 'AWAITING_APPROVAL' ? <details><summary>Decision actions: hold, reject or ask for context</summary>
      <form onSubmit={act('HoldChange')}><label>Reason to hold<input name="Text" required autoComplete="off"/></label><button disabled={busy}><PauseCircle size={13}/> Hold</button></form>
      <form onSubmit={act('RejectChange')}><label>Reason to reject<input name="Text" required autoComplete="off"/></label><button disabled={busy}><XCircle size={13}/> Reject</button></form>
      <form onSubmit={act('RequestMoreInfo')}><label>Question for the requester<input name="Text" required autoComplete="off"/></label><button disabled={busy}><MessageSquare size={13}/> Request more information</button></form>
    </details> : null}
    {timeline && <><h4>Recorded timeline</h4>{timeline.length ? <ol className="timeline">{timeline.map(e => <li key={e.sequenceNumber}><span>{e.eventType.replace(/^Change/, '')}</span><When iso={e.recordedAt}/><code>#{e.sequenceNumber}</code></li>)}</ol> : <p className="muted">No ledger events yet.</p>}
      <button type="button" className="entity-link" onClick={() => go('Audit', { requestId: c.requestId })}>Open in Audit</button></>}
  </Inspector>;
}
