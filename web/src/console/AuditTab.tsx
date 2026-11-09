import { useMemo, useState, type FormEvent } from 'react';
import { Download, ShieldAlert, ShieldCheck } from 'lucide-react';
import { decode } from '../lib/api';
import { decodeJSON, exportChain, short, type LedgerEvent } from './api';
import { useConsole } from './context';
import { Chips, EntityLink, Inspector, KeyValues, When } from './ui';

const categories = ['All', 'Approvals', 'Rejections', 'Access grants', 'Revocations', 'Executions', 'Policy changes', 'Containment'] as const;
type Category = typeof categories[number];
function category(event: LedgerEvent, payload: Record<string, unknown> | null): Category[] {
  const t = event.eventType; const out: Category[] = [];
  if (t.includes('Approval') || t === 'ChangeApproved') out.push('Approvals');
  if (t.includes('Rejected') || t.includes('Held')) out.push('Rejections');
  if (t.includes('Executed') || t.includes('Executing') || t.includes('Verified')) out.push('Executions');
  if (t.startsWith('Policy') || t.startsWith('Authority')) out.push('Policy changes');
  if (t.startsWith('Containment') || t.startsWith('Incident')) out.push('Containment');
  const kind = JSON.stringify(payload ?? {});
  if (t.startsWith('Change') && kind.includes('ROLE_REVOKE')) out.push('Revocations');
  if (t.startsWith('Change') && kind.includes('ROLE_ASSIGN') && t.includes('Executed')) out.push('Access grants');
  return out;
}
type Verification = { ok: boolean; checked: number; endHash: string; expectedEnd: string; checkpoint?: string; failure?: string; at: string };
async function sha256(parts: Uint8Array[]): Promise<string> {
  const length = parts.reduce((n, p) => n + p.length, 0); const all = new Uint8Array(length); let offset = 0;
  for (const p of parts) { all.set(p, offset); offset += p.length; }
  return [...new Uint8Array(await crypto.subtle.digest('SHA-256', all))].map(b => b.toString(16).padStart(2, '0')).join('');
}
const fromHex = (h: string) => Uint8Array.from(h.match(/../g) ?? [], b => parseInt(b, 16));

export function AuditTab({ result, onSearch, filter }: { result: unknown; onSearch: (requestId: string) => Promise<void>; filter: string }) {
  const { tenantId, busy, work, go } = useConsole();
  const events = ((result ?? {}) as { events?: LedgerEvent[] }).events ?? [];
  const [cat, setCat] = useState<Category>('All');
  const [selected, setSelected] = useState<LedgerEvent | null>(null);
  const [verification, setVerification] = useState<Verification | null>(null);
  const [progress, setProgress] = useState('');
  const decoded = useMemo(() => new Map(events.map(e => [e.sequenceNumber, e.eventPayloadJson ? (() => { try { return JSON.parse(e.eventPayloadJson!) as Record<string, unknown>; } catch { return null; } })() : null])), [events]);
  const counts = Object.fromEntries(categories.map(c => [c, c === 'All' ? events.length : events.filter(e => category(e, decoded.get(e.sequenceNumber) ?? null).includes(c)).length])) as Record<Category, number>;
  const rows = events.filter(e => cat === 'All' || category(e, decoded.get(e.sequenceNumber) ?? null).includes(cat));
  async function verify() {
    let pageToken = '', previous = '00'.repeat(32), checked = 0, expectedEnd = '', checkpoint: string | undefined;
    do {
      const page = await exportChain(tenantId, pageToken);
      for (const event of page.chain ?? []) {
        if (event.previousEventHash !== previous) { setVerification({ ok: false, checked, endHash: previous, expectedEnd, failure: `Event #${event.sequenceNumber} links to ${short(event.previousEventHash, 12)} but the previous hash is ${short(previous, 12)}`, at: new Date().toISOString() }); return; }
        const hash = await sha256([fromHex(previous), decode(event.canonicalContent ?? '')]);
        if (hash !== event.eventHash) { setVerification({ ok: false, checked, endHash: previous, expectedEnd, failure: `Event #${event.sequenceNumber} content does not hash to its recorded hash`, at: new Date().toISOString() }); return; }
        previous = hash; checked++;
      }
      setProgress(`${checked} events verified…`);
      pageToken = page.nextPageToken ?? ''; expectedEnd = page.snapshotEndHash ?? expectedEnd; checkpoint = page.latestCheckpointDigest || checkpoint;
    } while (pageToken);
    setProgress('');
    setVerification({ ok: previous === expectedEnd, checked, endHash: previous, expectedEnd, checkpoint, failure: previous === expectedEnd ? undefined : 'The recomputed chain end does not match the server snapshot end hash', at: new Date().toISOString() });
  }
  function exportRecords() {
    const blob = new Blob([JSON.stringify({ exportedAt: new Date().toISOString(), tenantId, filter: filter || null, verification, events }, null, 2)], { type: 'application/json' });
    const link = document.createElement('a'); link.href = URL.createObjectURL(blob); link.download = `ratchet-audit-${tenantId}-${Date.now()}.json`; link.click(); URL.revokeObjectURL(link.href);
  }
  return <div className={selected ? 'workspace-split has-inspector' : 'workspace-split'}><div className="workspace-main">
    <section className="ledger-verify"><div className="section-title"><h3>Ledger integrity</h3><span className="small-count">append-only · SHA-256 hash chain</span></div>
      <p>Every event links to the one before it: hash = SHA-256(previous hash ‖ canonical content). This browser recomputes the whole chain from the exported canonical bytes.</p>
      <div className="inspector-actions"><button type="button" className="button-dark" disabled={busy} onClick={() => void work(verify)}><ShieldCheck size={14}/> Verify audit chain</button><button type="button" disabled={!events.length && !verification} onClick={exportRecords}><Download size={13}/> Export records and verification</button>{progress && <span className="muted">{progress}</span>}</div>
      {verification && <div className={verification.ok ? 'verify-result is-ok' : 'verify-result is-failed'} data-testid="chain-verification">{verification.ok ? <ShieldCheck size={22}/> : <ShieldAlert size={22}/>}
        <div><strong>{verification.ok ? 'Chain integrity verified' : 'Verification failed'}</strong><span>{verification.checked} events verified{verification.ok ? ' · every link and hash recomputed in this browser' : ''}</span>{verification.failure && <span className="verify-failure">{verification.failure}</span>}</div>
        <KeyValues rows={[['Recomputed end hash', <code>{short(verification.endHash, 24)}</code>], ['Server snapshot end', <code>{short(verification.expectedEnd, 24)}</code>], ['Latest checkpoint', verification.checkpoint ? <code>{short(verification.checkpoint, 24)}</code> : 'No signed checkpoint yet'],
          ['Approval signatures', 'Verified by the core at submission; independently re-verifiable offline with ratchetctl audit verify'], ['Verified', <When iso={verification.at}/>]]}/></div>}
    </section>
    <section><h3>Permanent audit trail</h3><form onSubmit={(e: FormEvent<HTMLFormElement>) => { e.preventDefault(); const element = e.currentTarget; const v = Object.fromEntries(new FormData(element)) as Record<string, string>; void work(async () => { await onSearch(v.Request.trim()); element.reset(); }); }}><label>Request<input name="Request" required autoComplete="off"/></label><button disabled={busy}>Find request audit</button></form>
      {filter && <p className="muted">Showing events for request <code>{filter}</code>. <button type="button" className="entity-link" onClick={() => void work(() => onSearch(''))}>Show all events</button></p>}
      <Chips label="Event category" options={categories} value={cat} onChange={setCat} counts={counts}/>
      <table><thead><tr><th>Sequence</th><th>Event</th><th>Stream</th><th>Recorded</th><th>Event hash</th></tr></thead><tbody>{rows.map(event => <tr key={event.sequenceNumber} className={`is-clickable${selected?.sequenceNumber === event.sequenceNumber ? ' is-selected' : ''}`} onClick={() => setSelected(event)}><td>{event.sequenceNumber}</td><td>{event.eventType}</td><td>{event.streamId}</td><td>{event.recordedAt}</td><td><code>{event.eventHash}</code></td></tr>)}</tbody></table>
      {!rows.length && <p>No events in this authorized query.</p>}
    </section>
  </div>{selected && <EventInspector event={selected} onClose={() => setSelected(null)} onRequest={id => go('Changes', { requestId: id })}/>}</div>;
}

function EventInspector({ event, onClose, onRequest }: { event: LedgerEvent; onClose: () => void; onRequest: (id: string) => void }) {
  const content = decodeJSON<{ actor_id?: string; target_identity?: string; payload?: { facts?: Record<string, unknown> } }>(event.canonicalContent);
  const payload = (() => { try { return event.eventPayloadJson ? JSON.parse(event.eventPayloadJson) as Record<string, unknown> : null; } catch { return null; } })();
  const stream = event.streamId ?? '';
  const requestId = stream.startsWith('change:') ? stream.slice(7) : '';
  return <Inspector eyebrow={`EVENT #${event.sequenceNumber}`} title={event.eventType.replace(/([a-z])([A-Z])/g, '$1 $2')} onClose={onClose} testId="event-inspector">
    <KeyValues rows={[['Event ID', <code>{event.eventId ?? '—'}</code>], ['Recorded', event.recordedAt], ['Stream', requestId ? <button type="button" className="entity-link" onClick={() => onRequest(requestId)}>{stream}</button> : stream],
      ['Stream version', event.streamVersion ?? '—'], ['Actor reference', <code>{String(payload?.actor_reference ?? content?.actor_id ?? '—')}</code>],
      ['Target', content?.target_identity ? <EntityLink id={content.target_identity}/> : '—'], ['Format', `v${event.formatVersion ?? 1}`]]}/>
    <h4>Hash chain link</h4>
    <KeyValues rows={[['Previous event hash', <code>{event.previousEventHash}</code>], ['This event hash', <code>{event.eventHash}</code>]]}/>
    <p className="muted">Actor identifiers are stored as privacy-preserving references; the request and approvals are linked through the stream.</p>
    <details><summary>Recorded event payload</summary><pre className="data" tabIndex={0}>{JSON.stringify(payload ?? {}, null, 2)}</pre></details>
  </Inspector>;
}
