import { useEffect, useState, type ReactNode } from 'react';
import { BadgeCheck, FileLock2, Users } from 'lucide-react';
import { decisionEvidence, parsePolicyRules, readableCondition, short, type Evidence } from './api';
import { useConsole } from './context';
import { DecisionBadge, EntityLink, KeyValues, When } from './ui';

type Activation = { bundleVersion: string; bundleDigest: string; registryEpoch: string; registryDigest: string; eventPosition: string };

export function PolicyTab({ result, authority }: { result: unknown; authority: ReactNode }) {
  const { tenantId, changes } = useConsole();
  const activations = ((result ?? {}) as { activations?: Activation[] }).activations ?? [];
  const [evidence, setEvidence] = useState<Evidence | null>(null);
  const [state, setState] = useState<'loading' | 'ready' | 'none'>('loading');
  // The signed bundle travels with each request's decision evidence; read it from the newest visible request.
  const latest = [...changes].sort((a, b) => (b.createdAt ?? '').localeCompare(a.createdAt ?? ''))[0]?.requestId;
  useEffect(() => {
    if (!latest) { setState('none'); return; }
    let live = true; setState('loading');
    void decisionEvidence(tenantId, latest).then(e => { if (live) { setEvidence(e); setState(e?.bundle ? 'ready' : 'none'); } }).catch(() => { if (live) setState('none'); });
    return () => { live = false; };
  }, [tenantId, latest]);
  const bundle = evidence?.bundle; const registry = evidence?.registry;
  const rules = parsePolicyRules(bundle?.modules['change.rego']);
  return <>
    <section><div className="section-title"><h3>Active policy rules</h3><span className="small-count">{bundle ? `change.rego · v${bundle.version}` : 'signed bundle'}</span></div>
      <p>Every request is evaluated against these rules in order; the first matching rule decides. They are read from the signed policy bundle the core verified and activated, not from a copy in the console.</p>
      {state === 'loading' && <p className="muted">Reading the signed policy bundle…</p>}
      {state === 'none' && <p className="inline-note">The signed bundle is attached to request decision evidence. Submit or review a request to load it here.</p>}
      {rules.length > 0 && <ol className="policy-rules">{rules.map(r => <li key={r.order}><span className="rule-order">{String(r.order).padStart(2, '0')}</span>
        <div className="rule-when"><small>WHEN</small>{r.conditions.length ? r.conditions.map(c => <span key={c} title={c}>{readableCondition(c)}</span>) : <span>No earlier rule matched (default)</span>}</div>
        <div className="rule-then"><DecisionBadge decision={r.outcome}/><span>{r.quorum > 0 ? `${r.quorum} independent approval${r.quorum > 1 ? 's' : ''} from ${r.groups.map(g => g === 'resource-owner' ? 'the resource owner' : g).join(', ')}` : r.outcome === 'ALLOW' ? 'No approval needed' : 'No approval can satisfy it'}</span><small>{r.reasons.join(' · ')}</small></div></li>)}</ol>}
      {bundle && Object.keys(bundle.owners).length > 0 && <><h4>Resource owners</h4><ul className="plain-list">{Object.entries(bundle.owners).map(([resource, owners]) => <li key={resource}><EntityLink id={resource}/> owned by {owners.map((o, i) => <span key={o}>{i > 0 && ', '}<EntityLink id={o}/></span>)}</li>)}</ul></>}
      {bundle && <details><summary>Signed Rego source</summary>{Object.entries(bundle.modules).map(([name, source]) => <div key={name}><h4>{name}</h4><pre className="data" tabIndex={0}>{source}</pre></div>)}</details>}
    </section>
    <section><div className="section-title"><h3>Independent Authority</h3><span className="small-count"><Users size={12}/> {registry ? `${registry.thresholdM} of ${registry.totalN} quorum` : '—'}</span></div>
      <p>Policy and the approver registry change only with signatures from the current Authority quorum. The console cannot activate an unsigned bundle.</p>
      {registry ? <div className="authority-grid">
        <div><p className="eyebrow">MEMBERS · EPOCH {registry.epoch}</p><ul className="plain-list">{registry.members.map(m => <li key={m.actorId}><span className="eligibility" data-eligible={String(m.isActive)}>{m.isActive ? 'Active' : 'Inactive'}</span>{m.displayName || m.actorId}</li>)}</ul><p className="muted">Registry established <When iso={registry.initializedAt}/></p></div>
        <div><p className="eyebrow">CURRENT POLICY BUNDLE</p><KeyValues rows={[['Version', bundle ? `v${bundle.version}` : '—'], ['Status', bundle?.status ?? '—'], ['Bundle hash', bundle ? <code>{short(bundle.digest, 24)}</code> : '—'], ['Activated', <When iso={bundle?.activatedAt}/>], ['Description', bundle?.description ?? '—']]}/></div>
        <div><p className="eyebrow">SIGNATURES</p>{bundle?.signatures.length ? <ul className="plain-list">{bundle.signatures.map(s => <li key={s.actorId}><BadgeCheck size={13} className="is-verified"/> {s.actorId} <span className="muted"><When iso={s.signedAt}/></span></li>)}</ul> : <p className="muted">—</p>}
          <p className="muted">{bundle ? `${bundle.signatures.length} of ${registry.thresholdM} required signatures; the core verified them against the pinned registry before activation.` : ''}</p></div>
      </div> : <p className="muted">{state === 'loading' ? 'Loading…' : 'Authority details are carried with request decision evidence.'}</p>}
    </section>
    <section><div className="section-title"><h3>Policy change workflow</h3><span className="small-count"><FileLock2 size={12}/> M-of-N governed</span></div>
      {authority ?? <p className="inline-note">This deployment runs a signed genesis policy with no live Authority connected, so proposals cannot be made here. With a live Authority (the completion profile), members propose a bundle, review its exact content, sign it with their passkeys and activate it once the current quorum has signed.</p>}
    </section>
    <section data-testid="policy-history"><div className="section-title"><h3>Signed policy activations</h3><span className="small-count">{activations.length}</span></div><p>Every policy bundle the core has verified and activated, with the Authority registry epoch that signed it.</p>
      <table><thead><tr><th>Bundle</th><th>Registry epoch</th><th>Bundle digest</th><th>Registry digest</th><th>Ledger position</th></tr></thead><tbody>{activations.map(a => <tr key={a.eventPosition}><td>v{a.bundleVersion}{bundle?.version === a.bundleVersion && <span className="cell-sub">active · {bundle.signatures.map(s => s.actorId).join(', ')}</span>}</td><td>{a.registryEpoch}</td><td><code>{a.bundleDigest}</code></td><td><code>{a.registryDigest}</code></td><td>{a.eventPosition}</td></tr>)}</tbody></table>
      {!activations.length && <p>No policy activations in this authorized page.</p>}
    </section>
  </>;
}
