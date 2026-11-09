import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { ArrowRight, FlaskConical, Pin, X } from 'lucide-react';
import { reach, simulate, type ImpactDiff, type Reach } from './api';
import { nodeName, useConsole } from './context';
import { GraphCanvas, type CanvasEdge, type CanvasNode } from './GraphCanvas';
import { RoutePath, TierDelta } from './impact';
import { Empty, EntityLink, TierBadge } from './ui';

type Simulation = { id: number; identity: string; kind: string; access: string; duration: number; before: Reach | null; impact: ImpactDiff };
const sum = (r?: Record<string, number>) => Object.values(r ?? {}).reduce((a, b) => a + Number(b), 0);

export function ImpactTab() {
  const { tenantId, actor, bootstrap, busy, work, focus, organization } = useConsole();
  const [identity, setIdentity] = useState(actor);
  const [access, setAccess] = useState('');
  const [result, setResult] = useState<Simulation | null>(null);
  const [saved, setSaved] = useState<Simulation[]>([]);
  useEffect(() => { if (focus?.identity) setIdentity(focus.identity); if (focus?.access) setAccess(focus.access); }, [focus]);
  const identities = organization ? (bootstrap?.nodes ?? []).filter(n => n.type === 'Human' || n.type === 'ServiceAccount') : [{ id: actor, display_name: actor, type: 'Human' }];
  const roles = (bootstrap?.nodes ?? []).filter(n => n.type === 'Role');
  function run(e: FormEvent<HTMLFormElement>) {
    e.preventDefault(); const v = Object.fromEntries(new FormData(e.currentTarget)) as Record<string, string>;
    void work(async () => {
      const [before, r] = await Promise.all([reach(tenantId, v.Identity).catch(() => null), simulate(tenantId, { kind: v.Kind, targetIdentity: v.Identity, requestedAccess: v.Access, requestedBy: actor })]);
      setResult({ id: Date.now(), identity: v.Identity, kind: v.Kind, access: v.Access, duration: Number(v.DurationSeconds || 0), before, impact: r.impact ?? {} });
    });
  }
  return <>
    <p className="simulation-banner"><FlaskConical size={15}/> Simulation only — no changes are applied and nothing is submitted. Results come from the core's graph analysis of the current version.</p>
    <section><h3>Assess an access change</h3><p>Choose an identity and exact role. The server computes what would become reachable, controllable and critical.</p>
      <form onSubmit={run}>
        <label>Identity<select name="Identity" value={identity} onChange={e => setIdentity(e.target.value)}>{identities.map(n => <option key={n.id} value={n.id}>{n.display_name || n.id}</option>)}</select></label>
        <label>Change type<select name="Kind"><option value="ROLE_ASSIGN">Grant role (ROLE_ASSIGN)</option><option value="ROLE_REVOKE">Remove role (ROLE_REVOKE)</option></select></label>
        <label>Role<input name="Access" list="impact-roles" required value={access} onChange={e => setAccess(e.target.value)} placeholder="role:wallet-operator" autoComplete="off"/></label><datalist id="impact-roles">{roles.map(r => <option key={r.id} value={r.id}>{r.display_name}</option>)}</datalist>
        <label>Requested duration (seconds, 0 = permanent)<input name="DurationSeconds" type="number" min="0" max="86400" defaultValue="0"/></label>
        <button disabled={busy}>Compute impact on server</button>
      </form>
      {!organization && <p className="muted">Your account can simulate changes to its own access. Investigators can simulate any identity.</p>}
    </section>
    {result ? <SimulationResult simulation={result} onSave={() => setSaved(list => [result, ...list.filter(s => s.id !== result.id)].slice(0, 4))}/>
      : <Empty title="No simulation yet.">Configure a draft change above. RATCHET shows the existing access beside the proposed access, every newly reachable resource and the exact path to any tier-0 asset.</Empty>}
    {saved.length > 0 && <section><div className="section-title"><h3>Compare proposed changes</h3><span className="small-count">{saved.length}</span></div>
      <div className="compare-grid">{saved.map(s => { const d = s.impact; return <article key={s.id} className="compare-card"><button type="button" className="compare-remove" aria-label="Remove from comparison" onClick={() => setSaved(list => list.filter(x => x.id !== s.id))}><X size={12}/></button>
        <p className="eyebrow">{s.kind === 'ROLE_REVOKE' ? 'REMOVE' : 'GRANT'}</p><h4>{nodeName(bootstrap, s.access)}</h4><p className="muted">for {nodeName(bootstrap, s.identity)}{s.duration ? ` · ${s.duration}s` : ''}</p>
        <dl className="key-values"><div><dt>New resources</dt><dd>{d.newResources?.length ?? 0}</dd></div><div><dt>New tier-0 paths</dt><dd className={(d.newTier0PathsCount ?? 0) > 0 ? 'is-critical' : ''}>{d.newTier0PathsCount ?? 0}</dd></div><div><dt>Controllable identities</dt><dd>{d.newControlledIdentities?.length ?? 0}</dd></div><div><dt>Weakened safeguards</dt><dd>{d.safeguardsWeakened?.length ?? 0}</dd></div><div><dt>Blast radius change</dt><dd>{sum(d.blastRadiusDelta) >= 0 ? '+' : ''}{sum(d.blastRadiusDelta)}</dd></div></dl></article>; })}</div>
    </section>}
  </>;
}

function SimulationResult({ simulation: s, onSave }: { simulation: Simulation; onSave: () => void }) {
  const { bootstrap } = useConsole();
  const d = s.impact;
  const mine = d.affectedIdentities?.find(a => a.identityId === s.identity);
  const routes = d.sampleTier0Routes?.length ? d.sampleTier0Routes : (d.affectedIdentities ?? []).flatMap(a => a.newTier0Routes ?? []);
  const escalation = (d.newTier0PathsCount ?? 0) > 0 || (d.safeguardsWeakened?.length ?? 0) > 0;
  const verdict = d.monotonicReduction ? 'Verified reduction' : escalation ? 'Escalation detected' : (d.newResources?.length ?? 0) > 0 ? 'Access expansion' : 'No change in reach';
  const beforeTier = s.before?.reachByTier;
  const routeGraph = useMemo(() => {
    const ids = new Set<string>(); const edges: CanvasEdge[] = [];
    for (const r of routes) { const n = r.nodeIds ?? []; n.forEach(id => ids.add(id)); n.slice(1).forEach((id, i) => edges.push({ source: n[i], target: id, kind: r.edgeKinds?.[i] ?? 'GRANTS' })); }
    const nodes: CanvasNode[] = [...ids].map(id => { const known = bootstrap?.nodes.find(x => x.id === id); return { id, type: known?.type ?? (id.startsWith('user:') ? 'Human' : id.startsWith('role:') ? 'Role' : 'Resource'), label: known?.display_name || id, tier: known?.tier }; });
    const hot = { nodes: new Set<string>(), edges: new Set(edges.filter(e => e.source === s.identity && e.target === s.access).map(e => `${e.source}>${e.target}>${e.kind}`)) };
    return { nodes, edges, hot };
  }, [routes, bootstrap, s.identity, s.access]);
  return <section className="simulation"><div className="section-title"><h3>{s.kind === 'ROLE_REVOKE' ? 'Remove' : 'Grant'} {nodeName(bootstrap, s.access)} → {nodeName(bootstrap, s.identity)}</h3><button type="button" onClick={onSave}><Pin size={13}/> Add to comparison</button></div>
    <p className="muted">Graph version {d.graphVersion ?? '—'}{s.duration ? ` · requested for ${s.duration}s (a time limit bounds how long, not what becomes reachable)` : ''}</p>
    <div className="before-after">
      <article><p className="eyebrow">BEFORE</p><span className="state-pill" data-state="current">Current state</span><h4>{nodeName(bootstrap, s.identity)}'s existing access</h4>
        {s.before?.powers?.length ? <ul className="plain-list">{s.before.powers.map(p => <li key={`${p.nodeId}${p.action}`}><span className="power-action">{p.action}</span> <EntityLink id={p.nodeId}/></li>)}</ul> : <p className="muted">{s.before ? 'No effective access.' : 'Existing access is not visible to your account.'}</p>}</article>
      <ArrowRight className="before-after-arrow" size={20}/>
      <article className={escalation ? 'is-escalation' : ''}><p className="eyebrow">AFTER</p><span className="state-pill" data-state={d.monotonicReduction ? 'reduction' : escalation ? 'escalation' : 'neutral'}>{verdict}</span><h4>Proposed access</h4>
        <ul className="plain-list">{(s.before?.powers ?? []).filter(p => !mine?.removedPowers?.some(r => r.nodeId === p.nodeId && r.action === p.action)).map(p => <li key={`b${p.nodeId}${p.action}`}><span className="power-action">{p.action}</span> <EntityLink id={p.nodeId}/></li>)}
          {mine?.newPowers?.map(p => <li key={`n${p.nodeId}${p.action}`}><span className="power-action is-new">+ {p.action}</span> <EntityLink id={p.nodeId}/></li>)}
          {mine?.removedPowers?.map(p => <li key={`r${p.nodeId}${p.action}`}><span className="power-action is-removed">− {p.action}</span> <EntityLink id={p.nodeId}/></li>)}</ul>
        {!mine?.newPowers?.length && !mine?.removedPowers?.length && <p className="muted">No change to this identity's powers.</p>}</article>
    </div>
    <h4>Blast radius before and after</h4><TierDelta before={beforeTier} delta={mine?.blastRadiusDelta ?? d.blastRadiusDelta ?? {}}/>
    <div className="impact-breakdown">
      <div><h4>Newly accessible resources ({d.newResources?.length ?? 0})</h4>{d.newResources?.length ? <ul className="plain-list">{d.newResources.map(r => <li key={r.id}><EntityLink id={r.id}/> <TierBadge tier={r.tier ?? 0}/></li>)}</ul> : <p className="muted">None.</p>}</div>
      <div><h4>Newly controllable identities ({d.newControlledIdentities?.length ?? 0})</h4>{d.newControlledIdentities?.length ? <ul className="plain-list">{d.newControlledIdentities.map(id => <li key={id}><EntityLink id={id}/></li>)}</ul> : <p className="muted">None.</p>}</div>
      <div><h4>Weakened security controls ({d.safeguardsWeakened?.length ?? 0})</h4>{d.safeguardsWeakened?.length ? <ul className="plain-list">{d.safeguardsWeakened.map(w => <li key={w.id}><EntityLink id={w.id}/></li>)}</ul> : <p className="muted">None.</p>}</div>
    </div>
    <h4>New critical access paths ({d.newTier0PathsCount ?? 0})</h4>
    {routes.length ? <>{routes.map((r, i) => <RoutePath key={i} route={r}/>)}<GraphCanvas label="Proposed access path to tier-0 assets" nodes={routeGraph.nodes} edges={routeGraph.edges} highlight={routeGraph.hot} onSelect={() => undefined} height={260}/><p className="muted">The highlighted edge is the proposed change; the rest of each path already exists.</p></>
      : <p className="muted">This change creates no path to a tier-0 asset.</p>}
  </section>;
}
