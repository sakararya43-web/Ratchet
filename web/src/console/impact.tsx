import type { ReactNode } from 'react';
import type { AssessedImpact, Route } from './api';
import { edgeLabel } from './GraphCanvas';
import { EntityLink, TierBadge } from './ui';

export type Resource = { id: string; displayName?: string; tier?: number };
export type Impact = {
  graphVersion?: string; monotonicReduction?: boolean; newResources?: Resource[]; newControlledIdentities?: string[]; newTier0PathsCount?: number;
  safeguardsWeakened?: { id: string; description?: string }[];
  affectedIdentities?: { identityId: string; newPowers?: { nodeId: string; action: string }[]; removedPowers?: { nodeId: string; action: string }[] }[];
};
export type BoundImpact = {
  graph_version: number; monotonic_reduction: boolean; safeguards_weakened: { id: string; display_name?: string }[];
  affected_identities: { identity_id: string; new_resources: { id: string; display_name?: string; tier: number }[]; new_controlled_identities: string[]; new_tier0_routes: unknown[];
    new_powers: { node_id: string; action: string }[]; removed_powers?: { node_id: string; action: string }[] }[];
};
export function boundImpactView(impact: BoundImpact): Impact {
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

// The exact consequence view used in approval review; its structure is part of the reviewed evidence.
export function ImpactView({ impact }: { impact: Impact }) {
  return <div className="impact"><p>Graph version {impact.graphVersion} | {impact.monotonicReduction ? 'Verified access reduction' : 'Access expansion assessed'}</p>
    <h4>Newly reachable resources</h4>{impact.newResources?.length ? <ul>{impact.newResources.map(r => <li key={r.id}>{r.displayName || r.id} - tier {r.tier ?? 0} <code>{r.id}</code></li>)}</ul> : <p>No newly reachable resources.</p>}
    <p>New tier-0 paths: <strong>{impact.newTier0PathsCount ?? 0}</strong></p>
    <h4>Additional controlled identities</h4>{impact.newControlledIdentities?.length ? <ul>{impact.newControlledIdentities.map(id => <li key={id}>{id}</li>)}</ul> : <p>None.</p>}
    <h4>Changed authority by identity</h4>{impact.affectedIdentities?.map(a => <div key={a.identityId}><strong>{a.identityId}</strong><ul>{a.newPowers?.map(p => <li key={`add:${p.nodeId}:${p.action}`}>Gain {p.action} on {p.nodeId}</li>)}{a.removedPowers?.map(p => <li key={`remove:${p.nodeId}:${p.action}`}>Remove {p.action} on {p.nodeId}</li>)}</ul></div>)}
    <h4>Weakened safeguards</h4>{impact.safeguardsWeakened?.length ? <ul>{impact.safeguardsWeakened.map(s => <li key={s.id}>{s.description || s.id}</li>)}</ul> : <p>None observed.</p>}
  </div>;
}

export function RoutePath({ route }: { route: Route }) {
  const ids = route.nodeIds ?? [];
  return <p className="route-line">{ids.map((id, i) => <span key={`${id}${i}`}>{i > 0 && <span className="route-kind"> {edgeLabel[route.edgeKinds?.[i - 1] ?? ''] ?? '→'} </span>}<EntityLink id={id}/></span>)}</p>;
}

const tiers = ['0', '1', '2', '3'] as const;
export function TierDelta({ before, delta }: { before?: Record<string, number>; delta: Record<string, number> }) {
  return <div className="tier-delta">{tiers.map(t => { const b = before?.[t]; const d = delta[t] ?? 0; return <div key={t} data-changed={d !== 0} data-tier={t}><span>Tier {t}</span><strong>{b !== undefined ? `${b} → ${b + d}` : d > 0 ? `+${d}` : d}</strong>{b === undefined && <small>change</small>}</div>; })}</div>;
}

// The assessed consequence recorded in decision evidence, for any request the viewer may inspect.
export function AssessedImpactView({ impact, empty }: { impact: AssessedImpact; empty?: ReactNode }) {
  const routes = impact.affected.flatMap(a => a.newTier0Routes.map(r => ({ identity: a.identityId, route: r })));
  const resources = new Map<string, { id: string; tier?: number }>();
  impact.affected.forEach(a => a.newResources.forEach(r => resources.set(r.id, r)));
  const total: Record<string, number> = {};
  impact.affected.forEach(a => Object.entries(a.blastRadiusDelta).forEach(([t, n]) => { total[t] = Math.max(total[t] ?? 0, n); }));
  if (!impact.affected.length && !impact.safeguardsWeakened.length) return <>{empty ?? <p className="muted">No change in reach was assessed.</p>}</>;
  return <div className="assessed-impact">
    <p className="muted">{impact.reduction ? 'Graph analysis proved this change only reduces access.' : 'Access expansion assessed against the graph at assessment time.'}</p>
    <h4>Blast radius change</h4><TierDelta delta={total}/>
    <h4>Newly accessible resources</h4>{resources.size ? <ul className="plain-list">{[...resources.values()].map(r => <li key={r.id}><EntityLink id={r.id}/> <TierBadge tier={r.tier}/></li>)}</ul> : <p className="muted">None.</p>}
    <h4>New paths to tier-0 assets ({routes.length})</h4>{routes.length ? routes.map((r, i) => <RoutePath key={i} route={r.route}/>) : <p className="muted">None.</p>}
    <h4>Changed authority by identity</h4><ul className="plain-list">{impact.affected.map(a => <li key={a.identityId}><EntityLink id={a.identityId}/>: {a.newPowers.map(p => `${p.action} on ${p.nodeId}`).join(', ') || 'no new powers'}{a.newControlled.length ? ` · can take over ${a.newControlled.join(', ')}` : ''}</li>)}</ul>
    <h4>Weakened safeguards</h4>{impact.safeguardsWeakened.length ? <ul className="plain-list">{impact.safeguardsWeakened.map(id => <li key={id}><EntityLink id={id}/></li>)}</ul> : <p className="muted">None observed.</p>}
  </div>;
}
