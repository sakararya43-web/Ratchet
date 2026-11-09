// Graph analysis for demo mode: the same questions the core answers, over the demo graph.
import { containmentCosts, resourceOwners, type DemoEdge, type DemoNode } from './data';

export type Power = { node_id: string; action: string };
export type Route = { node_ids: string[]; edge_kinds: string[] };
export type Graph = { nodes: DemoNode[]; edges: DemoEdge[] };

const identityTypes = new Set(['Human', 'ServiceAccount', 'Session']);
export const isIdentity = (g: Graph, id: string) => identityTypes.has(g.nodes.find(n => n.id === id)?.type ?? '');
const node = (g: Graph, id: string) => g.nodes.find(n => n.id === id);

// Edges an identity can follow to gain authority. CAN_ASSUME and CAN_ADMINISTER hand over another identity.
const traversable = new Set(['MEMBER_OF', 'ASSIGNED', 'GRANTS', 'CAN_ASSUME', 'CAN_ADMINISTER', 'CAN_MODIFY']);

export function reach(g: Graph, origin: string) {
  const powers: Power[] = []; const controlled = new Set<string>(); const seen = new Set([origin]); const queue = [origin];
  while (queue.length) {
    const at = queue.shift()!;
    for (const e of g.edges.filter(e => e.source === at && traversable.has(e.kind))) {
      const target = node(g, e.target); if (!target) continue;
      if (e.kind === 'GRANTS' || e.kind === 'CAN_MODIFY') powers.push({ node_id: e.target, action: e.action ?? (e.kind === 'CAN_MODIFY' ? 'modify' : 'use') });
      if ((e.kind === 'CAN_ASSUME' || e.kind === 'CAN_ADMINISTER') && identityTypes.has(target.type)) { controlled.add(e.target); powers.push({ node_id: e.target, action: 'takeover' }); }
      if (!seen.has(e.target)) { seen.add(e.target); queue.push(e.target); }
    }
  }
  // An identity always holds its own sessions.
  for (const e of g.edges.filter(e => e.kind === 'CAN_ASSUME' && e.target === origin)) powers.push({ node_id: e.source, action: 'use' });
  const reachable = [...seen].filter(id => id !== origin).map(id => node(g, id)!).filter(Boolean);
  const byTier: Record<string, number> = { '0': 0, '1': 0, '2': 0, '3': 0 };
  for (const n of reachable) if ((n.type === 'Resource' || n.type === 'Safeguard') && n.tier !== undefined) byTier[String(n.tier)]++;
  const unique = new Map(powers.map(p => [`${p.node_id}:${p.action}`, p]));
  return { powers: [...unique.values()], controlled: [...controlled], reachable, byTier };
}

// Every simple path from an identity to a tier-0 resource or safeguard.
export function routes(g: Graph, origin: string, limit = 20): Route[] {
  const found: Route[] = [];
  const walk = (at: string, path: string[], kinds: string[]) => {
    if (found.length >= limit) return;
    const here = node(g, at);
    if (path.length > 1 && here && (here.type === 'Resource' || here.type === 'Safeguard') && here.tier === 0) { found.push({ node_ids: path, edge_kinds: kinds }); return; }
    for (const e of g.edges.filter(e => e.source === at && traversable.has(e.kind))) if (!path.includes(e.target)) walk(e.target, [...path, e.target], [...kinds, e.kind]);
  };
  walk(origin, [origin], []);
  return found;
}

// Identities that can take over `id` also inherit anything granted to it.
export const controllers = (g: Graph, id: string) => g.edges.filter(e => (e.kind === 'CAN_ASSUME' || e.kind === 'CAN_ADMINISTER') && e.target === id).map(e => e.source);

export function apply(g: Graph, kind: string, target: string, access: string): Graph {
  if (kind === 'ROLE_ASSIGN') return { ...g, edges: [...g.edges, { source: target, target: access, kind: 'ASSIGNED' }] };
  if (kind === 'ROLE_REVOKE') return { ...g, edges: g.edges.filter(e => !(e.kind === 'ASSIGNED' && e.source === target && e.target === access)) };
  return g;
}

export type Impact = {
  reduction: boolean; safeguardsWeakened: string[];
  affected: { identity: string; delta: Record<string, number>; newPowers: Power[]; removedPowers: Power[]; newResources: DemoNode[]; newRoutes: Route[]; newControlled: string[]; removedControlled: string[] }[];
};
export function impact(g: Graph, kind: string, target: string, access: string): Impact {
  if (kind === 'MODIFY_SAFEGUARD') return { reduction: false, safeguardsWeakened: [target], affected: [] };
  const after = apply(g, kind, target, access);
  const affected = [target, ...controllers(g, target)].filter((id, i, all) => all.indexOf(id) === i).map(identity => {
    const a = reach(g, identity), b = reach(after, identity);
    const key = (p: Power) => `${p.node_id}:${p.action}`;
    const before = new Set(a.powers.map(key)), later = new Set(b.powers.map(key));
    const ra = new Set(routes(g, identity).map(r => r.node_ids.join('>')));
    const delta: Record<string, number> = {}; for (const t of ['0', '1', '2', '3']) delta[t] = b.byTier[t] - a.byTier[t];
    const reachedBefore = new Set(a.reachable.map(n => n.id));
    return { identity, delta, newPowers: b.powers.filter(p => !before.has(key(p))), removedPowers: a.powers.filter(p => !later.has(key(p))),
      newResources: b.reachable.filter(n => (n.type === 'Resource' || n.type === 'Safeguard') && !reachedBefore.has(n.id)),
      newRoutes: routes(after, identity).filter(r => !ra.has(r.node_ids.join('>'))),
      newControlled: b.controlled.filter(id => !a.controlled.includes(id)), removedControlled: a.controlled.filter(id => !b.controlled.includes(id)) };
  }).filter(x => x.newPowers.length || x.removedPowers.length || x.identity === target);
  const reduction = affected.every(a => a.newPowers.length === 0) && affected.some(a => a.removedPowers.length > 0);
  return { reduction, safeguardsWeakened: [], affected };
}

// Mirrors the signed change.rego rule chain: the first matching rule decides.
export type Decision = { outcome: 'ALLOW' | 'REQUIRE_APPROVAL' | 'HOLD' | 'REJECT'; reasons: string[]; approver_groups: string[]; quorum: number; owners: string[]; newTier0: boolean };
export function decide(g: Graph, requester: string, kind: string, target: string, access: string, emergency: boolean, timeLimit: number, incident = ''): Decision {
  const i = impact(g, kind, target, access);
  const tier0Weakening = kind === 'MODIFY_SAFEGUARD' && node(g, target)?.tier === 0;
  const newTier0 = i.affected.some(a => a.newRoutes.length > 0);
  const resources = [...new Set(i.affected.flatMap(a => a.newResources.map(n => n.id)).concat(kind === 'ROLE_REVOKE' ? i.affected.flatMap(a => a.removedPowers.map(p => p.node_id)) : []))];
  const owners = [...new Set(resources.flatMap(r => resourceOwners[r] ?? []))];
  const responder = g.edges.some(e => e.source === requester && e.kind === 'ASSIGNED' && e.target === 'role:security-lead');
  const make = (outcome: Decision['outcome'], reason: string, groups: string[] = [], quorum = 0): Decision => ({ outcome, reasons: [reason], approver_groups: groups, quorum, owners, newTier0 });
  if (tier0Weakening) return make('REJECT', 'tier-0 safeguard weakening is prohibited');
  if (emergency && timeLimit <= 0) return make('HOLD', 'emergency access requires a fixed duration');
  if (i.reduction && responder && !incident) return make('ALLOW', 'authorized verified reduction');
  if (newTier0) return { ...make('REQUIRE_APPROVAL', 'new tier-0 authority requires two independent security leads', ['role:security-lead'], 2), owners: ['user:alice', 'user:bob'] };
  if (owners.length) return make('REQUIRE_APPROVAL', 'independent resource owner approval required', ['resource-owner'], 1);
  return make('HOLD', 'resource ownership context required');
}

// Minimum-disruption cut: the cheapest set of revocations that leaves no route to a tier-0 asset.
export type Revocation = { action_id: string; action_type: string; target_identity: string; resource_or_role: string; reason: string; cost: number };
export function planContainment(g: Graph, identity: string) {
  const candidates: Revocation[] = [];
  for (const e of g.edges.filter(e => e.kind === 'CAN_ASSUME' && e.target === identity)) candidates.push({ action_id: '', action_type: 'TERMINATE_SESSION', target_identity: identity, resource_or_role: e.source, reason: 'Ends the session an attacker could be using', cost: containmentCosts.TERMINATE_SESSION });
  for (const e of g.edges.filter(e => e.kind === 'ASSIGNED' && e.source === identity)) candidates.push({ action_id: '', action_type: 'REVOKE_ROLE', target_identity: identity, resource_or_role: e.target, reason: '', cost: containmentCosts.REVOKE_ROLE });
  const remove = (graph: Graph, set: Revocation[]): Graph => ({ ...graph, edges: graph.edges.filter(e => !set.some(r => (r.action_type === 'REVOKE_ROLE' && e.kind === 'ASSIGNED' && e.source === identity && e.target === r.resource_or_role) || (r.action_type === 'TERMINATE_SESSION' && e.kind === 'CAN_ASSUME' && e.source === r.resource_or_role))) });
  const roleCuts = candidates.filter(c => c.action_type === 'REVOKE_ROLE');
  let best: Revocation[] | null = null;
  for (let mask = 0; mask < 1 << roleCuts.length; mask++) {
    const set = roleCuts.filter((_, i) => mask & (1 << i));
    if (routes(remove(g, set), identity).length) continue;
    if (!best || set.reduce((a, r) => a + r.cost, 0) < best.reduce((a, r) => a + r.cost, 0)) best = set;
  }
  const sessions = candidates.filter(c => c.action_type === 'TERMINATE_SESSION');
  const chosen = [...sessions, ...(best ?? [])].map((r, i) => ({ ...r, action_id: `act-${i + 1}`, reason: r.reason || `Cuts every route from ${identity} to a tier-0 asset through ${node(g, r.resource_or_role)?.name ?? r.resource_or_role}` }));
  const before = routes(g, identity);
  const after = remove(g, chosen);
  const everyone = g.nodes.filter(n => n.type === 'Human' || n.type === 'ServiceAccount');
  const activity = (graph: Graph) => everyone.flatMap(p => reach(graph, p.id).powers.filter(x => { const t = node(g, x.node_id); return t && t.type === 'Resource'; }).map(x => ({ identity_id: p.id, resource_id: x.node_id, resource_name: node(g, x.node_id)!.name, permitted_action: x.action, tier: node(g, x.node_id)!.tier ?? 0 })));
  const kept = activity(after); const all = activity(g);
  const keyOf = (a: { identity_id: string; resource_id: string; permitted_action: string }) => `${a.identity_id}|${a.resource_id}|${a.permitted_action}`;
  const keptKeys = new Set(kept.map(keyOf));
  return { revocations: chosen, severed: before.length, preserved: kept, disrupted: all.filter(a => !keptKeys.has(keyOf(a))), cost: chosen.reduce((a, r) => a + r.cost, 0), after, zero: routes(after, identity).length === 0 };
}
