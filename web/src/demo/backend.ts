// In-browser stand-in for the core's console API, used when no RATCHET server is reachable.
// It answers the same endpoints with the same permission rules; state lives in memory.
import { ApiError } from '../lib/api';
import { canonicalize, digest } from '../lib/canon';
import { edges as seedEdges, nodes, personas, policy, resourceOwners, seedIncidents, seedRequests, TENANT, type DemoNode } from './data';
import { controllers, decide, impact, planContainment, reach, routes, type Decision, type Graph, type Impact, type Revocation } from './engine';

type Body = Record<string, unknown>;
type Event = { seq: number; type: string; stream: string; at: string; actor: string; payload: Body; canonical: string; prev: string; hash: string; id: string };
type Change = {
  id: string; requester: string; kind: string; target: string; access: string; justification: string; emergency: boolean; timeLimit: number; incident: string;
  status: string; revision: number; createdAt: string; updatedAt: string; decision: Decision; impact: Impact; graphVersion: number; approvals: string[];
  grantExpiresAt?: string; expiryStatus?: string; envelope: string; digest: string; bound: unknown; expiresAt: string; assessment?: Event;
};
type Plan = { id: string; identity: string; digest: string; graphVersion: number; createdAt: string; result: ReturnType<typeof planContainment> };
type Incident = { id: string; title: string; severity: string; status: string; identity: string; rootCause: string; openedAt: string; containedAt?: string; resolvedAt?: string; actions: string[]; plan?: Plan; graphVersion: number };
type Passkey = { actor: string; id: string; label: string; enrolledAt: string; revoked: boolean };

const ZERO = '0'.repeat(64);
const now = Date.now();
const iso = (hoursAgo: number) => new Date(now - hoursAgo * 3600_000).toISOString();
const later = (hours: number) => new Date(now + hours * 3600_000).toISOString();
const name = (id: string) => nodes.find(n => n.id === id)?.name ?? id;
const toBytes = (hex: string) => (hex.match(/../g) ?? []).map(b => parseInt(b, 16));
const b64 = (text: string) => btoa(unescape(encodeURIComponent(text)));
const b64url = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
async function sha256(parts: Uint8Array[]): Promise<Uint8Array> {
  const all = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let o = 0; for (const p of parts) { all.set(p, o); o += p.length; }
  return new Uint8Array(await crypto.subtle.digest('SHA-256', all));
}
const hexOf = (bytes: Uint8Array) => [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');

let state: {
  graph: Graph; graphVersion: number; changes: Change[]; incidents: Incident[]; ledger: Event[]; passkeys: Passkey[]; plans: Plan[];
  session: string | null; bundleHash: string; challenges: Map<string, string>; counter: number;
};

const isLead = (actor: string) => state.graph.edges.some(e => e.source === actor && e.kind === 'ASSIGNED' && e.target === 'role:security-lead');
const organization = (actor: string) => isLead(actor);
function me(): string { if (!state.session) throw new ApiError(401, 'session required'); return state.session; }
const forbid = (message = 'operation not authorized') => new ApiError(403, message);

async function append(type: string, stream: string, actor: string, payload: Body, at: string): Promise<Event> {
  const prev = state.ledger.length ? state.ledger[state.ledger.length - 1].hash : ZERO;
  const seq = state.ledger.length + 1;
  const canonical = canonicalize({ actor_id: actor, event_type: type, payload, sequence: seq, stream_id: stream, tenant_id: TENANT, timestamp: at });
  const hash = hexOf(await sha256([Uint8Array.from(toBytes(prev)), new TextEncoder().encode(canonical)]));
  const event = { seq, type, stream, at, actor, payload, canonical, prev, hash, id: crypto.randomUUID() };
  state.ledger.push(event);
  return event;
}

function boundImpact(c: { impact: Impact; graphVersion: number }) {
  return {
    graph_version: c.graphVersion, monotonic_reduction: c.impact.reduction,
    safeguards_weakened: c.impact.safeguardsWeakened.map(id => ({ id, display_name: name(id) })),
    affected_identities: c.impact.affected.map(a => ({ identity_id: a.identity, new_resources: a.newResources.map(n => ({ id: n.id, display_name: n.name, tier: n.tier ?? 0 })),
      new_controlled_identities: a.newControlled, new_tier0_routes: a.newRoutes.map(r => ({ node_ids: r.node_ids, edge_kinds: r.edge_kinds })),
      new_powers: a.newPowers, removed_powers: a.removedPowers })),
  };
}

async function seal(c: Change) {
  // The exact approval envelope a reviewer's passkey is bound to.
  c.bound = boundImpact(c);
  const envelope = { format_version: 2, tenant_id: TENANT, request_id: c.id, request_revision: 2, authenticated_requester: c.requester, graph_version: c.graphVersion, expires_at: c.expiresAt,
    intent: { kind: c.kind, target_identity: c.target, requested_access: c.access, time_limit_seconds: c.timeLimit, emergency: c.emergency },
    impact_digest: toBytes(await digest(c.bound)), policy_bundle_hash: toBytes(state.bundleHash) };
  const raw = canonicalize(envelope);
  c.envelope = b64(raw); c.digest = await digest(envelope);
}

async function step(c: Change, type: string, actor: string, at: string, payload: Body = {}) {
  c.revision++; c.updatedAt = at;
  return append(type, `change:${c.id}`, actor, { request_id: c.id, kind: c.kind, target_identity: c.target, requested_access: c.access, ...payload }, at);
}

function applyChange(c: Change) {
  if (c.kind === 'ROLE_ASSIGN') state.graph = { ...state.graph, edges: [...state.graph.edges, { source: c.target, target: c.access, kind: 'ASSIGNED' }] };
  if (c.kind === 'ROLE_REVOKE') state.graph = { ...state.graph, edges: state.graph.edges.filter(e => !(e.kind === 'ASSIGNED' && e.source === c.target && e.target === c.access)) };
  state.graphVersion++;
}

async function execute(c: Change, at: string) {
  await step(c, 'ChangeExecuting', c.requester, at);
  applyChange(c);
  await step(c, 'ChangeExecuted', 'connector:northwind-sim', new Date(Date.parse(at) + 900).toISOString(), { target_read_back: 'verified', graph_version: state.graphVersion });
  c.status = 'EXECUTED';
  if (c.timeLimit > 0) { c.expiryStatus = 'SCHEDULED'; c.grantExpiresAt ??= new Date(Date.parse(at) + c.timeLimit * 1000).toISOString(); }
}

async function submit(input: { requester: string; kind: string; target: string; access: string; justification: string; emergency: boolean; timeLimit: number; incident?: string; at: string; id?: string }): Promise<Change> {
  const decision = decide(state.graph, input.requester, input.kind, input.target, input.access, input.emergency, input.timeLimit, input.incident ?? '');
  const c: Change = { id: input.id ?? `req-${++state.counter}`, requester: input.requester, kind: input.kind, target: input.target, access: input.access, justification: input.justification,
    emergency: input.emergency, timeLimit: input.timeLimit, incident: input.incident ?? '', status: 'SUBMITTED', revision: 0, createdAt: input.at, updatedAt: input.at, decision,
    impact: impact(state.graph, input.kind, input.target, input.access), graphVersion: state.graphVersion, approvals: [], envelope: '', digest: '', bound: null, expiresAt: later(6) };
  state.changes.push(c);
  await step(c, 'ChangeSubmitted', c.requester, input.at, { justification_recorded: true });
  c.assessment = await step(c, 'ChangeAssessed', 'core:policy', new Date(Date.parse(input.at) + 400).toISOString(), { outcome: decision.outcome, reasons: decision.reasons, quorum: decision.quorum });
  await seal(c);
  const next = new Date(Date.parse(input.at) + 800).toISOString();
  if (decision.outcome === 'REJECT') { c.status = 'REJECTED'; await step(c, 'ChangeRejected', 'core:policy', next, { reasons: decision.reasons }); }
  else if (decision.outcome === 'HOLD') { c.status = 'HELD'; await step(c, 'ChangeHeld', 'core:policy', next, { reasons: decision.reasons }); }
  else if (decision.outcome === 'ALLOW') { c.status = 'ALLOWED'; await step(c, 'ChangeAllowed', 'core:policy', next); await execute(c, new Date(Date.parse(next) + 300).toISOString()); }
  else { c.status = 'AWAITING_APPROVAL'; await step(c, 'ChangeAwaitingApproval', 'core:policy', next, { quorum: decision.quorum, approver_groups: decision.approver_groups }); }
  return c;
}

function eligible(c: Change, actor: string) {
  return c.decision.owners.includes(actor) && actor !== c.requester && !controllers(state.graph, c.requester).includes(actor);
}

async function approve(c: Change, actor: string, at: string) {
  if (actor === c.requester) throw forbid('self-approval refused: a requester cannot approve their own escalation');
  if (!eligible(c, actor)) throw forbid('approver is not an independent eligible reviewer for this change');
  if (c.approvals.includes(actor)) throw forbid('duplicate approval refused: one person cannot count twice toward the quorum');
  if (c.status !== 'AWAITING_APPROVAL') throw new ApiError(409, 'request is no longer awaiting approval');
  c.approvals.push(actor);
  await step(c, 'ChangeApprovalRecorded', actor, at, { approver: actor, approvals: c.approvals.length, quorum: c.decision.quorum, passkey: 'demo-simulated' });
  if (c.approvals.length >= c.decision.quorum) {
    c.status = 'APPROVED'; await step(c, 'ChangeApproved', 'core:workflow', at);
    await execute(c, new Date(Date.parse(at) + 300).toISOString());
  }
}

export async function initDemo(): Promise<void> {
  // The organisation before the recorded history: Rahul's month-end grant and Meera's staging access come later.
  const initial = seedEdges.filter(e => !(e.source === 'user:rahul' && e.target === 'role:wallet-operator')).concat([{ source: 'user:david', target: 'role:staging-developer', kind: 'ASSIGNED' }]);
  state = { graph: { nodes, edges: initial }, graphVersion: 100, changes: [], incidents: [], ledger: [], passkeys: [], plans: [], session: null, bundleHash: '', challenges: new Map(), counter: 1007 };
  state.bundleHash = await digest({ bundle_version: '1.1.0', modules: { 'change.rego': policy.rego, 'authz.rego': policy.authz }, data: { resource_owners: resourceOwners } });
  await append('AuthorityRegistryActivated', 'policy:registry', 'authority', { epoch: 1, threshold_m: 2, members: policy.registry.members }, iso(24 * policy.registry.establishedDaysAgo));
  for (const b of policy.bundles) await append('PolicyBundleActivated', 'policy:bundles', 'authority', { bundle_version: b.version, signers: b.signers }, iso(24 * b.activatedDaysAgo));
  await append('AuthorityRegistryActivated', 'policy:registry', 'authority', { epoch: policy.registry.epoch, threshold_m: 2, members: policy.registry.members }, iso(24 * 6 + 1));
  for (const p of personas) state.passkeys.push({ actor: p.id, id: hexOf(await sha256([new TextEncoder().encode(p.id)])), label: `${p.name.split(' ')[0]}’s ${p.id === 'user:rahul' ? 'laptop' : 'security key'}`, enrolledAt: iso(24 * 20), revoked: false });
  state.passkeys.push({ actor: 'user:alice', id: hexOf(await sha256([new TextEncoder().encode('old-alice')])), label: 'Alice’s previous key (rotated)', enrolledAt: iso(24 * 90), revoked: true });
  for (const s of [...seedRequests].sort((a, b) => b.hoursAgo - a.hoursAgo)) {
    const at = iso(s.hoursAgo);
    const c = await submit({ id: s.id, requester: s.requester, kind: s.kind, target: s.target, access: s.access, justification: s.justification, emergency: !!s.emergency, timeLimit: s.timeLimitSeconds ?? 0, at });
    c.expiresAt = s.outcome === 'AWAITING_APPROVAL' ? later(6) : new Date(Date.parse(at) + 6 * 3600_000).toISOString();
    await seal(c);
    if (s.outcome === 'EXPIRED' && c.status === 'AWAITING_APPROVAL') { c.status = 'EXPIRED'; await step(c, 'ChangeExpired', 'core:workflow', new Date(Date.parse(at) + 6 * 3600_000).toISOString()); }
    for (const [i, approver] of (s.approvers ?? []).entries()) if (c.status === 'AWAITING_APPROVAL') await approve(c, approver, new Date(Date.parse(at) + (i + 1) * 240_000).toISOString());
    if (s.expiresInHours !== undefined) c.grantExpiresAt = later(s.expiresInHours);
    if (s.outcome === 'REVOKED' && c.status === 'EXECUTED') {
      const end = new Date(Date.parse(at) + 3600_000 + 60_000).toISOString();
      state.graph = { ...state.graph, edges: state.graph.edges.filter(e => !(e.kind === 'ASSIGNED' && e.source === c.target && e.target === c.access)) }; state.graphVersion++;
      c.status = 'REVOKED'; c.expiryStatus = 'REVOKED'; await step(c, 'GrantExpiryRevoked', 'core:workflow', end, { target_read_back: 'verified' });
    }
  }
  for (const i of seedIncidents) {
    const incident: Incident = { id: i.id, title: i.title, severity: i.severity, status: i.status, identity: i.identity, rootCause: i.rootCause, openedAt: iso(i.hoursAgo), actions: [...i.actions], graphVersion: state.graphVersion,
      ...(i.resolvedHoursAgo !== undefined ? { resolvedAt: iso(i.resolvedHoursAgo), containedAt: iso(i.resolvedHoursAgo) } : {}) };
    state.incidents.push(incident);
    await append('IncidentOpened', `incident:${i.id}`, i.status === 'OPEN' ? 'detector:session-anomaly' : 'connector:drift-watch', { incident_id: i.id, identity: i.identity, severity: i.severity, root_cause: i.rootCause }, iso(i.hoursAgo));
    if (i.resolvedHoursAgo !== undefined) await append('IncidentResolved', `incident:${i.id}`, 'user:alice', { incident_id: i.id }, iso(i.resolvedHoursAgo));
  }
  state.ledger.sort((a, b) => a.at.localeCompare(b.at));
  // Re-chain in time order so the ledger reads chronologically and every hash is genuine.
  const events = state.ledger; state.ledger = [];
  for (const e of events) { const fresh = await append(e.type, e.stream, e.actor, e.payload, e.at); if (state.changes.some(c => c.assessment === e)) state.changes.find(c => c.assessment === e)!.assessment = fresh; }
}

function view(c: Change) {
  return { requestId: c.id, tenantId: TENANT, kind: c.kind, targetIdentity: c.target, requestedAccess: c.access, justification: c.justification, requestedBy: c.requester, emergency: c.emergency,
    timeLimitSeconds: c.timeLimit, status: c.status, changeDigest: c.digest, graphVersion: String(c.graphVersion), requiredApproverGroups: c.decision.approver_groups, requiredQuorum: c.decision.quorum,
    decisionReasons: c.decision.reasons, createdAt: c.createdAt, updatedAt: c.updatedAt, revision: String(c.revision), policyBundleHash: state.bundleHash, canonicalApprovalEnvelopeJson: c.envelope,
    grantExpiresAt: c.grantExpiresAt, expiryStatus: c.expiryStatus };
}
const visible = (c: Change, actor: string) => organization(actor) || c.requester === actor || c.target === actor || c.decision.owners.includes(actor);
function change(id: unknown, actor: string): Change {
  const c = state.changes.find(x => x.id === id); if (!c || !visible(c, actor)) throw new ApiError(404, 'request not found'); return c;
}
const nodeView = (n: DemoNode) => ({ id: n.id, type: n.type, displayName: n.name, ...(n.tier !== undefined ? { tier: n.tier } : {}), properties: n.properties ?? {} });
const routeView = (r: { node_ids: string[]; edge_kinds: string[] }) => ({ nodeIds: r.node_ids, edgeKinds: r.edge_kinds });
function eventView(e: Event, withContent = false) {
  return { sequenceNumber: String(e.seq), tenantId: TENANT, eventType: e.type, eventPayloadJson: JSON.stringify({ event_type: e.type, actor_reference: e.actor, ...e.payload }), previousEventHash: e.prev, eventHash: e.hash,
    recordedAt: e.at, streamId: e.stream, streamVersion: '1', eventId: e.id, formatVersion: 1, ...(withContent ? { canonicalContent: b64(e.canonical) } : {}) };
}
function planView(p: Plan) {
  const r = p.result;
  return { planId: p.id, compromisedIdentity: p.identity, graphVersion: String(p.graphVersion), createdAt: p.createdAt, planDigest: p.digest, minimumProved: true, optimalityScope: 'exhaustive over role and session revocations',
    proposedZeroTier0Proved: r.zero, disruptionCost: String(r.cost), severedTier0RoutesCount: r.severed, algorithm: 'weighted minimum cut', policyBundleHash: state.bundleHash, expiresAt: later(1),
    recommendedRevocations: r.revocations.map((a: Revocation) => ({ actionId: a.action_id, actionType: a.action_type, targetIdentity: a.target_identity, resourceOrRole: a.resource_or_role, reason: a.reason })),
    preservedActivities: r.preserved.map(a => ({ resourceId: a.resource_id, resourceName: a.resource_name, permittedAction: a.permitted_action, tier: a.tier, identityId: a.identity_id })),
    disruptedActivities: r.disrupted.map(a => ({ resourceId: a.resource_id, resourceName: a.resource_name, permittedAction: a.permitted_action, tier: a.tier, identityId: a.identity_id })) };
}
const incidentView = (i: Incident) => ({ incidentId: i.id, title: i.title, severity: i.severity, status: i.status, affectedIdentity: i.identity, rootCauseType: i.rootCause, openedAt: i.openedAt,
  containedAt: i.containedAt, resolvedAt: i.resolvedAt, actionsTaken: i.actions, observedGraphVersion: String(i.graphVersion), ...(i.plan ? { containmentPlan: planView(i.plan) } : {}) });

function evidence(c: Change) {
  const a = c.assessment!;
  const owners = c.decision.owners;
  const raw = {
    event_sequence: a.seq, event_hash: toBytes(a.hash), previous_hash: toBytes(a.prev), request_id: c.id, tenant_id: TENANT,
    canonical_event: { payload: { facts: { change: {
      requester: c.requester, created_at: c.createdAt, intent: { kind: c.kind, target_identity: c.target, requested_access: c.access, emergency: c.emergency, time_limit_seconds: c.timeLimit },
      decision: { outcome: c.decision.outcome, reasons: c.decision.reasons, approver_groups: c.decision.approver_groups, quorum: c.decision.quorum },
      approval_envelope: { policy_bundle_hash: toBytes(state.bundleHash), graph_version: c.graphVersion },
      decision_facts: { evaluator: 'opa-1.22.0/ratchet-facts-v3 (demo)', input: { graph_version: c.graphVersion, owners, actor_groups: isLead(c.requester) ? ['role:security-lead'] : [], new_tier0: c.decision.newTier0,
        tier0_weakening: c.decision.outcome === 'REJECT', reduction: c.impact.reduction, registry_epoch: policy.registry.epoch,
        impact: { monotonic_reduction: c.impact.reduction, safeguards_weakened: c.impact.safeguardsWeakened.map(id => ({ id })), affected_identities: c.impact.affected.map(x => ({ identity_id: x.identity, blast_radius_delta: x.delta,
          new_powers: x.newPowers, new_resources: x.newResources.map(n => ({ id: n.id, tier: n.tier ?? 0, type: n.type })), new_tier0_routes: x.newRoutes, new_controlled_identities: x.newControlled })) } } } } } } },
    signed_bundle: { bundle_version: '1.1.0', description: policy.bundles[1].description, status: 'ACTIVE', epoch: policy.registry.epoch, bundle_digest: toBytes(state.bundleHash), activated_at: iso(24 * 6),
      modules: { 'change.rego': policy.rego, 'authz.rego': policy.authz }, data: { resource_owners: resourceOwners }, signatures: policy.bundles[1].signers.map((s, i) => ({ actor_id: s, signed_at: iso(24 * 6 + 2 - i) })) },
    registry_proof: { genesis: { epoch: policy.registry.epoch, threshold_m: policy.registry.thresholdM, total_n: policy.registry.members.length, initialized_at: iso(24 * policy.registry.establishedDaysAgo),
      members: policy.registry.members.map(m => ({ actor_id: m, is_active: true, display_name: name(m) })) } },
    public_graph: { nodes: state.graph.nodes.map(n => ({ id: n.id, type: n.type, tier: n.tier, display_name: n.name })), edges: state.graph.edges },
  };
  return { canonicalEvidenceJson: b64(JSON.stringify(raw)) };
}

async function rpc(service: string, method: string, body: Body): Promise<unknown> {
  const actor = me(); const org = organization(actor); const at = new Date().toISOString();
  const key = `${service}/${method}`;
  switch (key) {
    case 'ChangeService/ListChanges': return { requests: state.changes.filter(c => visible(c, actor)).map(view) };
    case 'ChangeService/GetChange': return { request: view(change(body.requestId, actor)) };
    case 'ChangeService/GetDecisionEvidence': if (!org) throw forbid(); return evidence(change(body.requestId, actor));
    case 'ChangeService/SubmitChange': {
      const c = await submit({ requester: actor, kind: String(body.kind), target: String(body.targetIdentity), access: String(body.requestedAccess), justification: String(body.justification ?? ''),
        emergency: !!body.emergency, timeLimit: Number(body.durationSeconds ?? 0), at });
      return { request: view(c) };
    }
    case 'ChangeService/ApproveChange': {
      const c = change(body.requestId, actor);
      if (body.approvedEnvelopeDigest !== c.digest) throw new ApiError(409, 'approval is bound to a different change digest');
      await approve(c, actor, at); return { request: view(c) };
    }
    case 'ChangeService/HoldChange': case 'ChangeService/RejectChange': {
      const c = change(body.requestId, actor);
      if (!org && !eligible(c, actor)) throw forbid();
      if (c.status !== 'AWAITING_APPROVAL') throw new ApiError(409, 'request is no longer awaiting a decision');
      c.status = method === 'HoldChange' ? 'HELD' : 'REJECTED';
      await step(c, method === 'HoldChange' ? 'ChangeHeld' : 'ChangeRejected', actor, at, { reasons: [String(body.reason ?? '')] }); return { request: view(c) };
    }
    case 'ChangeService/RequestMoreInfo': {
      const c = change(body.requestId, actor); if (!org && !eligible(c, actor)) throw forbid();
      await step(c, 'ChangeMoreInfoRequested', actor, at, { question: String(body.question ?? '') }); return { request: view(c) };
    }
    case 'ChangeService/ListPolicyHistory': {
      if (!org) throw forbid();
      const activations = state.ledger.filter(e => e.type === 'PolicyBundleActivated');
      return { activations: await Promise.all(activations.map(async (e, i) => ({ bundleVersion: String(e.payload.bundle_version), bundleDigest: i === activations.length - 1 ? state.bundleHash : await digest({ version: e.payload.bundle_version }),
        registryEpoch: String(i + 1), registryDigest: await digest({ registry_epoch: i + 1, members: policy.registry.members }), eventPosition: String(e.seq) }))) };
    }
    case 'OverviewService/GetAttentionItems': {
      const mine = state.changes.filter(c => visible(c, actor));
      const items = mine.filter(c => c.status === 'HELD').map(c => ({ itemId: c.id, itemType: 'PENDING_CHANGE', title: `HELD: ${c.kind}`, description: c.decision.outcome === 'HOLD' ? c.decision.reasons[0] : 'context changed', severity: 'review', createdAt: c.updatedAt, entityId: c.id }));
      const incidents = org ? state.incidents.filter(i => i.status !== 'RESOLVED') : [];
      for (const i of incidents) items.push({ itemId: i.id, itemType: 'ACTIVE_INCIDENT', title: i.title, description: `${i.severity} · ${i.status}`, severity: i.severity, createdAt: i.openedAt, entityId: i.id });
      return { attentionItems: items, pendingRequests: mine.filter(c => c.status === 'AWAITING_APPROVAL').map(view), activeIncidents: incidents.map(incidentView) };
    }
    case 'GraphService/GetNodeDetails': {
      const id = String(body.nodeId); if (!org && id !== actor) throw forbid();
      const n = state.graph.nodes.find(x => x.id === id); if (!n) throw new ApiError(404, 'node not found');
      const edgeView = (e: { source: string; target: string; kind: string; action?: string }) => ({ source: e.source, target: e.target, kind: e.kind, ...(e.action ? { action: e.action } : {}) });
      return { node: nodeView(n), incomingEdges: state.graph.edges.filter(e => e.target === id).map(edgeView), outgoingEdges: state.graph.edges.filter(e => e.source === id).map(edgeView), graphVersion: String(state.graphVersion) };
    }
    case 'GraphService/GetReach': {
      const id = String(body.identityId); if (!org && id !== actor) throw forbid();
      const r = reach(state.graph, id);
      return { reachableNodes: r.reachable.map(nodeView), controlledIdentities: r.controlled, reachByTier: r.byTier, graphVersion: String(state.graphVersion), powers: r.powers.map(p => ({ nodeId: p.node_id, action: p.action })) };
    }
    case 'GraphService/GetPathsToCritical': {
      const id = String(body.identityId); if (!org && id !== actor) throw forbid();
      return { routes: routes(state.graph, id).map(routeView), graphVersion: String(state.graphVersion) };
    }
    case 'ImpactService/SimulateChange': {
      const target = String(body.targetIdentity); if (!org && target !== actor) throw forbid('own target required');
      const i = impact(state.graph, String(body.kind), target, String(body.requestedAccess));
      const total: Record<string, number> = { '0': 0, '1': 0, '2': 0, '3': 0 };
      i.affected.forEach(a => Object.entries(a.delta).forEach(([t, n]) => { total[t] = Math.max(total[t], n); }));
      const resources = new Map(i.affected.flatMap(a => a.newResources).map(n => [n.id, n]));
      const all = i.affected.flatMap(a => a.newRoutes);
      return { impact: { graphVersion: String(state.graphVersion), monotonicReduction: i.reduction, newResources: [...resources.values()].map(n => ({ id: n.id, displayName: n.name, tier: n.tier ?? 0, type: n.type })),
        newControlledIdentities: [...new Set(i.affected.flatMap(a => a.newControlled))], newTier0PathsCount: all.length, sampleTier0Routes: all.slice(0, 5).map(routeView),
        safeguardsWeakened: i.safeguardsWeakened.map(id => ({ id, displayName: name(id) })), blastRadiusDelta: total,
        affectedIdentities: i.affected.map(a => ({ identityId: a.identity, newPowers: a.newPowers.map(p => ({ nodeId: p.node_id, action: p.action })), removedPowers: a.removedPowers.map(p => ({ nodeId: p.node_id, action: p.action })),
          newTier0Routes: a.newRoutes.map(routeView), blastRadiusDelta: a.delta, newControlledIdentities: a.newControlled, removedControlledIdentities: a.removedControlled })) } };
    }
    case 'IncidentService/ListIncidents': if (!org) throw forbid(); return { incidents: [...state.incidents].sort((a, b) => b.openedAt.localeCompare(a.openedAt)).map(incidentView) };
    case 'IncidentService/GetIncident': { if (!org) throw forbid(); const i = state.incidents.find(x => x.id === body.incidentId); if (!i) throw new ApiError(404, 'incident not found'); return { incident: incidentView(i) }; }
    case 'IncidentService/OpenIncident': {
      if (!org) throw forbid(); const p = state.plans.find(x => x.id === body.planId); if (!p) throw new ApiError(404, 'plan not found');
      let i = state.incidents.find(x => x.identity === p.identity && x.status !== 'RESOLVED');
      if (!i) { i = { id: `inc-${2000 + state.incidents.length + 1}`, title: `Manual containment review for ${name(p.identity)}`, severity: 'HIGH', status: 'OPEN', identity: p.identity, rootCause: 'MANUAL_CONTAINMENT', openedAt: at, actions: [], graphVersion: state.graphVersion }; state.incidents.push(i);
        await append('IncidentOpened', `incident:${i.id}`, actor, { incident_id: i.id, identity: p.identity }, at); }
      i.plan = p; return { incident: incidentView(i) };
    }
    case 'ContainmentService/PlanContainment': {
      if (!org) throw forbid(); const identity = String(body.compromisedIdentity);
      if (!state.graph.nodes.some(n => n.id === identity)) throw new ApiError(400, 'unknown identity');
      const result = planContainment(state.graph, identity);
      const id = `plan-${state.plans.length + 3001}`;
      const p: Plan = { id, identity, graphVersion: state.graphVersion, createdAt: at, result, digest: await digest({ id, identity, revocations: result.revocations.map(r => [r.action_type, r.resource_or_role]), graph_version: state.graphVersion }) };
      state.plans.push(p);
      const open = state.incidents.find(x => x.identity === identity && x.status === 'OPEN'); if (open) open.plan = p;
      await append('ContainmentPlanned', open ? `incident:${open.id}` : `containment:${id}`, actor, { plan_id: id, identity, actions: result.revocations.length, severed_tier0_routes: result.severed }, at);
      return { plan: planView(p) };
    }
    case 'ContainmentService/ExecuteContainment': {
      if (!isLead(actor)) throw forbid('containment requires a security lead');
      const p = state.plans.find(x => x.id === body.planId); if (!p) throw new ApiError(404, 'plan not found');
      if (body.approvedPlanDigest !== p.digest) throw new ApiError(409, 'passkey confirmation is bound to a different plan');
      let i = state.incidents.find(x => x.identity === p.identity && x.status !== 'RESOLVED');
      if (!i) { i = { id: `inc-${2000 + state.incidents.length + 1}`, title: `Containment of ${name(p.identity)}`, severity: 'HIGH', status: 'OPEN', identity: p.identity, rootCause: 'MANUAL_CONTAINMENT', openedAt: at, actions: [], graphVersion: state.graphVersion }; state.incidents.push(i); }
      i.plan = p; i.status = 'CONTAINING';
      await append('ContainmentExecuting', `incident:${i.id}`, actor, { plan_id: p.id, passkey: 'demo-simulated' }, at);
      for (const r of p.result.revocations) {
        state.graph = { ...state.graph, edges: state.graph.edges.filter(e => !((r.action_type === 'REVOKE_ROLE' && e.kind === 'ASSIGNED' && e.source === p.identity && e.target === r.resource_or_role) || (r.action_type === 'TERMINATE_SESSION' && e.kind === 'CAN_ASSUME' && e.source === r.resource_or_role))) };
        i.actions.push(`${r.action_type === 'TERMINATE_SESSION' ? 'Session terminated' : 'Role revoked'}: ${name(r.resource_or_role)} (verified by read-back)`);
        await append('ContainmentActionVerified', `incident:${i.id}`, 'connector:northwind-sim', { action_id: r.action_id, action_type: r.action_type, resource_or_role: r.resource_or_role, target_read_back: 'verified' }, at);
      }
      state.graphVersion++;
      for (const c of state.changes.filter(x => x.requester === p.identity && x.status === 'AWAITING_APPROVAL')) { c.status = 'HELD'; await step(c, 'ChangeContextChanged', 'core:workflow', at, { reason: `requester contained in incident ${i.id}` }); }
      for (const c of state.changes.filter(x => x.target === p.identity && x.status === 'EXECUTED' && x.expiryStatus === 'SCHEDULED')) c.expiryStatus = 'REVOKED';
      i.status = 'CONTAINED'; i.containedAt = new Date().toISOString(); i.graphVersion = state.graphVersion;
      i.actions.push(`Residual check: ${routes(state.graph, p.identity).length} routes to tier-0 assets remain`);
      await append('IncidentContained', `incident:${i.id}`, 'core:workflow', { incident_id: i.id, residual_tier0_routes: routes(state.graph, p.identity).length }, i.containedAt);
      return { executed: true, incidentId: i.id, executionResults: [], verifiedLatencyMs: '640' };
    }
    case 'ContainmentService/RestoreAccess': {
      if (!org) throw forbid(); const incident = state.incidents.find(x => x.id === body.incidentId); if (!incident) throw new ApiError(404, 'incident not found');
      const c = await submit({ requester: actor, kind: 'ROLE_ASSIGN', target: String(body.targetIdentity), access: String(body.accessToRestore), justification: String(body.justification ?? ''), emergency: false, timeLimit: 0, incident: incident.id, at });
      return { changeRequestId: c.id };
    }
    case 'AuditService/QueryAuditEvents': {
      if (!org) throw forbid();
      const stream = body.requestId ? `change:${body.requestId}` : body.incidentId ? `incident:${body.incidentId}` : '';
      const all = state.ledger.filter(e => !stream || e.stream === stream);
      const start = Number(body.pageToken || 0); const size = Number(body.pageSize || 50);
      return { events: all.slice(start, start + size).map(e => eventView(e)), ...(start + size < all.length ? { nextPageToken: String(start + size) } : {}) };
    }
    case 'AuditService/ExportHashChain': {
      if (!org) throw forbid(); const size = Number(body.pageSize || 100); if (size > 100) throw new ApiError(400, 'invalid change');
      const start = Number(body.pageToken || 0); const page = state.ledger.slice(start, start + size);
      return { tenantId: TENANT, chain: page.map(e => eventView(e, true)), snapshotEndHash: state.ledger[state.ledger.length - 1].hash, snapshotEndSequence: String(state.ledger.length), latestCheckpointDigest: '',
        ...(start + size < state.ledger.length ? { nextPageToken: String(start + size) } : {}) };
    }
  }
  throw new ApiError(404, '404 page not found');
}

async function rest(path: string, body: Body | undefined): Promise<unknown> {
  const route = path.split('?')[0];
  const query = new URLSearchParams(path.split('?')[1] ?? '');
  switch (route) {
    case '/api/setup': return { mode: 'RUNNING', governance: false, containment: true, demo: true };
    case '/api/auth/session': return { principal: { tenant_id: TENANT, actor_id: me() }, csrf_token: 'demo' };
    case '/api/auth/demo': state.session ??= 'user:rahul'; return { principal: { tenant_id: TENANT, actor_id: state.session }, csrf_token: 'demo' };
    case '/api/auth/login': {
      const actor = String(body?.actor_id ?? ''); if (!personas.some(p => p.id === actor)) throw new ApiError(401, 'Unknown demo persona. Use one of the persona buttons.');
      state.session = actor; return { principal: { tenant_id: TENANT, actor_id: actor }, csrf_token: 'demo' };
    }
    case '/api/auth/logout': state.session = null; return {};
    case '/api/console/bootstrap': {
      const actor = me(); const org = organization(actor);
      const shown = org ? state.graph.nodes : state.graph.nodes.filter(n => n.id === actor);
      const ids = new Set(shown.map(n => n.id));
      return { principal: { tenant_id: TENANT, actor_id: actor }, graph_version: state.graphVersion, scope: org ? 'ORGANIZATION' : 'SELF',
        nodes: shown.map(n => ({ id: n.id, type: n.type, display_name: n.name, ...(n.tier !== undefined ? { tier: n.tier } : {}) })),
        edges: state.graph.edges.filter(e => ids.has(e.source) && ids.has(e.target)).map((e, i) => ({ id: `edge:${i}`, source: e.source, target: e.target, kind: e.kind })) };
    }
    case '/api/console/approval-review': {
      const actor = me(); const c = change(query.get('request_id'), actor);
      if (c.status !== 'AWAITING_APPROVAL' || !eligible(c, actor)) throw forbid('independent review is limited to eligible reviewers');
      return { request_id: c.id, revision: c.revision, change_digest: c.digest, impact: c.bound, approvers: c.approvals };
    }
    case '/api/passkeys/list': { const actor = me(); return state.passkeys.filter(p => p.actor === actor).map(p => ({ credential_id: p.id, label: p.label, enrolled_at: p.enrolledAt, revoked: p.revoked })); }
    case '/api/passkeys/register/begin': return { session_id: 'demo-registration', options: { publicKey: { challenge: b64url(crypto.getRandomValues(new Uint8Array(32))), user: { id: b64url(new TextEncoder().encode(me())), name: me(), displayName: name(me()) } } } };
    case '/api/passkeys/register/finish': {
      const id = hexOf(crypto.getRandomValues(new Uint8Array(32)));
      state.passkeys.push({ actor: me(), id, label: query.get('label') || 'Demo passkey', enrolledAt: new Date().toISOString(), revoked: false }); return {};
    }
    case '/api/passkeys/revoke': { const p = state.passkeys.find(x => x.actor === me() && x.id === body?.credential_id); if (!p) throw new ApiError(404, 'credential not found'); p.revoked = true; return {}; }
    case '/api/passkeys/assert/begin': {
      const actor = me(); const nonce = hexOf(crypto.getRandomValues(new Uint8Array(32)));
      const digestHex = String(body?.change_digest ?? body?.containment_plan_digest ?? '');
      const prefix = new TextEncoder().encode(`RATCHET_APPROVAL_V1:${TENANT}:${actor}:`);
      const challenge = await sha256([prefix, Uint8Array.from(toBytes(digestHex)), Uint8Array.of(58), Uint8Array.from(toBytes(nonce))]);
      const credentials = state.passkeys.filter(p => p.actor === actor && !p.revoked);
      if (!credentials.length) throw forbid('register a passkey first');
      state.challenges.set(nonce, digestHex);
      return { session_id: nonce, challenge_nonce: nonce, options: { publicKey: { challenge: b64url(challenge), allowCredentials: credentials.map(p => ({ id: b64url(Uint8Array.from(toBytes(p.id))), type: 'public-key' })) } } };
    }
    case '/api/passkeys/assert/finish': return { submission: { credential_id: body?.credential_id, session_id: body?.session_id, demo: 'simulated passkey' } };
  }
  if (route.startsWith('/api/ratchet.v1.')) { const [service, method] = route.slice('/api/ratchet.v1.'.length).split('/'); return rpc(service, method, (body ?? {}) as Body); }
  throw new ApiError(404, '404 page not found');
}

export async function demoTransport(path: string, body?: unknown): Promise<unknown> {
  // Copy, as a server would: callers must never share objects with the demo state.
  const result = await rest(path, body as Body | undefined);
  return result === undefined ? undefined : JSON.parse(JSON.stringify(result));
}
export const demoPersona = () => state?.session ?? null;
