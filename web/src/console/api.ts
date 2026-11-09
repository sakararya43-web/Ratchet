// Typed access to the core's console APIs. Every view reads real server state through
// these calls; nothing here fabricates records.
import { decode, request, rpc, type Change } from '../lib/api';

export type GraphNode = { id: string; type: string; tier?: number; displayName?: string; properties?: Record<string, string> };
export type GraphEdge = { source: string; target: string; kind: string; action?: string; properties?: Record<string, string> };
export type Route = { nodeIds?: string[]; edgeKinds?: string[]; edgeIds?: string[] };
export type Power = { nodeId: string; action: string };
export type Reach = { reachableNodes?: GraphNode[]; controlledIdentities?: string[]; reachByTier?: Record<string, number>; graphVersion?: string; powers?: Power[] };
export type NodeDetails = { node?: GraphNode; incomingEdges?: GraphEdge[]; outgoingEdges?: GraphEdge[]; graphVersion?: string };
export type Paths = { routes?: Route[]; graphVersion?: string; truncated?: boolean };
export type AttentionItem = { itemId: string; itemType: string; title: string; description?: string; severity?: string; createdAt?: string; entityId?: string };
export type Attention = { attentionItems?: AttentionItem[]; pendingRequests?: Change[]; activeIncidents?: Incident[] };
export type Revocation = { actionId?: string; actionType?: string; targetIdentity?: string; resourceOrRole?: string; reason?: string };
export type Activity = { resourceId?: string; resourceName?: string; permittedAction?: string; tier?: number; identityId?: string };
export type Plan = {
  planId: string; compromisedIdentity?: string; recommendedRevocations?: Revocation[]; preservedActivities?: Activity[]; disruptedActivities?: Activity[];
  severedTier0RoutesCount?: number; planDigest: string; graphVersion?: string; createdAt?: string; minimumProved?: boolean; optimalityScope?: string;
  proposedZeroTier0Proved?: boolean; disruptionCost?: string | number; policyBundleHash?: string; expiresAt?: string; algorithm?: string;
};
export type Incident = {
  incidentId: string; title?: string; severity?: string; status?: string; affectedIdentity?: string; rootCauseType?: string; containmentPlan?: Plan;
  actionsTaken?: string[]; openedAt?: string; containedAt?: string; resolvedAt?: string; residualRoutes?: Route[]; residualRoutesComplete?: boolean; observedGraphVersion?: string;
};
export type LedgerEvent = {
  sequenceNumber: string; eventType: string; eventPayloadJson?: string; previousEventHash: string; eventHash: string; recordedAt: string;
  canonicalContent?: string; streamId?: string; streamVersion?: string; eventId?: string; formatVersion?: number;
};
export type ImpactDiff = {
  graphVersion?: string; monotonicReduction?: boolean; newResources?: { id: string; displayName?: string; tier?: number; type?: string }[]; newControlledIdentities?: string[];
  newTier0PathsCount?: number; sampleTier0Routes?: Route[]; safeguardsWeakened?: { id: string; displayName?: string; description?: string }[]; blastRadiusDelta?: Record<string, number>;
  affectedIdentities?: { identityId: string; newPowers?: Power[]; removedPowers?: Power[]; newTier0Routes?: Route[]; blastRadiusDelta?: Record<string, number>; newControlledIdentities?: string[]; removedControlledIdentities?: string[] }[];
};
export type Passkey = { credential_id: string; label?: string; enrolled_at?: string; revoked?: boolean; last_used_at?: string };

export const nodeDetails = (tenantId: string, nodeId: string) => rpc<NodeDetails>('GraphService', 'GetNodeDetails', { tenantId, nodeId });
export const reach = (tenantId: string, identityId: string) => rpc<Reach>('GraphService', 'GetReach', { tenantId, identityId, pageSize: 200 });
export const pathsToCritical = (tenantId: string, identityId: string) => rpc<Paths>('GraphService', 'GetPathsToCritical', { tenantId, identityId, maxPaths: 20 });
export const attention = (tenantId: string) => rpc<Attention>('OverviewService', 'GetAttentionItems', { tenantId });
export const simulate = (tenantId: string, body: { kind: string; targetIdentity: string; requestedAccess: string; requestedBy: string }) =>
  rpc<{ impact?: ImpactDiff }>('ImpactService', 'SimulateChange', { tenantId, ...body });
export const listIncidents = (tenantId: string) => rpc<{ incidents?: Incident[] }>('IncidentService', 'ListIncidents', { tenantId, pageSize: 20 });
export const getIncident = (tenantId: string, incidentId: string) => rpc<{ incident?: Incident }>('IncidentService', 'GetIncident', { tenantId, incidentId });
export const auditEvents = (tenantId: string, filter: { requestId?: string; incidentId?: string; pageToken?: string; pageSize?: number }) =>
  rpc<{ events?: LedgerEvent[]; nextPageToken?: string }>('AuditService', 'QueryAuditEvents', { tenantId, pageSize: 50, ...filter });
export const exportChain = (tenantId: string, pageToken: string) =>
  rpc<{ chain?: LedgerEvent[]; nextPageToken?: string; snapshotEndHash?: string; snapshotEndSequence?: string; latestCheckpointDigest?: string; pagePreviousHash?: string }>(
    'AuditService', 'ExportHashChain', { tenantId, pageSize: 100, pageToken });
export const passkeys = () => request<Passkey[]>('/api/passkeys/list');

export function hex(value: unknown): string {
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) return value.map(b => Number(b).toString(16).padStart(2, '0')).join('');
  return '';
}
export function short(id: string | undefined, size = 8): string {
  if (!id) return '—';
  return id.length > size + 3 ? `${id.slice(0, size)}…` : id;
}
export function decodeJSON<T>(base64: string | undefined): T | null {
  if (!base64) return null;
  try { return JSON.parse(new TextDecoder().decode(decode(base64))) as T; } catch { return null; }
}

// The consequence the core assessed and bound into the approval envelope.
export type AssessedImpact = {
  reduction: boolean; safeguardsWeakened: string[];
  affected: { identityId: string; blastRadiusDelta: Record<string, number>; newPowers: Power[]; newResources: { id: string; tier?: number; type?: string }[]; newTier0Routes: Route[]; newControlled: string[] }[];
};
// Canonical decision evidence recorded when the core assessed a request.
export type Evidence = {
  eventSequence: number; eventHash: string; previousHash: string;
  change: { requester: string; createdAt: string; intent: { kind: string; target_identity: string; requested_access: string; emergency: boolean; time_limit_seconds: number };
    decision: { outcome: string; reasons: string[]; approver_groups: string[]; quorum: number };
    facts: { evaluator?: string; graphVersion?: number; owners: string[]; actorGroups: string[]; newTier0: boolean; tier0Weakening: boolean; reduction: boolean; registryEpoch?: number };
    impact: AssessedImpact;
    policyBundleHash: string; registryDigest?: string; graphVersion?: number };
  bundle: { version: string; description?: string; status?: string; epoch?: number; digest: string; activatedAt?: string; modules: Record<string, string>; owners: Record<string, string[]>;
    signatures: { actorId: string; signedAt?: string }[] } | null;
  registry: { epoch: number; thresholdM: number; totalN: number; members: { actorId: string; isActive: boolean; displayName?: string }[]; initializedAt?: string } | null;
  graph: { nodes: GraphNode[]; edges: GraphEdge[] } | null;
};
type RawEvidence = {
  event_sequence?: number; event_hash?: number[]; previous_hash?: number[];
  canonical_event?: { payload?: { facts?: { change?: Record<string, never> } } };
  signed_bundle?: Record<string, never>; registry_proof?: { genesis?: Record<string, never> };
  public_graph?: { nodes?: { id: string; type: string; tier?: number; display_name?: string }[]; edges?: { source: string; target: string; kind: string; action?: string }[] };
};
export async function decisionEvidence(tenantId: string, requestId: string): Promise<Evidence | null> {
  const r = await rpc<{ canonicalEvidenceJson?: string }>('ChangeService', 'GetDecisionEvidence', { tenantId, requestId });
  const raw = decodeJSON<RawEvidence>(r.canonicalEvidenceJson);
  if (!raw) return null;
  const c = (raw.canonical_event?.payload?.facts?.change ?? {}) as any;
  const b = raw.signed_bundle as any;
  const g = raw.registry_proof?.genesis as any;
  const input = c.decision_facts?.input ?? {};
  return {
    eventSequence: raw.event_sequence ?? 0, eventHash: hex(raw.event_hash), previousHash: hex(raw.previous_hash),
    change: {
      requester: c.requester ?? '', createdAt: c.created_at ?? '', intent: c.intent ?? {},
      decision: { outcome: c.decision?.outcome ?? '', reasons: c.decision?.reasons ?? [], approver_groups: c.decision?.approver_groups ?? [], quorum: c.decision?.quorum ?? 0 },
      facts: { evaluator: c.decision_facts?.evaluator, graphVersion: input.graph_version, owners: input.owners ?? [], actorGroups: input.actor_groups ?? [],
        newTier0: !!input.new_tier0, tier0Weakening: !!input.tier0_weakening, reduction: !!input.reduction, registryEpoch: input.registry_epoch },
      impact: {
        reduction: !!input.impact?.monotonic_reduction,
        safeguardsWeakened: (input.impact?.safeguards_weakened ?? []).map((w: { id?: string } | string) => (typeof w === 'string' ? w : w.id ?? '')),
        affected: (input.impact?.affected_identities ?? []).map((a: { identity_id: string; blast_radius_delta?: Record<string, number>; new_powers?: { node_id: string; action: string }[];
          new_resources?: { id: string; tier?: number; type?: string }[]; new_tier0_routes?: { node_ids?: string[]; edge_kinds?: string[] }[]; new_controlled_identities?: string[] }) => ({
          identityId: a.identity_id, blastRadiusDelta: a.blast_radius_delta ?? {}, newPowers: (a.new_powers ?? []).map(p => ({ nodeId: p.node_id, action: p.action })),
          newResources: a.new_resources ?? [], newTier0Routes: (a.new_tier0_routes ?? []).map(r => ({ nodeIds: r.node_ids, edgeKinds: r.edge_kinds })), newControlled: a.new_controlled_identities ?? [] })),
      },
      policyBundleHash: hex(c.approval_envelope?.policy_bundle_hash), registryDigest: input.registry_digest, graphVersion: c.approval_envelope?.graph_version ?? input.graph_version,
    },
    bundle: b ? { version: b.bundle_version, description: b.description, status: b.status, epoch: b.epoch, digest: hex(b.bundle_digest), activatedAt: b.activated_at,
      modules: b.modules ?? {}, owners: b.data?.resource_owners ?? {}, signatures: (b.signatures ?? []).map((s: { actor_id: string; signed_at?: string }) => ({ actorId: s.actor_id, signedAt: s.signed_at })) } : null,
    registry: g ? { epoch: g.epoch, thresholdM: g.threshold_m, totalN: g.total_n, initializedAt: g.initialized_at,
      members: (g.members ?? []).map((m: { actor_id: string; is_active: boolean; display_name?: string }) => ({ actorId: m.actor_id, isActive: m.is_active, displayName: m.display_name })) } : null,
    graph: raw.public_graph ? { nodes: (raw.public_graph.nodes ?? []).map(n => ({ id: n.id, type: n.type, tier: n.tier, displayName: n.display_name })), edges: raw.public_graph.edges ?? [] } : null,
  };
}

// The signed change policy is an ordered Rego rule chain; the first matching rule decides.
export type PolicyRule = { order: number; outcome: string; reasons: string[]; groups: string[]; quorum: number; conditions: string[] };
export function parsePolicyRules(rego: string | undefined): PolicyRule[] {
  if (!rego) return [];
  const rules: PolicyRule[] = [];
  // Stop before each block's closing brace: the next rule begins with that same "} else :=".
  const pattern = /(?:decision := |\} else := )(\{.*?\})(?: if \{\n([\s\S]*?)\n(?=\}))?/g;
  for (const match of rego.matchAll(pattern)) {
    try {
      const value = JSON.parse(match[1]) as { outcome: string; reasons: string[]; approver_groups: string[]; quorum: number };
      const conditions = (match[2] ?? '').split('\n').map(line => line.trim()).filter(Boolean);
      rules.push({ order: rules.length + 1, outcome: value.outcome, reasons: value.reasons, groups: value.approver_groups, quorum: value.quorum, conditions });
    } catch { /* A rule the summary cannot read is still shown in the source view. */ }
  }
  return rules;
}
const conditionText: Record<string, string> = {
  'not input.complete': 'The assessment context is incomplete',
  'input.tier0_weakening': 'The change weakens a tier-0 safeguard',
  'input.intent.emergency': 'The request is marked as an emergency',
  'input.intent.time_limit_seconds <= 0': 'No fixed duration is set',
  'input.scope.complete == false': 'Temporary access lacks explicit resources and permissions',
  'input.scope.over_broad': 'The role grants more than was explicitly requested',
  'input.reduction': 'Graph analysis proves the change only reduces access',
  'input.authorized_responder': 'Requested by an authorized responder',
  'input.intent.incident_id == ""': 'Not part of an incident restoration',
  'input.new_tier0': 'The change creates a new path to a tier-0 asset',
  'count(input.owners) > 0': 'The affected resources have registered owners',
};
export const readableCondition = (condition: string) => conditionText[condition] ?? condition;

export function decisionOf(c: Change): 'ALLOW' | 'REQUIRE_APPROVAL' | 'HOLD' | 'REJECT' {
  if (c.status === 'HELD') return 'HOLD';
  if (c.status === 'REJECTED') return 'REJECT';
  if ((c.requiredQuorum ?? 0) > 0) return 'REQUIRE_APPROVAL';
  return 'ALLOW';
}
