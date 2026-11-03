export interface Identity {
  id: string;
  type: string;
  display_name: string;
  department?: string;
  email?: string;
  is_disabled: boolean;
  properties?: Record<string, string>;
}

export interface Role {
  id: string;
  display_name: string;
  description?: string;
  permissions: string[];
}

export interface Resource {
  id: string;
  type: string;
  tier: number; // 0, 1, 2, 3
  display_name: string;
  description?: string;
}

export interface Safeguard {
  id: string;
  tier: number;
  display_name: string;
  description: string;
  protected_resources: string[];
  parameters?: Record<string, string>;
}

export interface Grant {
  id: string;
  identity_id: string;
  role_id: string;
  granted_at: string;
  granted_by: string;
}

export interface ControlRelation {
  controller_id: string;
  controlled_id: string;
  kind: string;
}

export interface Session {
  session_id: string;
  identity_id: string;
  device_id: string;
  created_at: string;
  last_seen_at: string;
  is_revoked: boolean;
}

export interface TargetAuditEntry {
  revision: number;
  timestamp: string;
  actor_id: string;
  action: string;
  target: string;
  before_state?: string;
  after_state?: string;
  details?: Record<string, string>;
}

export interface OrgState {
  tenant_id: string;
  revision: number;
  identities: Identity[];
  roles: Role[];
  resources: Resource[];
  safeguards: Safeguard[];
  grants: Grant[];
  control_relations: ControlRelation[];
  sessions: Session[];
  audit_log: TargetAuditEntry[];
}

export interface ResourceSummary {
  id: string;
  type: string;
  tier: number;
  display_name: string;
}

export interface SafeguardSummary {
  id: string;
  tier: number;
  description: string;
}

export interface ImpactDiff {
  monotonic_reduction: boolean;
  new_resources: ResourceSummary[];
  new_controlled_identities: string[];
  new_tier0_paths_count: number;
  sample_tier0_routes: Array<{
    node_ids: string[];
    edge_kinds: string[];
  }>;
  safeguards_weakened: SafeguardSummary[];
  blast_radius_delta: Record<string, number>;
  graph_version: number;
}

// Fetch the complete live organization state from the simulator backend
export async function fetchOrgState(): Promise<OrgState> {
  const resp = await fetch('/api/v1/org');
  if (!resp.ok) {
    throw new Error(`Failed to fetch org state: HTTP ${resp.status}`);
  }
  return resp.json();
}

// Access probe verification
export async function probeAccess(
  identityId: string,
  resourceId: string,
  action: string
): Promise<{ allowed: boolean; reason: string }> {
  const resp = await fetch('/api/v1/probe', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      identity_id: identityId,
      resource_id: resourceId,
      action: action,
    }),
  });
  if (!resp.ok) {
    throw new Error(`Probe failed: HTTP ${resp.status}`);
  }
  return resp.json();
}

// Passkey Assertion Submission
export async function submitPasskeyAssertion(
  tenantId: string,
  actorId: string,
  changeDigestHex: string
): Promise<{
  verified: boolean;
  verified_at: string;
  actor_id: string;
  credential_id: string;
  user_verified: boolean;
  change_digest: string;
}> {
  const resp = await fetch('/api/v1/passkey/assert/simulate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      tenant_id: tenantId,
      actor_id: actorId,
      change_digest: changeDigestHex,
    }),
  });
  if (!resp.ok) {
    const errText = await resp.text();
    throw new Error(`Passkey assertion verification failed: ${errText}`);
  }
  return resp.json();
}

// Execute IAM command via Connector Broker
export async function executeConnectorCommand(
  commandId: string,
  action: 'ASSIGN_ROLE' | 'REVOKE_ROLE' | 'TERMINATE_SESSION' | 'RESTRICT_ACCOUNT',
  targetIdentity: string,
  resourceOrRole: string,
  brokerToken: string = 'sim-broker-secret'
): Promise<{
  command_id: string;
  success: boolean;
  revision: number;
  observed_state: {
    target_identity: string;
    current_roles: string[];
    active_sessions: string[];
    is_restricted: boolean;
  };
}> {
  const resp = await fetch('/api/v1/execute', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${brokerToken}`,
    },
    body: JSON.stringify({
      command_id: commandId,
      action: action,
      target_identity: targetIdentity,
      resource_or_role: resourceOrRole,
    }),
  });
  if (!resp.ok) {
    const errText = await resp.text();
    throw new Error(`Connector execution failed (HTTP ${resp.status}): ${errText}`);
  }
  return resp.json();
}

// Business Endpoint: Finance Report Read
export async function readBusinessFinanceReport(sessionId: string): Promise<{
  status: string;
  actor?: string;
  report?: any;
  reason?: string;
}> {
  const resp = await fetch('/api/v1/business/finance-report/read', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ session_id: sessionId }),
  });
  return resp.json();
}

// Simulate Draft Change
// Evaluates what newly accessible tier-0 assets and routes would be created
export function computeSimulationDiff(
  org: OrgState,
  targetIdentityId: string,
  proposedRoleId: string
): ImpactDiff {
  const targetRole = org.roles.find((r) => r.id === proposedRoleId);
  const targetIdentity = org.identities.find((i) => i.id === targetIdentityId);

  if (!targetRole || !targetIdentity) {
    return {
      monotonic_reduction: false,
      new_resources: [],
      new_controlled_identities: [],
      new_tier0_paths_count: 0,
      sample_tier0_routes: [],
      safeguards_weakened: [],
      blast_radius_delta: { tier0: 0, tier1: 0, tier2: 0, tier3: 0 },
      graph_version: org.revision,
    };
  }

  // Find permissions that target already has
  const existingRoleIds = new Set(
    org.grants.filter((g) => g.identity_id === targetIdentityId).map((g) => g.role_id)
  );

  const existingPermissions = new Set<string>();
  for (const roleId of existingRoleIds) {
    const role = org.roles.find((r) => r.id === roleId);
    if (role) {
      role.permissions.forEach((p) => existingPermissions.add(p));
    }
  }

  // Check new permissions introduced by the proposed role
  const newResourcesMap = new Map<string, ResourceSummary>();
  const sampleRoutes: Array<{ node_ids: string[]; edge_kinds: string[] }> = [];
  const blastDelta = { tier0: 0, tier1: 0, tier2: 0, tier3: 0 };
  let newTier0Paths = 0;

  for (const perm of targetRole.permissions) {
    if (existingPermissions.has(perm)) {
      continue;
    }

    // Parse perm e.g. "svc:wallet-signer:admin"
    const lastColon = perm.lastIndexOf(':');
    const resId = lastColon !== -1 ? perm.substring(0, lastColon) : perm;
    const res = org.resources.find((r) => r.id === resId);

    if (res) {
      if (!newResourcesMap.has(res.id)) {
        newResourcesMap.set(res.id, {
          id: res.id,
          type: res.type,
          tier: res.tier,
          display_name: res.display_name,
        });

        if (res.tier === 0) {
          blastDelta.tier0++;
          newTier0Paths++;
          sampleRoutes.push({
            node_ids: [targetIdentityId, proposedRoleId, res.id],
            edge_kinds: ['PROPOSED_ASSIGN', 'GRANTS'],
          });
        } else if (res.tier === 1) {
          blastDelta.tier1++;
        } else if (res.tier === 2) {
          blastDelta.tier2++;
        } else {
          blastDelta.tier3++;
        }
      }
    }
  }

  // Check weakened safeguards
  const weakenedSafeguards: SafeguardSummary[] = [];
  if (targetRole.permissions.some((p) => p.includes('safeguard:withdrawal-rule'))) {
    const sg = org.safeguards.find((s) => s.id === 'safeguard:withdrawal-rule');
    if (sg) {
      weakenedSafeguards.push({
        id: sg.id,
        tier: sg.tier,
        description: 'Proposed role introduces modification access to withdrawal threshold rule',
      });
    }
  }

  return {
    monotonic_reduction: false,
    new_resources: Array.from(newResourcesMap.values()),
    new_controlled_identities: [],
    new_tier0_paths_count: newTier0Paths,
    sample_tier0_routes: sampleRoutes,
    safeguards_weakened: weakenedSafeguards,
    blast_radius_delta: blastDelta,
    graph_version: org.revision,
  };
}

// ==========================================
// Independent Authority Governance API
// ==========================================

export interface AuthorityMember {
  actor_id: string;
  display_name: string;
  public_key: string;
  enrolled_at?: string;
  is_active: boolean;
}

export interface GenesisState {
  tenant_id: string;
  threshold_m: number;
  total_n: number;
  epoch: number;
  members: AuthorityMember[];
  genesis_digest: number[];
  initialized_at: string;
}

export interface MemberSignature {
  actor_id: string;
  signature: string;
  signed_at: string;
}

export interface PolicyBundle {
  proposal_id: string;
  tenant_id: string;
  bundle_version: string;
  description: string;
  epoch: number;
  modules: Record<string, string>;
  data: Record<string, any>;
  bundle_digest: number[];
  signatures: MemberSignature[];
  status: 'PROPOSED' | 'ACTIVE' | 'SUPERSEDED';
  proposed_at: string;
  activated_at?: string;
}

export interface RegistryHistoryEntry {
  epoch: number;
  threshold_m: number;
  total_n: number;
  members: AuthorityMember[];
  activated_at: string;
  approved_by: string[];
}

export async function fetchAuthorityRegistry(): Promise<GenesisState> {
  const resp = await fetch('/api/v1/authority/registry');
  if (!resp.ok) {
    throw new Error(`Failed to fetch authority registry: HTTP ${resp.status}`);
  }
  return resp.json();
}

export async function fetchRegistryHistory(): Promise<RegistryHistoryEntry[]> {
  const resp = await fetch('/api/v1/authority/registry/history');
  if (!resp.ok) {
    throw new Error(`Failed to fetch registry history: HTTP ${resp.status}`);
  }
  return resp.json();
}

export async function fetchActiveBundle(): Promise<PolicyBundle> {
  const resp = await fetch('/api/v1/authority/bundle/active');
  if (!resp.ok) {
    throw new Error(`Failed to fetch active bundle: HTTP ${resp.status}`);
  }
  return resp.json();
}

export async function fetchPolicyProposals(): Promise<PolicyBundle[]> {
  const resp = await fetch('/api/v1/authority/bundle/proposals');
  if (!resp.ok) {
    throw new Error(`Failed to fetch policy proposals: HTTP ${resp.status}`);
  }
  return resp.json();
}

export async function fetchBundleHistory(): Promise<PolicyBundle[]> {
  const resp = await fetch('/api/v1/authority/bundle/history');
  if (!resp.ok) {
    throw new Error(`Failed to fetch bundle history: HTTP ${resp.status}`);
  }
  return resp.json();
}

export async function proposePolicyBundle(
  tenantId: string,
  bundleVersion: string,
  description: string,
  modules: Record<string, string>,
  data: Record<string, any>
): Promise<PolicyBundle> {
  const resp = await fetch('/api/v1/authority/bundle/propose', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      tenant_id: tenantId,
      bundle_version: bundleVersion,
      description: description,
      modules: modules,
      data: data,
    }),
  });
  if (!resp.ok) {
    const errText = await resp.text();
    throw new Error(`Failed to propose bundle: ${errText}`);
  }
  return resp.json();
}

export async function signPolicyBundle(
  proposalId: string,
  actorId: string,
  signatureHex: string
): Promise<{ success: boolean }> {
  const resp = await fetch('/api/v1/authority/bundle/sign', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      proposal_id: proposalId,
      actor_id: actorId,
      signature: signatureHex,
    }),
  });
  if (!resp.ok) {
    const errText = await resp.text();
    throw new Error(`Failed to sign proposal: ${errText}`);
  }
  return resp.json();
}

export async function activatePolicyBundle(proposalId: string): Promise<PolicyBundle> {
  const resp = await fetch('/api/v1/authority/bundle/activate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ proposal_id: proposalId }),
  });
  if (!resp.ok) {
    const errText = await resp.text();
    throw new Error(`Failed to activate bundle: ${errText}`);
  }
  return resp.json();
}

export interface ContainmentAction {
  action_id: string;
  action_type: 'TERMINATE_SESSION' | 'REVOKE_ROLE' | 'RESTRICT_ACCOUNT' | 'REMOVE_SERVICE_PERMISSION';
  target_identity: string;
  target_resource_or_session: string;
  correlation_id: string;
}

export interface ContainmentPlan {
  plan_id: string;
  tenant_id: string;
  incident_id: string;
  target_identity: string;
  actions: ContainmentAction[];
  plan_digest: string;
  confirmed_by?: string;
}

export interface ContainmentActionResult {
  action_id: string;
  action_type: string;
  target_identity: string;
  success: boolean;
  error_message?: string;
  latency_ms: number;
}

export interface ContainmentPlanResult {
  plan_id: string;
  incident_id: string;
  total_actions: number;
  succeeded_actions: number;
  failed_actions: number;
  action_results: ContainmentActionResult[];
  total_latency_ms: number;
}

export interface AuditCheckpoint {
  checkpoint_id: string;
  tenant_id: string;
  epoch: number;
  from_sequence: number;
  to_sequence: number;
  merkle_root: string;
  checkpoint_digest: string;
  signatures: MemberSignature[];
  signed_at: string;
}

export interface AuditEvent {
  sequence: number;
  timestamp: string;
  tenant_id: string;
  event_type: string;
  actor_id: string;
  target_identity?: string;
  action?: string;
  payload: Record<string, any>;
  previous_event_hash: string;
  event_digest: string;
}

export interface AuditExportBundle {
  tenant_id: string;
  exported_at: string;
  events: AuditEvent[];
  checkpoints: AuditCheckpoint[];
  genesis: GenesisState;
  credential_history: Array<{
    tenant_id: string;
    actor_id: string;
    public_key: string;
    enrolled_at: string;
    is_revoked: boolean;
  }>;
}

export async function executeSimulatorCommand(
  action: string,
  targetIdentity: string,
  resourceOrRole: string,
  brokerToken: string = 'sim-broker-secret'
): Promise<{ success: boolean; revision: number; error_message?: string }> {
  const resp = await fetch('/api/v1/execute', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${brokerToken}`,
    },
    body: JSON.stringify({
      action,
      target_identity: targetIdentity,
      resource_or_role: resourceOrRole,
    }),
  });

  if (!resp.ok) {
    const errText = await resp.text();
    return { success: false, revision: 0, error_message: errText };
  }

  const data = await resp.json();
  return { success: true, revision: data.revision };
}

export async function fetchCheckpoints(): Promise<AuditCheckpoint[]> {
  try {
    const resp = await fetch('/api/v1/authority/checkpoint/list');
    if (!resp.ok) return [];
    return resp.json();
  } catch {
    return [];
  }
}

export async function executeProbe(
  identityId: string,
  sessionId: string,
  resourceId: string,
  action: string
): Promise<{ allowed: boolean; reason: string }> {
  const resp = await fetch('/api/v1/probe', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      identity_id: identityId,
      session_id: sessionId,
      resource_id: resourceId,
      action: action,
    }),
  });
  if (!resp.ok) {
    return { allowed: false, reason: `HTTP ${resp.status}` };
  }
  return resp.json();
}



