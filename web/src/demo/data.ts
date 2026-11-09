// The demo dataset: one fictional exchange and one story, used by every console tab.
// Kept deliberately small: enough to show each feature, nothing more.
import changeRego from '../../../policies/change.rego?raw';

export { TENANT, personas, type Persona } from './personas';

export type DemoNode = { id: string; type: string; name: string; tier?: number; properties?: Record<string, string> };
export type DemoEdge = { source: string; target: string; kind: string; action?: string };

export const nodes: DemoNode[] = [
  { id: 'user:rahul', type: 'Human', name: 'Rahul Sharma (Finance Analyst)', properties: { team: 'Finance', manager: 'user:priya' } },
  { id: 'user:meera', type: 'Human', name: 'Meera Iyer (Finance Associate)', properties: { team: 'Finance', manager: 'user:priya' } },
  { id: 'user:priya', type: 'Human', name: 'Priya Patel (Finance Lead)', properties: { team: 'Finance' } },
  { id: 'user:alice', type: 'Human', name: 'Alice Vance (Security Lead)', properties: { team: 'Security' } },
  { id: 'user:bob', type: 'Human', name: 'Bob Chen (Security Lead)', properties: { team: 'Security' } },
  { id: 'user:david', type: 'Human', name: 'David Kim (Platform Admin)', properties: { team: 'Platform' } },
  { id: 'svc:reporting-worker', type: 'ServiceAccount', name: 'Nightly Reporting Worker', properties: { owner: 'user:priya' } },
  { id: 'svc:withdrawal-worker', type: 'ServiceAccount', name: 'Withdrawal Processor', properties: { owner: 'user:david' } },
  { id: 'session:rahul-laptop', type: 'Session', name: 'Rahul’s laptop session', properties: { device: 'FIN-LT-0142', owner: 'user:rahul' } },
  { id: 'group:finance', type: 'Group', name: 'Finance team' },
  { id: 'role:finance-analyst', type: 'Role', name: 'Finance Analyst' },
  { id: 'role:finance-lead', type: 'Role', name: 'Finance Lead' },
  { id: 'role:security-lead', type: 'Role', name: 'Security Lead' },
  { id: 'role:wallet-operator', type: 'Role', name: 'Wallet Operator (tier 0)' },
  { id: 'role:exchange-admin', type: 'Role', name: 'Exchange Administrator (tier 0)' },
  { id: 'role:staging-developer', type: 'Role', name: 'Staging Developer' },
  { id: 'svc:wallet-signer', type: 'Resource', name: 'Hot Wallet Signer', tier: 0 },
  { id: 'res:customer-db', type: 'Resource', name: 'Customer & KYC Database', tier: 0 },
  { id: 'res:finance-reports', type: 'Resource', name: 'Finance Reports', tier: 2 },
  { id: 'res:transaction-history', type: 'Resource', name: 'Transaction History', tier: 2 },
  { id: 'res:daily-ledger', type: 'Resource', name: 'Daily Exchange Ledger', tier: 1 },
  { id: 'res:staging-env', type: 'Resource', name: 'Staging Environment', tier: 3 },
  { id: 'safeguard:withdrawal-rule', type: 'Safeguard', name: 'Dual-Control Withdrawal Rule', tier: 0 },
  { id: 'safeguard:admin-mfa', type: 'Safeguard', name: 'Hardware MFA for Admins', tier: 1 },
];

// The organisation before the story. Rahul holds wallet access from a reviewed,
// time-limited month-end grant: that is what makes the compromise dangerous.
export const edges: DemoEdge[] = [
  { source: 'user:rahul', target: 'group:finance', kind: 'MEMBER_OF' },
  { source: 'user:meera', target: 'group:finance', kind: 'MEMBER_OF' },
  { source: 'group:finance', target: 'role:finance-analyst', kind: 'ASSIGNED' },
  { source: 'user:priya', target: 'role:finance-lead', kind: 'ASSIGNED' },
  { source: 'user:alice', target: 'role:security-lead', kind: 'ASSIGNED' },
  { source: 'user:bob', target: 'role:security-lead', kind: 'ASSIGNED' },
  { source: 'user:david', target: 'role:exchange-admin', kind: 'ASSIGNED' },
  { source: 'user:rahul', target: 'role:wallet-operator', kind: 'ASSIGNED' },
  { source: 'svc:withdrawal-worker', target: 'role:wallet-operator', kind: 'ASSIGNED' },
  { source: 'svc:reporting-worker', target: 'role:finance-analyst', kind: 'ASSIGNED' },
  { source: 'session:rahul-laptop', target: 'user:rahul', kind: 'CAN_ASSUME' },
  { source: 'role:finance-analyst', target: 'res:finance-reports', kind: 'GRANTS', action: 'read' },
  { source: 'role:finance-analyst', target: 'res:transaction-history', kind: 'GRANTS', action: 'read' },
  { source: 'role:finance-lead', target: 'res:finance-reports', kind: 'GRANTS', action: 'approve' },
  { source: 'role:finance-lead', target: 'res:daily-ledger', kind: 'GRANTS', action: 'read' },
  { source: 'role:wallet-operator', target: 'svc:wallet-signer', kind: 'GRANTS', action: 'sign' },
  { source: 'role:exchange-admin', target: 'svc:wallet-signer', kind: 'GRANTS', action: 'admin' },
  { source: 'role:exchange-admin', target: 'res:customer-db', kind: 'GRANTS', action: 'admin' },
  { source: 'role:exchange-admin', target: 'safeguard:withdrawal-rule', kind: 'CAN_MODIFY' },
  { source: 'role:staging-developer', target: 'res:staging-env', kind: 'GRANTS', action: 'write' },
  { source: 'role:security-lead', target: 'svc:wallet-signer', kind: 'CAN_APPROVE' },
  { source: 'svc:wallet-signer', target: 'safeguard:withdrawal-rule', kind: 'PROTECTED_BY' },
  { source: 'res:customer-db', target: 'safeguard:admin-mfa', kind: 'PROTECTED_BY' },
];

// Who may approve access to each resource (from the signed policy bundle data).
export const resourceOwners: Record<string, string[]> = {
  'res:finance-reports': ['user:priya'], 'res:transaction-history': ['user:priya'], 'res:daily-ledger': ['user:priya'],
  'res:staging-env': ['user:david'], 'svc:wallet-signer': ['user:alice', 'user:bob'], 'res:customer-db': ['user:alice', 'user:bob'],
};

export const policy = {
  rego: changeRego,
  authz: 'package ratchet.authz\n\n# Organisation-wide views (graph detail, incidents, audit, policy) are limited to security leads.\nallow if input.actor_groups[_] == "role:security-lead"\n',
  bundles: [
    { version: '1.0.0', description: 'Initial governed policy for Northwind Exchange', activatedDaysAgo: 30, status: 'SUPERSEDED', signers: ['user:alice', 'user:bob'] },
    { version: '1.1.0', description: 'Adds dual control for tier-0 roles and blocks safeguard weakening', activatedDaysAgo: 6, status: 'ACTIVE', signers: ['user:alice', 'user:bob'] },
  ],
  registry: { epoch: 2, thresholdM: 2, members: ['user:alice', 'user:bob'], establishedDaysAgo: 30 },
};

// Requests already in the ledger when the demo opens. Times are relative (hours ago).
export type SeedRequest = {
  id: string; requester: string; kind: 'ROLE_ASSIGN' | 'ROLE_REVOKE' | 'MODIFY_SAFEGUARD'; target: string; access: string; justification: string;
  hoursAgo: number; emergency?: boolean; timeLimitSeconds?: number; approvers?: string[]; outcome?: 'EXECUTED' | 'AWAITING_APPROVAL' | 'HELD' | 'REJECTED' | 'EXPIRED' | 'REVOKED';
  expiresInHours?: number;
};
export const seedRequests: SeedRequest[] = [
  { id: 'req-1001', requester: 'user:rahul', kind: 'ROLE_ASSIGN', target: 'user:rahul', access: 'role:wallet-operator', justification: 'Month-end settlement reconciliation needs signing access for 48 hours.',
    hoursAgo: 30, timeLimitSeconds: 172800, approvers: ['user:alice', 'user:bob'], outcome: 'EXECUTED', expiresInHours: 18 },
  { id: 'req-1002', requester: 'user:meera', kind: 'ROLE_ASSIGN', target: 'user:meera', access: 'role:finance-lead', justification: 'Covering Priya’s approvals while she is on leave.',
    hoursAgo: 52, approvers: [], outcome: 'EXPIRED' },
  { id: 'req-1003', requester: 'user:meera', kind: 'ROLE_ASSIGN', target: 'user:meera', access: 'role:staging-developer', justification: 'Test the new settlement export in staging for one hour.',
    hoursAgo: 26, timeLimitSeconds: 3600, approvers: ['user:david'], outcome: 'REVOKED' },
  { id: 'req-1004', requester: 'user:alice', kind: 'ROLE_REVOKE', target: 'user:david', access: 'role:staging-developer', justification: 'Platform admins no longer deploy to staging directly.',
    hoursAgo: 20, outcome: 'EXECUTED' },
  { id: 'req-1005', requester: 'user:david', kind: 'ROLE_ASSIGN', target: 'user:david', access: 'role:finance-lead', justification: 'Emergency: need ledger access to debug a settlement job.',
    hoursAgo: 9, emergency: true, outcome: 'HELD' },
  // The story: Rahul's session, now controlled by an attacker, reaches for more power.
  { id: 'req-1006', requester: 'user:rahul', kind: 'MODIFY_SAFEGUARD', target: 'safeguard:withdrawal-rule', access: 'withdrawal-approvals:1', justification: 'Single approval is enough for small withdrawals tonight.',
    hoursAgo: 0.9, outcome: 'REJECTED' },
  { id: 'req-1007', requester: 'user:rahul', kind: 'ROLE_ASSIGN', target: 'user:rahul', access: 'role:exchange-admin', justification: 'Need admin to fix a stuck withdrawal batch urgently.',
    hoursAgo: 0.7, outcome: 'AWAITING_APPROVAL' },
];

export const seedIncidents = [
  { id: 'inc-2001', title: 'Unapproved change to admin MFA policy', severity: 'MEDIUM', status: 'RESOLVED', identity: 'user:david', rootCause: 'DRIFT', hoursAgo: 72, resolvedHoursAgo: 70,
    actions: ['Drift detected: MFA requirement disabled outside RATCHET', 'Change reverted by the connector and read back', 'Resolved after owner confirmation'] },
  { id: 'inc-2002', title: 'Suspicious escalation from Rahul Sharma’s session', severity: 'CRITICAL', status: 'OPEN', identity: 'user:rahul', rootCause: 'SUSPICIOUS_ESCALATION', hoursAgo: 0.5,
    actions: ['Safeguard-weakening request rejected by policy', 'Exchange Administrator request sent to two security leads', 'Session flagged: unusual device location'] },
];

// Relative cost of each revocation kind for the minimum-disruption cut (operator configuration).
export const containmentCosts: Record<string, number> = { TERMINATE_SESSION: 1, REVOKE_ROLE: 5, RESTRICT_ACCOUNT: 100 };
