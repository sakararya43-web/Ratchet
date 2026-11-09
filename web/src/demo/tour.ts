// The guided tour: one story, Rahul's compromised session, told across every workspace.
import type { Focus, Tab } from '../console/context';

export type TourStep = { persona: string; tab: Tab; focus?: Focus; title: string; body: string; action?: string };

export const tour: TourStep[] = [
  { persona: 'user:rahul', tab: 'Changes', focus: { requestId: 'req-1001' }, title: 'Meet Rahul',
    body: 'Rahul is a finance analyst at Northwind, a fictional crypto exchange. Yesterday two security leads approved 48 hours of Wallet Operator access for Rahul’s month-end work. That grant is still active.',
    action: 'You are signed in as Rahul. The approved request is open in the request panel.' },
  { persona: 'user:rahul', tab: 'Changes', focus: { requestId: 'req-1006' }, title: 'The session turns hostile',
    body: 'Tonight, someone using Rahul’s laptop session asks to cut the withdrawal rule to a single approval. Policy rejects it outright: no approver can weaken a tier-0 safeguard.' },
  { persona: 'user:rahul', tab: 'Changes', focus: { requestId: 'req-1007' }, title: 'Then it asks for admin',
    body: 'Next it requests Exchange Administrator. RATCHET sends this to two independent security leads. The requester can never approve their own escalation.' },
  { persona: 'user:rahul', tab: 'Impact', focus: { identity: 'user:rahul', access: 'role:exchange-admin' }, title: 'What approval would unlock',
    body: 'Before anyone decides, RATCHET shows the consequence: the new powers and routes to critical assets this one role would add.',
    action: 'Press “Compute impact on server”.' },
  { persona: 'user:rahul', tab: 'Audit', title: 'A requester’s view is narrow',
    body: 'A requester sees their own requests and impact. Policy, incidents and the audit ledger belong to security leads. Next, the same story through Alice’s eyes.' },
  { persona: 'user:alice', tab: 'Overview', title: 'Alice, security lead',
    body: 'Alice sees the whole organisation. The attention queue shows a critical incident: suspicious escalation from Rahul’s session.' },
  { persona: 'user:alice', tab: 'Infrastructure', focus: { nodeId: 'user:rahul', trace: true }, title: 'Why it is dangerous',
    body: 'Traced from Rahul: the laptop session can act as Rahul, and the month-end Wallet Operator grant already reaches the Hot Wallet Signer, a tier-0 asset.' },
  { persona: 'user:alice', tab: 'Security policy', title: 'The rules that decided',
    body: 'Rule 02 rejected the safeguard change. Rule 07 requires two security leads for new tier-0 power. The policy is signed by Alice and Bob, two of two.' },
  { persona: 'user:alice', tab: 'Incidents', focus: { incidentId: 'inc-2002', identity: 'user:rahul' }, title: 'Plan the containment',
    body: 'RATCHET finds the cheapest set of revocations that cuts every route to tier-0 assets, and shows what keeps working.',
    action: 'Press “Compute containment plan”: end the laptop session and revoke Wallet Operator, while finance reports stay available.' },
  { persona: 'user:alice', tab: 'Incidents', focus: { incidentId: 'inc-2002', identity: 'user:rahul' }, title: 'Contain with a passkey',
    body: 'Execution is bound to the exact plan digest and confirmed with Alice’s passkey. Each action is read back from the target, and Rahul’s pending admin request is put on hold.',
    action: 'Press “Execute containment with passkey confirmation”, then “Use passkey”.' },
  { persona: 'user:alice', tab: 'Audit', title: 'Prove what happened',
    body: 'Every step above is an event in a SHA-256 hash chain, including the ones you just created. Restoring Rahul later is a new, independently reviewed request.',
    action: 'Press “Verify audit chain”. Your browser recomputes every link.' },
];
