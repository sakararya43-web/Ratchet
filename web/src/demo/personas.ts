// Who a viewer can be in demo mode. Kept apart from the dataset so the live console stays lean.
export const TENANT = 'tenant-northwind-demo';

export type Persona = { id: string; name: string; role: string; summary: string; scope: 'SELF' | 'ORGANIZATION' };
export const personas: Persona[] = [
  { id: 'user:rahul', name: 'Rahul Sharma', role: 'Finance analyst · requester', summary: 'Submits access requests. Cannot approve a request they made.', scope: 'SELF' },
  { id: 'user:priya', name: 'Priya Patel', role: 'Finance lead · resource owner', summary: 'Owns the finance resources and approves access to them.', scope: 'SELF' },
  { id: 'user:alice', name: 'Alice Vance', role: 'Security lead 1 · responder', summary: 'Reviews tier-0 changes, investigates incidents and runs containment.', scope: 'ORGANIZATION' },
  { id: 'user:bob', name: 'Bob Chen', role: 'Security lead 2', summary: 'The second independent approval for any tier-0 change.', scope: 'ORGANIZATION' },
];
