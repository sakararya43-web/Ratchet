import { createContext, useContext } from 'react';
import type { Bootstrap, Change } from '../lib/api';

export const tabs = ['Overview', 'Changes', 'Infrastructure', 'Impact', 'Security policy', 'Incidents', 'Audit', 'Passkeys'] as const;
export type Tab = typeof tabs[number];

// A focus target lets one workspace open a specific record in another.
export type Focus = { requestId?: string; nodeId?: string; trace?: boolean; incidentId?: string; identity?: string; access?: string; filter?: string } | null;

export type ConsoleContextValue = {
  tenantId: string;
  actor: string;
  scope: string;
  organization: boolean;
  bootstrap: Bootstrap | null;
  changes: Change[];
  busy: boolean;
  focus: Focus;
  go: (tab: Tab, focus?: Focus) => void;
  inspect: (nodeId: string) => void;
  work: (action: () => Promise<void>) => Promise<void>;
  notify: (message: string) => void;
  reloadChanges: () => Promise<void>;
};

export const ConsoleContext = createContext<ConsoleContextValue | null>(null);
export function useConsole(): ConsoleContextValue {
  const value = useContext(ConsoleContext);
  if (!value) throw new Error('Console context missing');
  return value;
}

export function nodeName(bootstrap: Bootstrap | null, id: string | undefined): string {
  if (!id) return '—';
  const node = bootstrap?.nodes.find(n => n.id === id);
  return node?.display_name || id;
}
export function nodeType(bootstrap: Bootstrap | null, id: string): string {
  return bootstrap?.nodes.find(n => n.id === id)?.type ?? (id.startsWith('user:') ? 'Human' : id.startsWith('role:') ? 'Role' : id.startsWith('res:') || id.startsWith('svc:') ? 'Resource' : 'Node');
}
