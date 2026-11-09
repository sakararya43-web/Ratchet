import { useEffect, useState, type ReactNode } from 'react';
import { ArrowUpRight, Network, ScanLine, Route as RouteIcon } from 'lucide-react';
import { ApiError } from '../lib/api';
import { nodeDetails, pathsToCritical, reach, type NodeDetails, type Paths, type Reach } from './api';
import { nodeName, useConsole } from './context';
import { edgeLabel } from './GraphCanvas';
import { EntityLink, Inspector, KeyValues, StatusBadge, Tabs, TierBadge, When } from './ui';

const identityTypes = new Set(['Human', 'ServiceAccount', 'Session']);
const identityViews = ['Overview', 'Access', 'Relationships', 'Activity'] as const;
const resourceViews = ['Overview', 'Accessors', 'Safeguards', 'Related changes'] as const;

export function EntityInspector({ nodeId, onClose }: { nodeId: string; onClose: () => void }) {
  const { tenantId, bootstrap, changes, go } = useConsole();
  const known = bootstrap?.nodes.find(n => n.id === nodeId);
  const [details, setDetails] = useState<NodeDetails | null>(null);
  const [power, setPower] = useState<Reach | null>(null);
  const [paths, setPaths] = useState<Paths | null>(null);
  const [restricted, setRestricted] = useState(false);
  const [view, setView] = useState<string>('Overview');
  const type = details?.node?.type ?? known?.type ?? '';
  const isIdentity = identityTypes.has(type) || nodeId.startsWith('user:') || nodeId.startsWith('svc-account:');
  useEffect(() => {
    let live = true;
    setDetails(null); setPower(null); setPaths(null); setRestricted(false); setView('Overview');
    void nodeDetails(tenantId, nodeId).then(d => { if (live) setDetails(d); }).catch(e => { if (live && e instanceof ApiError && e.status === 403) setRestricted(true); });
    void reach(tenantId, nodeId).then(r => { if (live) setPower(r); }).catch(() => undefined);
    void pathsToCritical(tenantId, nodeId).then(p => { if (live) setPaths(p); }).catch(() => undefined);
    return () => { live = false; };
  }, [tenantId, nodeId]);
  const incoming = details?.incomingEdges ?? [];
  const outgoing = details?.outgoingEdges ?? [];
  const related = changes.filter(c => c.targetIdentity === nodeId || c.requestedBy === nodeId || c.requestedAccess === nodeId);
  const tier = details?.node?.tier ?? known?.tier;
  const accessors = incoming.filter(e => e.kind === 'GRANTS' || e.kind === 'CAN_MODIFY' || e.kind === 'CAN_ADMINISTER');
  const safeguards = outgoing.filter(e => e.kind === 'PROTECTED_BY');
  const routes = paths?.routes ?? [];
  return <Inspector eyebrow={`${(type || 'entity').toUpperCase()} · GRAPH ${details?.graphVersion ?? bootstrap?.graph_version ?? '—'}`} title={details?.node?.displayName || known?.display_name || nodeId} onClose={onClose} testId="entity-inspector">
    <p className="inspector-id"><code>{nodeId}</code>{(type === 'Resource' || type === 'Safeguard') && <TierBadge tier={tier}/>}</p>
    {restricted && <p className="inline-note">Organization graph detail for this entity requires investigator authorization. Showing only what your account may see.</p>}
    <div className="inspector-actions">
      <button type="button" onClick={() => go('Infrastructure', { nodeId })}><Network size={13}/> Show in graph</button>
      {isIdentity && <button type="button" onClick={() => go('Infrastructure', { nodeId, trace: true })}><RouteIcon size={13}/> Trace to tier 0</button>}
      {isIdentity && <button type="button" onClick={() => go('Impact', { identity: nodeId })}><ScanLine size={13}/> Simulate a change</button>}
      {!isIdentity && type === 'Role' && <button type="button" onClick={() => go('Impact', { access: nodeId })}><ScanLine size={13}/> Simulate granting</button>}
    </div>
    <Tabs options={isIdentity ? identityViews : resourceViews} value={view as never} onChange={setView}/>
    {view === 'Overview' && <KeyValues rows={[
      ['Type', type || '—'], ['Display name', details?.node?.displayName || known?.display_name || '—'],
      ...Object.entries(details?.node?.properties ?? {}).map(([k, v]) => [k.replace(/_/g, ' '), k === 'supervisor' || k === 'owner' ? <EntityLink id={v}/> : v] as [string, ReactNode]),
      ...(isIdentity ? [['Reaches', power ? `${power.reachableNodes?.length ?? 0} nodes · tier 0: ${power.reachByTier?.['0'] ?? 0}, tier 1: ${power.reachByTier?.['1'] ?? 0}, tier 2: ${power.reachByTier?.['2'] ?? 0}, tier 3: ${power.reachByTier?.['3'] ?? 0}` : 'Not visible to your account'],
        ['Routes to tier 0', paths ? `${routes.length}${paths.truncated ? '+' : ''}` : 'Not visible to your account']] as [string, ReactNode][]
        : [['Accessors', details ? String(accessors.length) : '—'], ['Protected by', details ? (safeguards.map(e => e.target).join(', ') || 'No safeguard') : '—']] as [string, ReactNode][]),
      ['Relationships', details ? `${incoming.length} in · ${outgoing.length} out` : '—'],
    ]}/>}
    {view === 'Access' && <>{power?.powers?.length ? <ul className="plain-list">{power.powers.map(p => <li key={`${p.nodeId}:${p.action}`}><span className="power-action">{p.action}</span> <EntityLink id={p.nodeId}/></li>)}</ul> : <p className="muted">No effective powers returned for this entity.</p>}
      {!!power?.controlledIdentities?.length && <><h4>Identities it can take over</h4><ul className="plain-list">{power.controlledIdentities.map(id => <li key={id}><EntityLink id={id}/></li>)}</ul></>}
      <h4>Routes to critical assets</h4>{routes.length ? routes.map((r, i) => <p key={i} className="route-line">{(r.nodeIds ?? []).map((id, j) => <span key={id + j}>{j > 0 && <span className="route-kind"> {edgeLabel[r.edgeKinds?.[j - 1] ?? ''] ?? '→'} </span>}<EntityLink id={id}/></span>)}</p>) : <p className="muted">{paths ? 'No route from this identity reaches a tier-0 asset.' : 'Route analysis is not available to your account.'}</p>}</>}
    {view === 'Relationships' && <EdgeList incoming={incoming} outgoing={outgoing} restricted={restricted}/>}
    {view === 'Accessors' && (accessors.length ? <ul className="plain-list">{accessors.map(e => <li key={`${e.source}${e.kind}`}><EntityLink id={e.source}/> <span className="route-kind">{edgeLabel[e.kind] ?? e.kind}{e.action ? ` (${e.action})` : ''}</span></li>)}</ul> : <p className="muted">{restricted ? 'Accessors are visible to authorized investigators.' : 'No direct accessors recorded.'}</p>)}
    {view === 'Safeguards' && (safeguards.length ? <ul className="plain-list">{safeguards.map(e => <li key={e.target}><EntityLink id={e.target}/></li>)}</ul> : <p className="muted">No safeguards protect this resource in the observed graph.</p>)}
    {(view === 'Activity' || view === 'Related changes') && (related.length ? <ul className="plain-list">{related.slice(0, 12).map(c => <li key={c.requestId}><button type="button" className="entity-link" onClick={() => go('Changes', { requestId: c.requestId })}>{c.kind === 'ROLE_REVOKE' ? 'Revoke' : 'Assign'} {nodeName(bootstrap, c.requestedAccess)}</button> <StatusBadge status={c.status}/> <span className="muted"><When iso={c.updatedAt ?? c.createdAt}/></span> <ArrowUpRight size={11}/></li>)}</ul> : <p className="muted">No access changes in your visible scope involve this entity.</p>)}
  </Inspector>;
}

function EdgeList({ incoming, outgoing, restricted }: { incoming: NodeDetails['incomingEdges']; outgoing: NodeDetails['outgoingEdges']; restricted: boolean }) {
  if (restricted) return <p className="muted">Relationship detail requires investigator authorization.</p>;
  return <><h4>Outgoing</h4>{outgoing?.length ? <ul className="plain-list">{outgoing.map(e => <li key={`${e.target}${e.kind}`}><span className="route-kind">{edgeLabel[e.kind] ?? e.kind}{e.action ? ` (${e.action})` : ''}</span> <EntityLink id={e.target}/></li>)}</ul> : <p className="muted">None.</p>}
    <h4>Incoming</h4>{incoming?.length ? <ul className="plain-list">{incoming.map(e => <li key={`${e.source}${e.kind}`}><EntityLink id={e.source}/> <span className="route-kind">{edgeLabel[e.kind] ?? e.kind}{e.action ? ` (${e.action})` : ''}</span></li>)}</ul> : <p className="muted">None.</p>}</>;
}
